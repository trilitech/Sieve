package iampolicies

import (
	"context"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/policy"
)

// Decide runs the IAM PDP for a request and returns the result as a
// *policy.PolicyDecision — the SAME shape the legacy evaluator returns — so the
// PEPs (api/router.go, mcp/server.go) plug it into their existing
// allow/deny/approval switch unchanged (the "swap the decision source, not the
// handler" strategy). ctx is accepted for symmetry with the legacy
// Evaluator.Evaluate; the engine itself is pure.
//
// Mapping (spec §7):
//   - Cedar deny → Action "deny".
//   - Cedar allow + a pre-guard obligation (script_guard/rate_limit) → "deny"
//     (fail-closed: guard EXECUTION is not wired in v1, and we must not allow
//     past an unenforced guard). Post-execution filters DO apply.
//   - Cedar allow + @approval → "approval_required".
//   - Cedar allow → "allow", with post filters bridged to ResponseFilters.
func (s *Service) Decide(
	ctx context.Context,
	reg *connector.Registry,
	tokenID string, roleIDs []string, connType, connID, connStatus, op string,
	params map[string]any,
) (*policy.PolicyDecision, error) {
	_ = ctx
	eng, err := s.Engine()
	if err != nil {
		return nil, err
	}
	opDef := taxonomyOp(reg, connType, op)
	prereq := &policy.PolicyRequest{
		Operation: op, Connection: connID, Connector: connType,
		Params: params, Metadata: params, Phase: "pre",
	}
	req := iam.BuildRequest(tokenID, roleIDs, connType, connID, connStatus, opDef, params)

	// Connector-derived context (e.g. recipient_domains) that RuleConditions
	// reference. Pure func on Meta — no configured instance / keyring needed.
	if reg != nil {
		if meta, ok := reg.Meta(connType); ok && meta.EnrichContext != nil {
			if extra := meta.EnrichContext(op, params); len(extra) > 0 {
				if req.Context == nil {
					req.Context = map[string]any{}
				}
				for k, v := range extra {
					req.Context[k] = v
				}
			}
		}
	}

	dec, err := eng.Decide(req)
	if err != nil {
		return nil, err
	}
	return s.resolveDecision(ctx, dec, prereq), nil
}

// taxonomyOp resolves the static OperationDef for (connType, op) from the
// registry. mcp_proxy's runtime ops are dynamic (discovered tools), so any tool
// maps to the single synthetic "mcp_proxy/call" action at connection grain
// (tool-level resource scoping is a v1 deferral).
func taxonomyOp(reg *connector.Registry, connType, op string) connector.OperationDef {
	if connType == "mcp_proxy" {
		return connector.OperationDef{Name: op, Action: "mcp_proxy/call", ReadOnly: false}
	}
	if reg != nil {
		if meta, ok := reg.Meta(connType); ok {
			for _, o := range meta.Operations {
				if o.Name == op {
					return o
				}
			}
		}
	}
	// Unknown op: a minimal def whose derived action ("<type>/<op>") won't match
	// any policy → default deny. Never silently allows.
	return connector.OperationDef{Name: op, ReadOnly: false}
}

// resolveDecision turns an engine Decision into a PolicyDecision, EXECUTING any
// pre-execution guard obligations (e.g. a custom script that inspects the
// outgoing request and allows/denies it — "what can or cannot be sent"). A guard
// that denies (or its execution failing) short-circuits to deny: fail-closed,
// but now because the guard actually ran and said so, not because execution is
// stubbed. Post-execution filters are bridged to the response-filter applier.
func (s *Service) resolveDecision(ctx context.Context, d iam.Decision, req *policy.PolicyRequest) *policy.PolicyDecision {
	if !d.Allow {
		reason := d.Reason
		if reason == "" {
			reason = "denied by policy"
		}
		return &policy.PolicyDecision{Action: "deny", Reason: reason}
	}

	for _, g := range d.Obligations.Guards {
		switch g.Kind {
		case iam.KindScriptGuard:
			gd := runScriptGuard(ctx, g, req)
			if gd.Action != "allow" {
				return gd // deny / approval_required from the guard propagates
			}
		default:
			// e.g. rate_limit — not executable in this build. Fail closed
			// LOUDLY rather than silently allowing past an unenforced guard.
			// (The UI must not offer guard kinds that aren't executed.)
			return &policy.PolicyDecision{Action: "deny", Reason: "guard kind " + string(g.Kind) + " is not supported in this build"}
		}
	}

	pd := &policy.PolicyDecision{Action: "allow", Filters: obligationsToFilters(d.Obligations.Post)}
	if d.Obligations.Approval {
		pd.Action = "approval_required"
		pd.Reason = "approval required"
	}
	return pd
}

// runScriptGuard executes a script_guard obligation: it materializes the inline
// script to a temp file and runs it through the sandboxed ScriptEvaluator (stdin
// = the request JSON, stdout = {action: allow|deny|approval_required}). The
// command is allowlist-validated by NewScriptEvaluator.
func runScriptGuard(ctx context.Context, g iam.Filter, req *policy.PolicyRequest) *policy.PolicyDecision {
	path, _ := g.Config["path"].(string)
	command, _ := g.Config["command"].(string)
	if path == "" || command == "" {
		return &policy.PolicyDecision{Action: "deny", Reason: "script guard '" + g.Name + "' is misconfigured"}
	}
	// Defense in depth: re-validate the script path at execution time (it was
	// also checked at save), so a path that left the allowlist since (or a
	// tampered config) can't reach the interpreter.
	if err := policy.ValidateScriptPath(path); err != nil {
		return &policy.PolicyDecision{Action: "deny", Reason: "script guard '" + g.Name + "': " + err.Error()}
	}

	ev, err := policy.NewScriptEvaluator(map[string]any{
		"command": command, "script": path, "timeout": g.Config["timeout"],
	})
	if err != nil {
		return &policy.PolicyDecision{Action: "deny", Reason: "script guard '" + g.Name + "': " + err.Error()}
	}
	pd, err := ev.Evaluate(ctx, req)
	if err != nil {
		return &policy.PolicyDecision{Action: "deny", Reason: "script guard '" + g.Name + "' error: " + err.Error()}
	}
	return pd
}

// ValidateScriptPath checks a filter's script path against the allowlisted
// scripts directories (thin wrapper so the web layer doesn't import policy).
func ValidateScriptPath(path string) error { return policy.ValidateScriptPath(path) }

// ValidateScriptCommand checks a filter's interpreter against the command
// allowlist (thin wrapper so the web layer doesn't import policy).
func ValidateScriptCommand(command string) error {
	return policy.ValidateCommand(command, policy.CurrentCommandAllowlist())
}

// ScriptCommand returns the interpreter the admin UI should store for a new
// script filter: the operator allowlist's first entry, else the bundled default.
func ScriptCommand() string {
	if al := policy.CurrentCommandAllowlist(); len(al) > 0 {
		return al[0]
	}
	return policy.DefaultCommand
}

// ScriptCommandFor returns the interpreter path for a guard/filter language:
// JavaScript → Node, anything else → Python. Both must pass the command
// allowlist at save + execution.
func ScriptCommandFor(language string) string {
	switch strings.ToLower(strings.TrimSpace(language)) {
	case "javascript", "js", "node":
		return policy.DefaultNodeCommand
	default:
		return ScriptCommand()
	}
}

// obligationsToFilters bridges IAM post-obligations to the existing
// policy.ResponseFilter applier (which already supports redact/exclude/script).
func obligationsToFilters(post []iam.Filter) []policy.ResponseFilter {
	var out []policy.ResponseFilter
	for _, f := range post {
		switch f.Kind {
		case iam.KindRedact:
			out = append(out, policy.ResponseFilter{Label: f.Name, RedactPatterns: strSlice(f.Config["patterns"]), Match: str(f.Config["match"]), Fields: strSlice(f.Config["fields"])})
		case iam.KindExcludeItems:
			out = append(out, policy.ResponseFilter{Label: f.Name, ExcludePatterns: strSlice(f.Config["patterns"]), Match: str(f.Config["match"]), Fields: strSlice(f.Config["fields"])})
		case iam.KindScriptFilter:
			out = append(out, policy.ResponseFilter{
				Label:         f.Name,
				ScriptCommand: str(f.Config["command"]),
				ScriptPath:    str(f.Config["path"]),
			})
		}
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func strSlice(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
