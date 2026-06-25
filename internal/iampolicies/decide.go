package iampolicies

import (
	"context"
	"sort"
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

// resolveDecision turns an engine Decision into a PolicyDecision, running any
// PER-GRANT script conditions (spec §5.4: a script that returns allow/deny/
// approval is the "script mode" of a rule's condition). A script that denies (or
// errors) vetoes ONLY ITS grant — not the whole request — so the request is
// allowed as long as some grant survives (a plain grant, or a script grant whose
// script allowed). Obligations are collected from the SURVIVING grants plus the
// always-on unconditional set. Post-execution filters bridge to the applier.
func (s *Service) resolveDecision(ctx context.Context, d iam.Decision, req *policy.PolicyRequest) *policy.PolicyDecision {
	if !d.Allow {
		reason := d.Reason
		if reason == "" {
			reason = "denied by policy"
		}
		return &policy.PolicyDecision{Action: "deny", Reason: reason}
	}
	// Legacy backstop: a pre-execution guard FILTER is no longer a thing (decision
	// scripts are rule conditions now). If one lingers in stored data, fail closed
	// loudly rather than silently allow past an unenforced guard.
	if len(d.Obligations.Guards) > 0 {
		return &policy.PolicyDecision{Action: "deny", Reason: "unsupported guard filter — express it as a rule's script condition (spec §5.4)"}
	}

	// Unconditional obligations (plain grants + guardrails) always apply.
	post := append([]iam.Filter(nil), d.Obligations.Post...)
	approval := d.Obligations.Approval
	allowStands := d.HasPlainGrant

	// Per-grant script conditions: each gates only its own grant. The script's
	// return IS the decision (allow/deny/approval); a grant carries no transforms
	// (those are guardrail-only and already in `post`).
	for _, c := range d.ScriptGrants {
		v := runScriptCondition(ctx, c.Script, req)
		switch v.Action {
		case "allow":
			allowStands = true
		case "approval_required":
			allowStands = true
			approval = true
		default: // deny / error → veto THIS grant only
			continue
		}
	}

	if !allowStands {
		// Every matching grant was vetoed by its script condition → default deny.
		return &policy.PolicyDecision{Action: "deny", Reason: "denied by policy"}
	}

	pd := &policy.PolicyDecision{Action: "allow", Filters: obligationsToFilters(mergePost(post))}
	if approval {
		pd.Action = "approval_required"
		pd.Reason = "approval required"
	}
	return pd
}

// mergePost dedups the surviving grants' + unconditional post filters by name and
// orders them by (Order, Name) — the canonical pipeline order (spec §7.1).
func mergePost(in []iam.Filter) []iam.Filter {
	seen := make(map[string]bool, len(in))
	out := make([]iam.Filter, 0, len(in))
	for _, f := range in {
		if seen[f.Name] {
			continue
		}
		seen[f.Name] = true
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// runScriptCondition runs a grant's script-mode condition: the script reads the
// request on stdin and returns {action: allow|deny|approval_required}. A deny (or
// any execution failure) vetoes the grant — fail-closed. The path + command are
// re-validated here (defense in depth) on top of the save-time check.
func runScriptCondition(ctx context.Context, sc iam.ScriptCond, req *policy.PolicyRequest) *policy.PolicyDecision {
	if sc.Path == "" || sc.Command == "" {
		return &policy.PolicyDecision{Action: "deny", Reason: "script condition is misconfigured"}
	}
	if err := policy.ValidateScriptPath(sc.Path); err != nil {
		return &policy.PolicyDecision{Action: "deny", Reason: "script condition: " + err.Error()}
	}
	ev, err := policy.NewScriptEvaluator(map[string]any{"command": sc.Command, "script": sc.Path})
	if err != nil {
		return &policy.PolicyDecision{Action: "deny", Reason: "script condition: " + err.Error()}
	}
	pd, err := ev.Evaluate(ctx, req)
	if err != nil {
		return &policy.PolicyDecision{Action: "deny", Reason: "script condition error: " + err.Error()}
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
