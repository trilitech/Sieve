package iampolicies

import (
	"context"
	"fmt"
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
	// A token with no roles has no grants — default-deny before touching the
	// engine. Belt-and-suspenders with the role-scoped-permit invariant: even a
	// legacy unconstrained-principal permit can't authorize a revoked token.
	if len(roleIDs) == 0 {
		return &policy.PolicyDecision{Action: "deny", Reason: "token has no roles"}, nil
	}
	eng, err := s.Engine()
	if err != nil {
		return nil, err
	}
	prereq, req := prepRequest(reg, tokenID, roleIDs, connType, connID, connStatus, op, params)
	dec, err := eng.Decide(req)
	if err != nil {
		return nil, err
	}
	pd, _ := s.resolveDecisionDetail(ctx, dec, prereq)
	return pd, nil
}

// prepRequest builds the engine request (with connector-enriched context) and
// the legacy PolicyRequest the script-condition evaluator reads from stdin.
// Shared by Decide and Explain so the dry-run evaluates exactly like the real PDP.
func prepRequest(
	reg *connector.Registry,
	tokenID string, roleIDs []string, connType, connID, connStatus, op string,
	params map[string]any,
) (*policy.PolicyRequest, iam.Request) {
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
	return prereq, req
}

// ExplainResult is the decision explorer's rich, dry-run view of a decision. It
// reflects the REAL decision path — including per-grant script conditions, which
// the engine runs to decide — so a model/amount/recipient_count condition and a
// script-mode condition all genuinely evaluate. Only post-execution transforms
// are NOT executed: there is no response to transform in a dry run, so they are
// reported (in applied order) rather than applied.
type ExplainResult struct {
	Action      string // allow | deny | approval_required
	Reason      string
	Approval    bool
	DefaultDeny bool // allow=false AND no rule matched at all (vs an explicit deny)
	// Determining is the rule(s) that decided: the permit(s) that granted an
	// allow, or the forbid rule(s) that denied. Resolved to names + descriptions.
	Determining []ExplainRule
	// Transforms are the response transforms that WOULD run, in applied order.
	Transforms []ExplainTransform
	// ScriptRules are the per-grant script conditions that ran, with their verdict.
	ScriptRules []ExplainScript
	// EvalErrors are per-policy Cedar evaluation errors (a policy that failed
	// closed) — surfaced so a silently-skipped rule is visible.
	EvalErrors []string
}

// ExplainRule is a determining rule, resolved from its policy id to a name and
// the operator's description (the human label shown in the rules list).
type ExplainRule struct {
	Name   string
	Detail string
}

// ExplainTransform is one would-run transform: its library name and kind.
type ExplainTransform struct {
	Name string
	Kind string
}

// ExplainScript is one per-grant script-condition run: the rule and its verdict.
type ExplainScript struct {
	Rule    string
	Verdict string
}

// Explain runs the PDP for a request like Decide, but returns the rich detail
// the decision explorer shows: the determining rule(s), the per-grant script
// verdicts, and the transforms that would run — not just allow/deny. It uses the
// exact same evaluation path as Decide (so it never diverges from enforcement).
func (s *Service) Explain(
	ctx context.Context,
	reg *connector.Registry,
	tokenID string, roleIDs []string, connType, connID, connStatus, op string,
	params map[string]any,
) (*ExplainResult, error) {
	// A role-less token default-denies (mirror of Decide) — reflect it in the
	// dry run instead of evaluating an empty grant set.
	if len(roleIDs) == 0 {
		return &ExplainResult{Action: "deny", DefaultDeny: true, Reason: "token has no roles"}, nil
	}
	eng, err := s.Engine()
	if err != nil {
		return nil, err
	}
	prereq, req := prepRequest(reg, tokenID, roleIDs, connType, connID, connStatus, op, params)
	dec, err := eng.Decide(req)
	if err != nil {
		return nil, err
	}
	pd, extra := s.resolveDecisionDetail(ctx, dec, prereq)

	idx := s.ruleNameIndex()
	res := &ExplainResult{
		Action:      pd.Action,
		Reason:      pd.Reason,
		Approval:    pd.Action == "approval_required",
		DefaultDeny: !dec.Allow && len(dec.Determining) == 0,
	}
	for _, pid := range dedupeStrings(dec.Determining) {
		res.Determining = append(res.Determining, idx.lookup(pid))
	}
	for _, f := range extra.post {
		res.Transforms = append(res.Transforms, ExplainTransform{Name: f.Name, Kind: string(f.Kind)})
	}
	for _, sr := range extra.scriptRuns {
		res.ScriptRules = append(res.ScriptRules, ExplainScript{Rule: idx.lookup(sr.PolicyID).Name, Verdict: sr.Verdict})
	}
	for _, e := range dec.EvalErrors {
		res.EvalErrors = append(res.EvalErrors, e.PolicyID+": "+e.Message)
	}
	return res, nil
}

// ruleIndex maps a stored policy ID → its record, for resolving engine policy
// ids ("pol:<id>#<n>") back to operator-facing rule names.
type ruleIndex map[string]StoredPolicy

func (s *Service) ruleNameIndex() ruleIndex {
	idx := ruleIndex{}
	if pols, err := s.ListPolicies(); err == nil {
		for _, p := range pols {
			idx[p.ID] = p
		}
	}
	return idx
}

func (idx ruleIndex) lookup(policyID string) ExplainRule {
	sid := storedIDFromPolicyID(policyID)
	if p, ok := idx[sid]; ok {
		return ExplainRule{Name: p.Name, Detail: p.Description}
	}
	return ExplainRule{Name: policyID} // unresolved: show the raw id, never blank
}

// storedIDFromPolicyID extracts the stored policy ID from an engine policy id of
// the form "<prefix>:<storedID>#<idx>" (spec §9.3).
func storedIDFromPolicyID(pid string) string {
	out := pid
	if i := strings.IndexByte(out, ':'); i >= 0 {
		out = out[i+1:]
	}
	if i := strings.LastIndexByte(out, '#'); i >= 0 {
		out = out[:i]
	}
	return out
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
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
// scriptRun records one per-grant script-condition execution (for the explorer).
type scriptRun struct {
	PolicyID string
	Verdict  string // allow | deny | approval_required
}

// decisionExtra carries the detail the decision explorer surfaces but the PEPs
// don't need: the would-run transforms (merged + ordered, only on an allow) and
// the per-grant script-condition verdicts.
type decisionExtra struct {
	post       []iam.Filter
	scriptRuns []scriptRun
}

// resolveDecisionDetail turns an engine Decision into a PolicyDecision (the PEP
// result) AND a decisionExtra (the explorer detail), running any PER-GRANT script
// conditions exactly as the real PDP does. See the package doc / spec §5.4, §7.3.
func (s *Service) resolveDecisionDetail(ctx context.Context, d iam.Decision, req *policy.PolicyRequest) (*policy.PolicyDecision, decisionExtra) {
	if !d.Allow {
		reason := d.Reason
		if reason == "" {
			reason = "denied by policy"
		}
		return &policy.PolicyDecision{Action: "deny", Reason: reason}, decisionExtra{}
	}
	// Legacy backstop: a pre-execution guard FILTER is no longer a thing (decision
	// scripts are rule conditions now). If one lingers in stored data, fail closed
	// loudly rather than silently allow past an unenforced guard.
	if len(d.Obligations.Guards) > 0 {
		return &policy.PolicyDecision{Action: "deny", Reason: "unsupported guard filter — express it as a rule's script condition (spec §5.4)"}, decisionExtra{}
	}

	// Unconditional obligations (plain grants + guardrails) always apply.
	post := append([]iam.Filter(nil), d.Obligations.Post...)
	approval := d.Obligations.Approval
	allowStands := d.HasPlainGrant

	// Per-grant script conditions: each gates only its own grant. The script's
	// return IS the decision (allow/deny/approval); a grant carries no transforms
	// (those are guardrail-only and already in `post`).
	var runs []scriptRun
	for _, c := range d.ScriptGrants {
		v := runScriptCondition(ctx, c.Script, req)
		runs = append(runs, scriptRun{PolicyID: c.PolicyID, Verdict: v.Action})
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
		return &policy.PolicyDecision{Action: "deny", Reason: "denied by policy"}, decisionExtra{scriptRuns: runs}
	}

	merged := mergePost(post)
	filters, ferr := obligationsToFilters(merged)
	if ferr != nil {
		// A post-obligation we can't translate must withhold the response, not
		// pass it through unfiltered.
		return &policy.PolicyDecision{Action: "deny", Reason: "denied by policy: " + ferr.Error()}, decisionExtra{scriptRuns: runs}
	}
	pd := &policy.PolicyDecision{Action: "allow", Filters: filters}
	if approval {
		pd.Action = "approval_required"
		pd.Reason = "approval required"
	}
	return pd, decisionExtra{post: merged, scriptRuns: runs}
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
// An unrecognized post-obligation kind FAILS CLOSED (returns an error so the
// caller denies) rather than being silently dropped — dropping it would let the
// response go out unfiltered while the decision stayed "allow" (mirrors the deny
// on an unresolvable @filters name).
func obligationsToFilters(post []iam.Filter) ([]policy.ResponseFilter, error) {
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
		default:
			return nil, fmt.Errorf("unknown post-obligation filter kind %q (filter %q)", f.Kind, f.Name)
		}
	}
	return out, nil
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
