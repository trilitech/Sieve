package iampolicies

import (
	"context"

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
	tokenID, roleID, connType, connID, connStatus, op string,
	params map[string]any,
) (*policy.PolicyDecision, error) {
	_ = ctx
	eng, err := s.Engine()
	if err != nil {
		return nil, err
	}
	groups, err := s.GroupsForRole(roleID)
	if err != nil {
		return nil, err
	}
	opDef := taxonomyOp(reg, connType, op)
	req := iam.BuildRequest(tokenID, roleID, groups, connType, connID, connStatus, opDef, params)
	dec, err := eng.Decide(req)
	if err != nil {
		return nil, err
	}
	return toPolicyDecision(dec), nil
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

func toPolicyDecision(d iam.Decision) *policy.PolicyDecision {
	if !d.Allow {
		reason := d.Reason
		if reason == "" {
			reason = "denied by policy"
		}
		return &policy.PolicyDecision{Action: "deny", Reason: reason}
	}
	if len(d.Obligations.Guards) > 0 {
		// Fail closed: pre-guard execution (script_guard/rate_limit) is not wired
		// in this build; allowing past an unenforced guard would be a hole.
		return &policy.PolicyDecision{Action: "deny", Reason: "policy guard not enforceable in this build"}
	}
	pd := &policy.PolicyDecision{Action: "allow", Filters: obligationsToFilters(d.Obligations.Post)}
	if d.Obligations.Approval {
		pd.Action = "approval_required"
		pd.Reason = "approval required"
	}
	return pd
}

// obligationsToFilters bridges IAM post-obligations to the existing
// policy.ResponseFilter applier (which already supports redact/exclude/script).
func obligationsToFilters(post []iam.Filter) []policy.ResponseFilter {
	var out []policy.ResponseFilter
	for _, f := range post {
		switch f.Kind {
		case iam.KindRedact:
			out = append(out, policy.ResponseFilter{Label: f.Name, RedactPatterns: strSlice(f.Config["patterns"])})
		case iam.KindExcludeItems:
			out = append(out, policy.ResponseFilter{Label: f.Name, ExcludeContaining: str(f.Config["text"])})
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
