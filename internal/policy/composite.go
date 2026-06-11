// composite.go implements the CompositeEvaluator which chains multiple
// policy evaluators. This is used when a token references multiple policies
// (e.g., "gmail-drafter" + "redact-pii" + "rate-limit").
// Evaluation semantics:
// - All evaluators run in order
// - First "deny" short-circuits and returns immediately
// - Any "approval_required" is sticky (returned if nothing denies)
// - All redactions are merged
// - All response filters from "allow" decisions are merged
// - Last non-empty rewrite wins (later policies can override earlier rewrites)
// - If all evaluators return "allow", the result is "allow"
package policy

import (
	"context"
	"strings"
)

// CompositeEvaluator chains multiple evaluators. All must allow for the
// request to proceed. Exported so the MCP server and API router can
// construct it from a token's policy list.
type CompositeEvaluator struct {
	Evaluators []Evaluator
}

func (c *CompositeEvaluator) Type() string { return "composite" }

func (c *CompositeEvaluator) Evaluate(ctx context.Context, req *PolicyRequest) (*PolicyDecision, error) {
	var (
		allRedactions    []Redaction
		allFilters       []ResponseFilter
		approvalRequired bool
		reasons          []string
		rewrite          string
	)

	for _, eval := range c.Evaluators {
		decision, err := eval.Evaluate(ctx, req)
		if err != nil {
			return nil, err
		}

		if len(decision.Redactions) > 0 {
			allRedactions = append(allRedactions, decision.Redactions...)
		}

		if decision.Rewrite != "" {
			rewrite = decision.Rewrite
		}

		switch decision.Action {
		case "deny":
			decision.Redactions = allRedactions
			return decision, nil
		case "approval_required":
			approvalRequired = true
			if decision.Reason != "" {
				reasons = append(reasons, decision.Reason)
			}
		default:
			// Collect filters from sub-evaluators that return "allow".
			if len(decision.Filters) > 0 {
				allFilters = append(allFilters, decision.Filters...)
			}
			if decision.Reason != "" {
				reasons = append(reasons, decision.Reason)
			}
		}
	}

	action := "allow"
	if approvalRequired {
		action = "approval_required"
	}

	return &PolicyDecision{
		Action:     action,
		Reason:     strings.Join(reasons, "; "),
		Redactions: allRedactions,
		Rewrite:    rewrite,
		Filters:    allFilters,
	}, nil
}
