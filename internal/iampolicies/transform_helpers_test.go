package iampolicies_test

import (
	"context"
	"testing"

	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/policy"
)

// allowRead stores an allow-read rule for a role so reads are permitted and a
// transform's effect on the response can be observed. Shared by the attachment
// (reuse-by-reference) tests.
func allowRead(t *testing.T, svc *iampolicies.Service, role string) {
	t.Helper()
	cedar, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: role, Effect: "allow", ConnectorType: "mock", OpScope: "read",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy("allow-read-"+role, "", cedar, true); err != nil {
		t.Fatal(err)
	}
}

// decideRead runs a read decision for a token holding roles.
func decideRead(t *testing.T, svc *iampolicies.Service, roles []string) *policy.PolicyDecision {
	t.Helper()
	d, err := svc.Decide(context.Background(), approvalMockReg(), "tok", roles,
		"mock", "c", "active", "list_emails", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// hasRedact reports whether the decision carries any redacting response filter.
func hasRedact(d *policy.PolicyDecision) bool {
	for _, f := range d.Filters {
		if len(f.RedactPatterns) > 0 {
			return true
		}
	}
	return false
}
