package iampolicies_test

import (
	"context"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iampolicies"
	mockconnector "github.com/trilitech/Sieve/internal/testing/mockconnector"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// TestDecide_ApprovalRequired proves a "require approval" rule resolves to the
// approval_required action, which the api/mcp PEPs already route to the human
// approval queue (shared with the legacy path).
func TestDecide_ApprovalRequired(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)

	cedar, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: "R", Effect: "require_approval", ConnectorType: "mock", OpScope: "write",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy("needs-approval", "", cedar, true); err != nil {
		t.Fatal(err)
	}

	reg := connector.NewRegistry()
	m := mockconnector.New("mock")
	reg.Register(m.Meta(), m.Factory())

	d, err := svc.Decide(context.Background(), reg, "tok", "R", "mock", "c", "active", "send_email",
		map[string]any{"to": []string{"a@b.com"}, "subject": "s", "body": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != "approval_required" {
		t.Errorf("require_approval rule: got action %q, want approval_required", d.Action)
	}
}
