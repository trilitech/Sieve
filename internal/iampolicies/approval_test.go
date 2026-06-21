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

	spec := iampolicies.RuleSpec{
		RoleID: "R", Effect: "require_approval", ConnectorType: "mock", OpScope: "write",
	}
	// Grant (allow the write) + the companion guardrail (the approval obligation,
	// spec §7.2 — obligations live in the guardrail set, not on the grant).
	grant, err := iampolicies.BuildRuleCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy("needs-approval", "", grant, true); err != nil {
		t.Fatal(err)
	}
	guard, err := iampolicies.BuildGuardrailCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateGuardrail("needs-approval-g", "", guard, true); err != nil {
		t.Fatal(err)
	}

	reg := connector.NewRegistry()
	m := mockconnector.New("mock")
	reg.Register(m.Meta(), m.Factory())

	d, err := svc.Decide(context.Background(), reg, "tok", []string{"R"}, "mock", "c", "active", "send_email",
		map[string]any{"to": []string{"a@b.com"}, "subject": "s", "body": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != "approval_required" {
		t.Errorf("require_approval rule: got action %q, want approval_required", d.Action)
	}
}
