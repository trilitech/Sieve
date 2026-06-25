package iampolicies_test

import (
	"context"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iampolicies"
	mockconnector "github.com/trilitech/Sieve/internal/testing/mockconnector"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

func approvalMockReg() *connector.Registry {
	reg := connector.NewRegistry()
	m := mockconnector.New("mock")
	reg.Register(m.Meta(), m.Factory())
	return reg
}

func decideWrite(t *testing.T, svc *iampolicies.Service) string {
	t.Helper()
	d, err := svc.Decide(context.Background(), approvalMockReg(), "tok", []string{"R"},
		"mock", "c", "active", "send_email",
		map[string]any{"to": []string{"a@b.com"}, "subject": "s", "body": "x"})
	if err != nil {
		t.Fatal(err)
	}
	return d.Action
}

func mustPolicy(t *testing.T, svc *iampolicies.Service, name, effect string) {
	t.Helper()
	cedar, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: "R", Effect: effect, ConnectorType: "mock", OpScope: "write",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy(name, "", cedar, true); err != nil {
		t.Fatal(err)
	}
}

// TestDecide_ApprovalRequired proves a rule with Effect=require_approval resolves to
// approval_required ON ITS OWN — approval is the decision lattice's middle (§3.2), the
// permit carries @approval, no companion guardrail needed. The api/mcp PEPs route the
// approval_required action to the human approval queue.
func TestDecide_ApprovalRequired(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)
	mustPolicy(t, svc, "needs-approval", "require_approval")
	if got := decideWrite(t, svc); got != "approval_required" {
		t.Errorf("require_approval rule alone: got %q, want approval_required", got)
	}
}

// TestDecide_DenyOverridesApproval proves the lattice min: a deny rule (0) beats a
// require_approval rule (1) on the same request ⇒ deny.
func TestDecide_DenyOverridesApproval(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)
	mustPolicy(t, svc, "ask-write", "require_approval")
	mustPolicy(t, svc, "deny-write", "deny")
	if got := decideWrite(t, svc); got != "deny" {
		t.Errorf("deny + require_approval: got %q, want deny (min→0)", got)
	}
}

// TestDecide_ApprovalBeatsAllow proves the lattice min: a require_approval rule (1)
// beats a plain allow rule (2) on the same request ⇒ approval. A plain allow cannot
// lift an approval (the same "stacks, no privilege-lift" property as redaction).
func TestDecide_ApprovalBeatsAllow(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)
	mustPolicy(t, svc, "allow-write", "allow")
	mustPolicy(t, svc, "ask-write", "require_approval")
	if got := decideWrite(t, svc); got != "approval_required" {
		t.Errorf("allow + require_approval: got %q, want approval_required (min→1)", got)
	}
}
