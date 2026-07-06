package iampolicies_test

import (
	"context"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/roles"
	mockconnector "github.com/trilitech/Sieve/internal/testing/mockconnector"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/tokens"
)

// TestDeleteRole_Cascade_Revokes proves the role-delete cascade actually REVOKES
// access, not just hides the role in the UI. A token that lists a deleted role id
// would otherwise be synthesized as `in` that role by the engine, so the access
// would survive. The cascade (the same calls handleIAMRoleDelete makes) must:
//   - strip the role from the token (so the engine no longer composes it), and
//   - delete the rules that targeted the role,
//
// after which the (formerly fully-authorized) token is default-denied — both with
// its real, now-empty role set AND even if the stale role id were replayed.
func TestDeleteRole_Cascade_Revokes(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)
	roleSvc := roles.NewService(env.DB)
	tokSvc := tokens.NewService(env.DB)

	role, err := roleSvc.Create("only-role", nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := tokSvc.Create(&tokens.CreateRequest{Name: "t", RoleID: role.ID})
	if err != nil {
		t.Fatal(err)
	}

	// A broad allow rule + a companion guardrail, both targeting the role.
	spec := iampolicies.RuleSpec{
		RoleID: role.ID, Effect: "require_approval", ConnectorType: "mock", OpScope: "all",
	}
	grant, err := iampolicies.BuildRuleCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy("only-role-allow", "", grant, true); err != nil {
		t.Fatal(err)
	}
	guard, err := iampolicies.BuildGuardrailCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateGuardrail("only-role-guard", "", guard, true); err != nil {
		t.Fatal(err)
	}

	reg := connector.NewRegistry()
	m := mockconnector.New("mock")
	reg.Register(m.Meta(), m.Factory())

	decide := func(roleIDs []string) string {
		d, err := svc.Decide(context.Background(), reg, tok.Token.ID, roleIDs,
			"mock", "c", "active", "list_emails", nil)
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
		return d.Action
	}

	// Before: the token can act through its role.
	if got := decide([]string{role.ID}); got == "deny" {
		t.Fatalf("pre-delete: token should be authorized via its role, got %q", got)
	}

	// The cascade — exactly what handleIAMRoleDelete runs.
	changed, err := tokSvc.RemoveRoleFromAll(role.ID)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 1 {
		t.Errorf("RemoveRoleFromAll: changed %d tokens, want 1", changed)
	}
	nRules, err := svc.DeletePoliciesForRole(role.ID)
	if err != nil {
		t.Fatal(err)
	}
	if nRules != 1 {
		t.Errorf("DeletePoliciesForRole: deleted %d rules, want 1", nRules)
	}
	nGuards, err := svc.DeleteGuardrailsForRole(role.ID)
	if err != nil {
		t.Fatal(err)
	}
	if nGuards != 1 {
		t.Errorf("DeleteGuardrailsForRole: deleted %d guardrails, want 1", nGuards)
	}
	if err := roleSvc.Delete(role.ID); err != nil {
		t.Fatal(err)
	}

	// The token no longer references the role (revoked at the token level).
	reloaded, err := tokSvc.Get(tok.Token.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range reloaded.RoleIDs {
		if id == role.ID {
			t.Fatalf("token still lists the deleted role %q: %v", role.ID, reloaded.RoleIDs)
		}
	}

	// Engine revocation: denied with the real (now-empty) role set...
	if got := decide(reloaded.RoleIDs); got != "deny" {
		t.Errorf("post-delete (real roles): want deny, got %q", got)
	}
	// ...and still denied even if the stale id were replayed (the rule is gone).
	if got := decide([]string{role.ID}); got != "deny" {
		t.Errorf("post-delete (replayed stale role id): want deny, got %q", got)
	}

	// The role's rules are gone.
	pols, err := svc.ListPolicies()
	if err != nil {
		t.Fatal(err)
	}
	if len(pols) != 0 {
		t.Errorf("expected 0 rules after cascade, got %d", len(pols))
	}
}
