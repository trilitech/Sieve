package iampolicies_test

import (
	"testing"

	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// TestDecide_EmptyRolesDefaultDeny pins (reviewer c): a token with no roles (e.g.
// all roles revoked) must default-deny — even when a legacy unconstrained-principal
// permit exists that Cedar would otherwise match against a role-less principal.
func TestDecide_EmptyRolesDefaultDeny(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)
	allowRead(t, svc, "reader")

	// Sanity: the role grants the read.
	if d := decideRead(t, svc, []string{"reader"}); d.Action != "allow" {
		t.Fatalf("role reader should allow read, got %q", d.Action)
	}

	// A legacy raw permit with an unconstrained principal (the hole the authoring
	// guard now blocks, but which could already exist on disk).
	if _, err := svc.CreatePolicy("legacy-broad", "", `permit(principal, action, resource);`, true); err != nil {
		t.Fatal(err)
	}

	if d := decideRead(t, svc, []string{}); d.Action != "deny" {
		t.Errorf("empty roleIDs must default-deny even with an unconstrained permit, got %q", d.Action)
	}
	if d := decideRead(t, svc, nil); d.Action != "deny" {
		t.Errorf("nil roleIDs must default-deny, got %q", d.Action)
	}
}
