package roles_test

// Regression test for spec 002 FR-014: role bindings MUST NOT reference
// reserved-prefix connection ids (e.g., oauth_app__slack). The roles
// service rejects with ErrReservedConnectionID at Create and Update so
// agent tokens can never be wired to address a reserved system row.

import (
	"errors"
	"testing"

	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

func TestCreate_RejectsReservedConnectionID(t *testing.T) {
	env := testenv.New(t)

	bindings := []roles.Binding{
		{ConnectionID: "oauth_app__slack", PolicyIDs: nil},
	}
	_, err := env.Roles.Create("oauth-app-role", bindings)
	if err == nil {
		t.Fatal("expected Create to reject binding to oauth_app__slack, got nil")
	}
	if !errors.Is(err, roles.ErrReservedConnectionID) {
		t.Fatalf("error does not wrap ErrReservedConnectionID: %v", err)
	}
}

func TestUpdate_RejectsReservedConnectionID(t *testing.T) {
	env := testenv.New(t)

	role, err := env.Roles.Create("good-role", []roles.Binding{
		{ConnectionID: "normal-conn", PolicyIDs: nil},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	err = env.Roles.Update(role.ID, role.Name, []roles.Binding{
		{ConnectionID: "oauth_app__slack", PolicyIDs: nil},
	})
	if err == nil {
		t.Fatal("expected Update to reject reserved-prefix binding")
	}
	if !errors.Is(err, roles.ErrReservedConnectionID) {
		t.Fatalf("error does not wrap ErrReservedConnectionID: %v", err)
	}
}

func TestCreate_AcceptsNormalConnectionIDs(t *testing.T) {
	env := testenv.New(t)
	_, err := env.Roles.Create("normal-role", []roles.Binding{
		{ConnectionID: "slack-prod", PolicyIDs: nil},
		{ConnectionID: "gmail-personal", PolicyIDs: nil},
	})
	if err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
}
