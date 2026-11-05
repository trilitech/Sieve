package roles_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/roles"
)

// A role has no expiry or revocation, so unlike a token there is no dead
// holder to retire — the name is simply taken. What must not happen is the raw
// UNIQUE-constraint text reaching the operator as an HTTP 500.
func TestCreate_DuplicateName(t *testing.T) {
	svc := setup(t)

	if _, err := svc.Create("ops", nil); err != nil {
		t.Fatalf("create first: %v", err)
	}

	_, err := svc.Create("ops", nil)
	if !errors.Is(err, roles.ErrDuplicateName) {
		t.Fatalf("err = %v, want ErrDuplicateName", err)
	}
	if strings.Contains(err.Error(), "UNIQUE constraint") {
		t.Errorf("error leaks the SQL constraint: %v", err)
	}
}

// Rename collides the same way — handleIAMRoleRename routes through Update.
func TestUpdate_DuplicateName(t *testing.T) {
	svc := setup(t)

	if _, err := svc.Create("ops", nil); err != nil {
		t.Fatalf("create ops: %v", err)
	}
	second, err := svc.Create("dev", nil)
	if err != nil {
		t.Fatalf("create dev: %v", err)
	}

	err = svc.Update(second.ID, "ops", nil)
	if !errors.Is(err, roles.ErrDuplicateName) {
		t.Fatalf("err = %v, want ErrDuplicateName", err)
	}

	// Renaming a role to the name it already holds must still work — the row
	// collides with itself only if the UPDATE is mishandled.
	if err := svc.Update(second.ID, "dev", nil); err != nil {
		t.Errorf("renaming a role to its own name failed: %v", err)
	}
}
