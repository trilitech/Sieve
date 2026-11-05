package tokens_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/tokens"
)

// byID looks a token up in the full list — the retired incumbent is still a
// real row, so it must remain findable by its original id after the handover.
func byID(t *testing.T, svc *tokens.Service, id string) *tokens.Token {
	t.Helper()
	all, err := svc.List()
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i]
		}
	}
	t.Fatalf("token %q not found after name handover — it must be retired, never deleted", id)
	return nil
}

// TestCreate_NameReusedAfterRevoke is the headline case Arthur hit: a token
// expired, was revoked, and the replacement could not take its name.
func TestCreate_NameReusedAfterRevoke(t *testing.T) {
	svc, roleSvc := setup(t)
	role, _ := roleSvc.Create("r", nil)

	first, err := svc.Create(&tokens.CreateRequest{Name: "taxes-agent", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create first: %v", err)
	}
	if err := svc.Revoke(first.Token.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	second, err := svc.Create(&tokens.CreateRequest{Name: "taxes-agent", RoleID: role.ID})
	if err != nil {
		t.Fatalf("reusing a revoked token's name must succeed, got: %v", err)
	}
	if second.Token.Name != "taxes-agent" {
		t.Errorf("new token name = %q, want the name it asked for", second.Token.Name)
	}

	// The incumbent survives under a retired name, so its audit history stays
	// attributable rather than being deleted to free the name.
	old := byID(t, svc, first.Token.ID)
	if old.Name == "taxes-agent" {
		t.Error("both tokens are named taxes-agent; the dead one should have been retired")
	}
	if !strings.HasPrefix(old.Name, "taxes-agent (retired ") {
		t.Errorf("retired name = %q, want it to still carry the original name", old.Name)
	}
	if !strings.Contains(old.Name, first.Token.ID) {
		t.Errorf("retired name %q must embed the token id so archiving cannot collide", old.Name)
	}
	if !old.Revoked {
		t.Error("retiring the name must not un-revoke the old token")
	}

	// The old secret stays dead; the new one works.
	if _, err := svc.Validate(first.PlaintextToken); err == nil {
		t.Error("revoked token validated after its name was reused")
	}
	if _, err := svc.Validate(second.PlaintextToken); err != nil {
		t.Errorf("new token must validate: %v", err)
	}
}

// TestCreate_NameReusedAfterExpiry: expiry alone frees the name, with no
// revoke step. Expiry is time-dependent, which is why this cannot be a partial
// UNIQUE index and is enforced in Create instead.
func TestCreate_NameReusedAfterExpiry(t *testing.T) {
	svc, roleSvc := setup(t)
	role, _ := roleSvc.Create("r", nil)

	first, err := svc.Create(&tokens.CreateRequest{
		Name: "nightly", RoleID: role.ID, ExpiresIn: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("create first: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	if _, err := svc.Create(&tokens.CreateRequest{Name: "nightly", RoleID: role.ID}); err != nil {
		t.Fatalf("reusing an expired token's name must succeed, got: %v", err)
	}
	if old := byID(t, svc, first.Token.ID); old.Name == "nightly" {
		t.Error("expired token kept the name")
	}
}

// TestCreate_LiveNameStillRejected: the restriction that remains. Two usable
// tokens with one name is ambiguous — which does the operator revoke?
func TestCreate_LiveNameStillRejected(t *testing.T) {
	svc, roleSvc := setup(t)
	role, _ := roleSvc.Create("r", nil)

	if _, err := svc.Create(&tokens.CreateRequest{Name: "live", RoleID: role.ID}); err != nil {
		t.Fatalf("create first: %v", err)
	}

	_, err := svc.Create(&tokens.CreateRequest{Name: "live", RoleID: role.ID})
	if !errors.Is(err, tokens.ErrDuplicateName) {
		t.Fatalf("err = %v, want ErrDuplicateName (handlers key the 409 off this)", err)
	}
	// The raw SQLite text is what used to reach the operator as a 500.
	if strings.Contains(err.Error(), "UNIQUE constraint") {
		t.Errorf("error still leaks the SQL constraint: %v", err)
	}

	// A token with a future expiry is live too, not merely "has an expiry".
	if _, err := svc.Create(&tokens.CreateRequest{
		Name: "live", RoleID: role.ID, ExpiresIn: time.Hour,
	}); !errors.Is(err, tokens.ErrDuplicateName) {
		t.Fatalf("err = %v, want ErrDuplicateName for an unexpired token", err)
	}
}

// TestCreate_RepeatedRotationDoesNotCollide: the archived name must itself be
// unique, or the second rotation fails where the first succeeded.
func TestCreate_RepeatedRotationDoesNotCollide(t *testing.T) {
	svc, roleSvc := setup(t)
	role, _ := roleSvc.Create("r", nil)

	for i := 0; i < 4; i++ {
		res, err := svc.Create(&tokens.CreateRequest{Name: "rotated", RoleID: role.ID})
		if err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		if err := svc.Revoke(res.Token.ID); err != nil {
			t.Fatalf("revoke %d: %v", i, err)
		}
	}

	all, err := svc.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	seen := map[string]bool{}
	for _, tok := range all {
		if seen[tok.Name] {
			t.Errorf("duplicate name %q after repeated rotation", tok.Name)
		}
		seen[tok.Name] = true
	}
	if len(all) != 4 {
		t.Errorf("got %d tokens, want 4 — retiring must never delete history", len(all))
	}
}

// TestCreate_EmptyName: the form marks name required, so this is only
// reachable via a hand-rolled POST — but it was a 500 (UNIQUE on "") rather
// than a 400 once a second nameless token was created.
func TestCreate_EmptyName(t *testing.T) {
	svc, roleSvc := setup(t)
	role, _ := roleSvc.Create("r", nil)

	for _, name := range []string{"", "   "} {
		if _, err := svc.Create(&tokens.CreateRequest{Name: name, RoleID: role.ID}); !errors.Is(err, tokens.ErrEmptyName) {
			t.Errorf("Create(name=%q) err = %v, want ErrEmptyName", name, err)
		}
	}
}

// TestCreate_NameTrimmed keeps "agent" and "agent " from being two tokens that
// look identical in every list and audit row.
func TestCreate_NameTrimmed(t *testing.T) {
	svc, roleSvc := setup(t)
	role, _ := roleSvc.Create("r", nil)

	res, err := svc.Create(&tokens.CreateRequest{Name: "  padded  ", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Token.Name != "padded" {
		t.Errorf("name = %q, want trimmed", res.Token.Name)
	}
	if _, err := svc.Create(&tokens.CreateRequest{Name: "padded", RoleID: role.ID}); !errors.Is(err, tokens.ErrDuplicateName) {
		t.Errorf("err = %v, want the trimmed name to collide", err)
	}
}
