package web

import (
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connections"
)

// TestMatchesReauthIdentity_Match: the happy path — operator signed back in
// as the same Google account.
func TestMatchesReauthIdentity_Match(t *testing.T) {
	existing := &connections.Connection{Config: map[string]any{"email": "alice@example.com"}}
	if err := matchesReauthIdentity(existing, "alice@example.com"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

// TestMatchesReauthIdentity_CaseInsensitive: Gmail treats local-part case as
// non-significant in practice (and the domain is case-insensitive by RFC).
// Comparing case-sensitively would falsely block "Alice@example.com" vs
// "alice@example.com" round-trips.
func TestMatchesReauthIdentity_CaseInsensitive(t *testing.T) {
	existing := &connections.Connection{Config: map[string]any{"email": "Alice@Example.com"}}
	if err := matchesReauthIdentity(existing, "alice@example.com"); err != nil {
		t.Errorf("expected nil for case-only difference, got %v", err)
	}
}

// TestMatchesReauthIdentity_Mismatch: this is the security finding from the
// review — a re-auth that picks a different Google account in the consent
// screen MUST be refused so the connection's identity doesn't silently swap.
func TestMatchesReauthIdentity_Mismatch(t *testing.T) {
	existing := &connections.Connection{Config: map[string]any{"email": "work@example.com"}}
	err := matchesReauthIdentity(existing, "personal@example.com")
	if err == nil {
		t.Fatal("expected error for mismatched accounts, got nil")
	}
	// The error message has to actually tell the operator what to do —
	// "mismatch" alone doesn't help; surface both addresses and the recovery
	// path (re-auth with the right account, or delete + re-add).
	msg := err.Error()
	for _, want := range []string{"work@example.com", "personal@example.com", "Re-authenticate"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should contain %q, got: %s", want, msg)
		}
	}
}

// TestMatchesReauthIdentity_NoExistingEmail: degenerate case — a connection
// somehow has no email in its config. Allow the update; there's nothing to
// guard against. We don't currently produce this state, but the guard
// should fail open rather than block recovery from a malformed row.
func TestMatchesReauthIdentity_NoExistingEmail(t *testing.T) {
	existing := &connections.Connection{Config: map[string]any{}}
	if err := matchesReauthIdentity(existing, "alice@example.com"); err != nil {
		t.Errorf("expected nil when existing has no email, got %v", err)
	}
}
