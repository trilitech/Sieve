package connections_test

// Regression tests for FR-001..FR-005 lifecycle unification.
//
// In Sieve pre-launch, the unification dropped the legacy needs_reauth
// column entirely (no deprecation window). These tests pin:
//   - SetStatusWithReason is the canonical writer (atomic two-column update).
//   - Get/List/GetWithConfig surface only Status + ReauthReason.
//   - The reserved-prefix predicates correctly identify _oauth_app:* rows.
//   - List() filters reserved-prefix rows.
//   - GetConnector rejects reserved IDs.

import (
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/database"
	mockconn "github.com/trilitech/Sieve/internal/testing/mockconnector"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

func unifyTestSvc(t *testing.T) *connections.Service {
	t.Helper()
	env := testenv.New(t)
	mock := mockconn.New("mock")
	env.Registry.Register(mock.Meta(), mock.Factory())
	if err := env.Connections.Add("c", "mock", "C", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}
	return env.Connections
}

// TestSetStatusWithReason_WritesBothColumns verifies that one call
// updates both status and reauth_reason atomically.
func TestSetStatusWithReason_WritesBothColumns(t *testing.T) {
	svc := unifyTestSvc(t)

	if err := svc.SetStatusWithReason("c", connections.StatusReauthRequired, "test reason"); err != nil {
		t.Fatalf("SetStatusWithReason: %v", err)
	}

	got, err := svc.Get("c")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != connections.StatusReauthRequired {
		t.Fatalf("status: got %q, want reauth_required", got.Status)
	}
	if got.ReauthReason != "test reason" {
		t.Fatalf("reason: got %q, want test reason", got.ReauthReason)
	}
}

// TestSetStatusWithReason_ClearsReasonOnActive verifies that
// SetStatusWithReason(active, "") clears the reason and flips status.
func TestSetStatusWithReason_ClearsReasonOnActive(t *testing.T) {
	svc := unifyTestSvc(t)
	_ = svc.SetStatusWithReason("c", connections.StatusReauthRequired, "broken")

	if err := svc.SetStatusWithReason("c", connections.StatusActive, ""); err != nil {
		t.Fatalf("SetStatusWithReason(active): %v", err)
	}
	got, _ := svc.Get("c")
	if got.Status != connections.StatusActive {
		t.Fatalf("status: got %q, want active", got.Status)
	}
	if got.ReauthReason != "" {
		t.Fatalf("reason: got %q, want empty after active", got.ReauthReason)
	}
}

// TestSetStatusWithReason_RejectsInvalid verifies that invalid status
// values return an error without touching the row.
func TestSetStatusWithReason_RejectsInvalid(t *testing.T) {
	svc := unifyTestSvc(t)

	if err := svc.SetStatusWithReason("c", "bogus", "x"); err == nil {
		t.Fatal("expected SetStatusWithReason to reject invalid status")
	}
	got, _ := svc.Get("c")
	if got.Status != connections.StatusActive {
		t.Fatalf("status should be unchanged after rejected write, got %q", got.Status)
	}
}

// TestIsReservedConnectorType verifies the reserved-prefix predicate.
func TestIsReservedConnectorType(t *testing.T) {
	cases := map[string]bool{
		"":                 false,
		"slack":            false,
		"google":           false,
		"_oauth_app":       true,
		"_oauth_app:slack": true,
		"_internal":        true,
	}
	for in, want := range cases {
		if got := connections.IsReservedConnectorType(in); got != want {
			t.Errorf("IsReservedConnectorType(%q)=%v, want %v", in, got, want)
		}
	}
}

// TestIsReservedConnectionID verifies the reserved-id predicate uses
// the `oauth_app__<provider>` shape per the contract.
func TestIsReservedConnectionID(t *testing.T) {
	cases := map[string]bool{
		"":                  false,
		"slack":             false,
		"oauth_app":         false, // bare prefix without the double-underscore
		"oauth_app_":        false,
		"oauth_app__":       true, // boundary: matches the prefix
		"oauth_app__slack":  true,
		"oauth_app__linear": true,
	}
	for in, want := range cases {
		if got := connections.IsReservedConnectionID(in); got != want {
			t.Errorf("IsReservedConnectionID(%q)=%v, want %v", in, got, want)
		}
	}
}

// TestList_FiltersReservedRows seeds a reserved-prefix row directly via
// the test env's database and confirms that Service.List does not
// return it. Cross-checks the per-tenant view doesn't leak system rows.
func TestList_FiltersReservedRows(t *testing.T) {
	env := testenv.New(t)
	mock := mockconn.New("mock")
	env.Registry.Register(mock.Meta(), mock.Factory())
	if err := env.Connections.Add("tenant1", "mock", "Tenant 1", map[string]any{}); err != nil {
		t.Fatalf("add tenant: %v", err)
	}

	// Seed a reserved row directly via SQL — the public Add() path
	// doesn't recognise the synthetic _oauth_app:* connector type.
	if _, err := env.DB.Exec(
		`INSERT INTO connections (
			id, connector_type, display_name,
			config_ciphertext, config_nonce,
			dek_wrapped, dek_nonce, enc_version,
			status, created_at, reauth_reason
		) VALUES ('oauth_app__test', '_oauth_app:test', 'Test OAuth App',
		          x'', x'', x'', x'', 1, 'active', datetime('now'), NULL)`,
	); err != nil {
		t.Fatalf("seed reserved row: %v", err)
	}

	list, err := env.Connections.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, c := range list {
		if c.ID == "oauth_app__test" {
			t.Fatalf("List returned reserved row %q; expected filtered out", c.ID)
		}
	}
}

// TestGetConnector_RejectsReservedID verifies that GetConnector refuses
// to instantiate a reserved-prefix row, returning an unknown-connector
// error even though the underlying row exists.
func TestGetConnector_RejectsReservedID(t *testing.T) {
	env := testenv.New(t)
	mock := mockconn.New("mock")
	env.Registry.Register(mock.Meta(), mock.Factory())

	if _, err := env.DB.Exec(
		`INSERT INTO connections (
			id, connector_type, display_name,
			config_ciphertext, config_nonce,
			dek_wrapped, dek_nonce, enc_version,
			status, created_at, reauth_reason
		) VALUES ('oauth_app__test', '_oauth_app:test', 'Test',
		          x'', x'', x'', x'', 1, 'active', datetime('now'), NULL)`,
	); err != nil {
		t.Fatalf("seed reserved row: %v", err)
	}

	if _, err := env.Connections.GetConnector("oauth_app__test"); err == nil {
		t.Fatal("GetConnector(reserved id): expected error, got nil")
	}
}

// suppress unused warnings (grouped import block warning-free)
var _ = filepath.Join
var _ = database.DB{}
var _ = connector.ErrUnknownConnector{}
