package connections

// Internal-package tests for refresh-token rotation persistence.
//
// These tests live in package connections (not connections_test) so they
// can invoke the unexported injectRefreshCallback / persistRefreshedToken
// helpers directly and observe the failure-path semantics without going
// through a real OAuth refresh flow.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/secrets"
	mockconn "github.com/trilitech/Sieve/internal/testing/mockconnector"
	"golang.org/x/oauth2"
)

// internalTestKeyring builds a loaded Keyring using cheap argon2 params
// so the suite stays fast. Mirrors connections_test.testKeyring (which
// lives in the external test package and is not visible here).
func internalTestKeyring(t *testing.T, db *database.DB) *secrets.Keyring {
	t.Helper()
	saved := secrets.DefaultArgon2Params
	secrets.DefaultArgon2Params = secrets.Argon2Params{Time: 1, Memory: 8, Threads: 1, KeyLen: 32}
	defer func() { secrets.DefaultArgon2Params = saved }()
	k := &secrets.Keyring{}
	if err := k.Setup(db.DB, []byte("test-passphrase")); err != nil {
		t.Fatalf("keyring setup: %v", err)
	}
	return k
}

// setupRefresh creates a Service with one connection that has an
// oauth_token map in its config. Returns the service, raw db handle (for
// blob corruption in failure tests), and connection id.
func setupRefresh(t *testing.T) (*Service, *database.DB, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "refresh.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	registry := connector.NewRegistry()
	mock := mockconn.New("mock")
	registry.Register(mock.Meta(), mock.Factory())

	keyring := internalTestKeyring(t, db)
	svc := NewService(db, registry, keyring)

	const id = "rt-conn"
	cfg := map[string]any{
		"oauth_token": map[string]any{
			"access_token":  "old-access",
			"refresh_token": "old-refresh",
			"token_type":    "Bearer",
		},
	}
	if err := svc.Add(id, "mock", "RT Conn", cfg); err != nil {
		t.Fatalf("add: %v", err)
	}
	return svc, db, id
}

// invokeCallback grabs the `_on_token_refresh` callback the Service
// injected via injectRefreshCallback into a fresh config map and invokes
// it. Mirrors what golang.org/x/oauth2 does after a successful HTTP
// refresh.
func invokeCallback(t *testing.T, svc *Service, id string, tok *oauth2.Token) {
	t.Helper()
	cfg := map[string]any{}
	svc.injectRefreshCallback(id, cfg)
	cb, ok := cfg["_on_token_refresh"].(func(*oauth2.Token))
	if !ok {
		t.Fatal("_on_token_refresh not injected or wrong type")
	}
	cb(tok)
}

// TestInjectRefreshCallback_PersistSuccess_LeavesStatusActive verifies
// the happy path: a successful refresh updates the persisted oauth_token
// and leaves status='active'. Regression guard against over-eager status
// transitions on every refresh.
func TestInjectRefreshCallback_PersistSuccess_LeavesStatusActive(t *testing.T) {
	svc, _, id := setupRefresh(t)

	newTok := &oauth2.Token{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	invokeCallback(t, svc, id, newTok)

	c, err := svc.Get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if c.Status != StatusActive {
		t.Fatalf("expected status=active after successful refresh, got %q", c.Status)
	}

	full, err := svc.GetWithConfig(id)
	if err != nil {
		t.Fatalf("get with config: %v", err)
	}
	got, _ := full.Config["oauth_token"].(map[string]any)
	if got["access_token"] != "new-access" {
		t.Fatalf("expected access_token='new-access', got %v", got["access_token"])
	}
	if got["refresh_token"] != "new-refresh" {
		t.Fatalf("expected refresh_token='new-refresh', got %v", got["refresh_token"])
	}
}

// TestInjectRefreshCallback_PersistFailure_TransitionsToReauthRequired
// verifies that when the persist step fails, the connection's status
// MUST transition to reauth_required so subsequent agent calls
// short-circuit with ErrReauthRequired instead of burning further refresh
// attempts against a stale refresh token that the upstream has already
// invalidated.
//
// The failure is induced by corrupting the encrypted config blob:
// GetWithConfig then errors at decrypt, but the row itself stays intact
// so SetStatus can still succeed and the transition is observable.
// Equivalent observable behavior to a UpdateConfig write failure (DB
// error, disk full, encryption error) — same callback branch.
func TestInjectRefreshCallback_PersistFailure_TransitionsToReauthRequired(t *testing.T) {
	svc, db, id := setupRefresh(t)

	// Precondition.
	c, _ := svc.Get(id)
	if c.Status != StatusActive {
		t.Fatalf("precondition: expected status=active, got %q", c.Status)
	}

	// Corrupt the blob so GetWithConfig fails at decrypt.
	if _, err := db.Exec(
		`UPDATE connections SET config_ciphertext = ? WHERE id = ?`,
		make([]byte, 16), id,
	); err != nil {
		t.Fatalf("corrupt blob: %v", err)
	}

	newTok := &oauth2.Token{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	invokeCallback(t, svc, id, newTok)

	c2, err := svc.Get(id)
	if err != nil {
		t.Fatalf("get after failure: %v", err)
	}
	if c2.Status != StatusReauthRequired {
		t.Fatalf("expected status=reauth_required after persist failure, got %q", c2.Status)
	}
	// The persist-failure branch must record a non-empty reason so the
	// admin UI surfaces something meaningful — matches the contract of
	// the sibling _on_token_refresh_failure callback, which always
	// supplies a reason.
	if c2.ReauthReason == "" {
		t.Fatalf("expected non-empty ReauthReason after persist failure, got empty")
	}
}

// TestPersistRefreshedToken_DirectFailure exercises the persist helper
// directly to verify it returns an error without silently swallowing
// the failure (callers depend on that to drive the status transition).
func TestPersistRefreshedToken_DirectFailure(t *testing.T) {
	svc, db, id := setupRefresh(t)

	if _, err := db.Exec(
		`UPDATE connections SET config_ciphertext = ? WHERE id = ?`,
		make([]byte, 16), id,
	); err != nil {
		t.Fatalf("corrupt blob: %v", err)
	}

	err := svc.persistRefreshedToken(id, &oauth2.Token{AccessToken: "x", TokenType: "Bearer"})
	if err == nil {
		t.Fatal("expected persist to fail with corrupted blob")
	}
}

// TestPersistRefreshedToken_HappyPath exercises the persist helper on
// the no-error path and asserts the rotated token lands in the stored
// config. Companion to the TransitionsToReauthRequired failure test.
func TestPersistRefreshedToken_HappyPath(t *testing.T) {
	svc, _, id := setupRefresh(t)

	tok := &oauth2.Token{
		AccessToken:  "n1",
		RefreshToken: "r1",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	if err := svc.persistRefreshedToken(id, tok); err != nil {
		t.Fatalf("persist: %v", err)
	}
	c, _ := svc.GetWithConfig(id)
	got := c.Config["oauth_token"].(map[string]any)
	if got["access_token"] != "n1" || got["refresh_token"] != "r1" {
		t.Fatalf("token not persisted: %v", got)
	}
}
