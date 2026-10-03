package connections

import (
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/database"
	mockconn "github.com/trilitech/Sieve/internal/testing/mockconnector"
	"golang.org/x/oauth2"
)

// capturingService builds a Service whose registry records the config map
// handed to the connector factory on every create, so a test can assert which
// token-lifecycle callbacks were injected before the live connector was built.
func capturingService(t *testing.T) (*Service, *[]map[string]any) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "wiring.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	captured := &[]map[string]any{}
	registry := connector.NewRegistry()
	mock := mockconn.New("mock")
	inner := mock.Factory()
	registry.Register(mock.Meta(), func(cfg map[string]any) (connector.Connector, error) {
		*captured = append(*captured, cfg)
		return inner(cfg)
	})

	return NewService(db, registry, internalTestKeyring(t, db)), captured
}

// assertCallbacks fails unless the config the factory received carries both
// lifecycle callbacks with their expected signatures.
func assertCallbacks(t *testing.T, where string, cfg map[string]any) {
	t.Helper()
	if _, ok := cfg["_on_token_refresh_failure"].(func(string)); !ok {
		t.Errorf("%s: live connector built WITHOUT _on_token_refresh_failure — an irrecoverable "+
			"refresh (invalid_grant) can never flip the connection to reauth_required, so the UI "+
			"keeps showing Active while every agent call fails", where)
	}
	if _, ok := cfg["_on_token_refresh"].(func(*oauth2.Token)); !ok {
		t.Errorf("%s: live connector built WITHOUT _on_token_refresh — a rotated token is never "+
			"persisted, so every restart burns a fresh refresh", where)
	}
}

// TestRefreshCallbacks_WiredAtEveryCreateSite is the regression guard for the
// reported bug: perso-gmail/c1-gmail kept reporting "needs re-authentication:
// invalid_grant" to agents while the admin UI still showed them as Active.
// Root cause: UpdateConfig — which runs on EVERY successful OAuth re-auth —
// rebuilt the cached live connector from a config map with no callbacks, so the
// connector that replaced the working one was permanently deaf to refresh
// failures. Add() had the same gap.
func TestRefreshCallbacks_WiredAtEveryCreateSite(t *testing.T) {
	svc, captured := capturingService(t)

	cfg := map[string]any{"oauth_token": map[string]any{
		"access_token": "a", "refresh_token": "r", "token_type": "Bearer",
	}}

	if err := svc.Add("c1", "mock", "C1", cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(*captured) == 0 {
		t.Fatal("Add created no live connector")
	}
	assertCallbacks(t, "Add", (*captured)[len(*captured)-1])

	// The reported path: a successful re-auth calls UpdateConfig.
	*captured = nil
	if err := svc.UpdateConfig("c1", map[string]any{"oauth_token": map[string]any{
		"access_token": "a2", "refresh_token": "r2", "token_type": "Bearer",
	}}); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}
	if len(*captured) == 0 {
		t.Fatal("UpdateConfig created no live connector")
	}
	assertCallbacks(t, "UpdateConfig", (*captured)[len(*captured)-1])

	// GetConnector's lazy path (clear the cache so it rebuilds from the DB).
	svc.mu.Lock()
	delete(svc.live, "c1")
	svc.mu.Unlock()
	*captured = nil
	if _, err := svc.GetConnector("c1"); err != nil {
		t.Fatalf("GetConnector: %v", err)
	}
	if len(*captured) == 0 {
		t.Fatal("GetConnector created no live connector")
	}
	assertCallbacks(t, "GetConnector", (*captured)[len(*captured)-1])
}

// TestRefreshCallbacks_NotPersisted guards the other side of the injection:
// the "_"-prefixed function values must never reach the encrypted config blob
// (they are not JSON-marshalable and are runtime-only wiring).
func TestRefreshCallbacks_NotPersisted(t *testing.T) {
	svc, _ := capturingService(t)
	cfg := map[string]any{"oauth_token": map[string]any{"access_token": "a", "refresh_token": "r"}}
	if err := svc.Add("c2", "mock", "C2", cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := svc.UpdateConfig("c2", map[string]any{"oauth_token": map[string]any{"access_token": "b"}}); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}
	got, err := svc.GetWithConfig("c2")
	if err != nil {
		t.Fatalf("GetWithConfig: %v", err)
	}
	for _, k := range []string{"_on_token_refresh", "_on_token_refresh_failure"} {
		if _, present := got.Config[k]; present {
			t.Errorf("%q leaked into the persisted config blob", k)
		}
	}
}
