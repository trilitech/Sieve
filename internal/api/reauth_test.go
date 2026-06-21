package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// reauthEnv builds a complete env with a connection + token wired up, ready
// for tests that need to flag the connection between Add and the API call.
type reauthEnv struct {
	*testenv.Env
	Token  string
	Server *httptest.Server
}

func newReauthEnv(t *testing.T) *reauthEnv {
	t.Helper()
	env := testenv.New(t)
	role := env.SetupConnectionAndRole(t, "test-conn", "read-only")
	tok := env.CreateToken(t, role.ID)
	srv := httptest.NewServer(api.NewRouter(
		env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit,
	).Handler())
	t.Cleanup(srv.Close)
	return &reauthEnv{Env: env, Token: tok, Server: srv}
}

// TestReauth_StructuredResponse: a flagged connection returns HTTP 403
// with the canonical reauth_required envelope. The legacy 503/
// connection_reauth_required shape was retired.
func TestReauth_StructuredResponse(t *testing.T) {
	r := newReauthEnv(t)

	if err := r.Connections.SetStatusWithReason("test-conn", connections.StatusReauthRequired, "invalid_grant: refresh token revoked"); err != nil {
		t.Fatalf("set reauth_required: %v", err)
	}

	req, _ := http.NewRequest("POST",
		r.Server.URL+"/api/v1/connections/test-conn/ops/list_emails",
		strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+r.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if body["error"] != "reauth_required" {
		t.Errorf("error = %v, want reauth_required", body["error"])
	}
	if body["connection_id"] != "test-conn" {
		t.Errorf("connection_id = %v, want test-conn", body["connection_id"])
	}
	if body["reauth_url"] != "/connections/test-conn/reauth" {
		t.Errorf("reauth_url = %v", body["reauth_url"])
	}
	if reason, _ := body["reason"].(string); !strings.Contains(reason, "invalid_grant") {
		t.Errorf("reason should mention invalid_grant, got %q", reason)
	}
}

// TestReauth_ClearedAfterUpdateConfig: a successful re-auth (modeled by
// UpdateConfig with fresh credentials) must immediately stop returning 503.
// Verifies that needs_reauth is cleared in the same UPDATE as the config —
// no stale-flag race window where the UI says "broken" but the API works.
func TestReauth_ClearedAfterUpdateConfig(t *testing.T) {
	r := newReauthEnv(t)

	if err := r.Connections.SetStatusWithReason("test-conn", connections.StatusReauthRequired, "invalid_grant"); err != nil {
		t.Fatalf("set reauth_required: %v", err)
	}
	if err := r.Connections.UpdateConfig("test-conn", map[string]any{"refreshed": true}); err != nil {
		t.Fatalf("update: %v", err)
	}

	req, _ := http.NewRequest("POST",
		r.Server.URL+"/api/v1/connections/test-conn/ops/list_emails",
		strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+r.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		t.Errorf("after re-auth (UpdateConfig), expected non-403, got 403 — reauth-required state should have cleared")
	}
}
