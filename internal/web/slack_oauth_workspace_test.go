package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	slackconn "github.com/trilitech/Sieve/internal/connectors/slack"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// reauthOAuthCallback drives a Slack OAuth reauth for connection id and returns
// the callback recorder. It stashes the pendingOAuth via the reauth handler
// (empty form ⇒ OAuth path), then completes the callback with the mock code.
func reauthOAuthCallback(t *testing.T, handler http.Handler, env *testenv.Env, id, code string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/connections/slack/"+id+"/reauth", nil)
	if c := env.SessionCookie(); c != nil {
		req.AddCookie(c)
	}
	if tok := env.CSRFToken(); tok != "" {
		req.Header.Set("X-CSRF-Token", tok)
	}
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, req)
	if startRec.Code != http.StatusFound {
		t.Fatalf("reauth start: want 302 redirect to Slack, got %d (%s)", startRec.Code, startRec.Body.String())
	}
	loc, _ := url.Parse(startRec.Header().Get("Location"))
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("no state in reauth redirect")
	}
	cbReq := httptest.NewRequest(http.MethodGet, "/oauth/callback?code="+code+"&state="+state, nil)
	if c := env.SessionCookie(); c != nil {
		cbReq.AddCookie(c)
	}
	cbRec := httptest.NewRecorder()
	handler.ServeHTTP(cbRec, cbReq)
	return cbRec
}

// TestHandleSlackOAuthReauth_RejectsWorkspaceSwap proves an OAuth reauth cannot
// silently repoint a connection at a different Slack workspace. IAM grants bind
// to the connection id, so the workspace behind that id must stay fixed across
// reauth. The token-paste path already guarded this; the OAuth path did not.
// The mock oauth.v2.access always returns team T012; the seeded connection is on
// a different team, so the reauth must be rejected and the config left intact.
func TestHandleSlackOAuthReauth_RejectsWorkspaceSwap(t *testing.T) {
	handler, _, env := slackTestServer(t)

	// Existing bot connection on workspace T999 (different from the mock's T012).
	if err := env.Connections.Add("acme", "slack", "Acme", map[string]any{
		"auth_kind": slackconn.KindToken,
		"bot_token": "xoxb-existing",
		"team_id":   "T999",
		"team_name": "Acme Old",
	}); err != nil {
		t.Fatalf("seed connection: %v", err)
	}

	cbRec := reauthOAuthCallback(t, handler, env, "acme", "fake-code")

	if cbRec.Code != http.StatusBadRequest {
		t.Fatalf("OAuth reauth against a different workspace must be rejected (400), got %d (%s)", cbRec.Code, cbRec.Body.String())
	}
	// Config must be unchanged — still workspace T999, still the old token.
	full, err := env.Connections.GetWithConfig("acme")
	if err != nil {
		t.Fatalf("get connection: %v", err)
	}
	if full.Config["team_id"] != "T999" {
		t.Errorf("connection workspace was repointed: team_id=%v (want T999)", full.Config["team_id"])
	}
	if full.Config["bot_token"] != "xoxb-existing" {
		t.Errorf("connection token was overwritten: %v", full.Config["bot_token"])
	}
}

// TestHandleSlackOAuthReauth_SameWorkspaceSucceeds proves the workspace guard
// doesn't break the legitimate case: reauthorizing against the SAME workspace
// updates the connection and reactivates it.
func TestHandleSlackOAuthReauth_SameWorkspaceSucceeds(t *testing.T) {
	handler, _, env := slackTestServer(t)

	// Existing bot connection already on T012 (what the mock returns).
	if err := env.Connections.Add("acme", "slack", "Acme", map[string]any{
		"auth_kind": slackconn.KindToken,
		"bot_token": "xoxb-existing",
		"team_id":   "T012",
		"team_name": "Acme",
	}); err != nil {
		t.Fatalf("seed connection: %v", err)
	}

	cbRec := reauthOAuthCallback(t, handler, env, "acme", "fake-code")

	if cbRec.Code != http.StatusSeeOther {
		t.Fatalf("same-workspace reauth should succeed (303), got %d (%s)", cbRec.Code, cbRec.Body.String())
	}
	full, err := env.Connections.GetWithConfig("acme")
	if err != nil {
		t.Fatalf("get connection: %v", err)
	}
	if full.Config["auth_kind"] != slackconn.KindOAuth {
		t.Errorf("reauth should have written the OAuth install config, got auth_kind=%v", full.Config["auth_kind"])
	}
}

// TestHandleSlackToken_KeyringLocked503 proves a config-WRITE path returns 503
// "service locked" (not 500) when the keyring is locked, per the CLAUDE.md
// contract — a transient service state, not a server error.
func TestHandleSlackToken_KeyringLocked503(t *testing.T) {
	handler, _, env := slackTestServer(t)
	env.Keyring.Lock() // auth.test still works (no keyring), but connections.Add can't encrypt

	rec := formPost(handler, env, "/connections/slack/token", url.Values{
		"id":           {"acme"},
		"display_name": {"Acme"},
		"bot_token":    {"xoxb-valid-looking"},
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("keyring-locked config write should be 503, got %d (%s)", rec.Code, rec.Body.String())
	}
}
