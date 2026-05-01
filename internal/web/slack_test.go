package web

// Tests for the Slack admin-side handlers: OAuth start, OAuth callback,
// direct bot-token entry, and reauth.
//
// Internal package so the package-level slackOAuthEndpointOverride
// testing seam is reachable. Stands up a real Server backed by testenv
// (in-memory DB + keyring) and a small httptest.Server playing the
// Slack OAuth + auth.test endpoints.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connections"
	slackconn "github.com/trilitech/Sieve/internal/connectors/slack"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// slackTestServer brings up a fresh Server + mock Slack OAuth surface.
// The mock implements oauth.v2.access (returns a canned bot token) and
// auth.test (returns canned team metadata).
func slackTestServer(t *testing.T) (handler http.Handler, mockSlack *httptest.Server, env *testenv.Env) {
	t.Helper()
	env = testenv.New(t)
	// Register the slack connector factory in the test env's registry
	// so connections.Service can construct a Connector for it. testenv
	// only registers `mock` by default.
	env.Registry.Register(slackconn.Meta(), slackconn.Factory())

	mockSlack = httptest.NewServer(http.HandlerFunc(slackMockHandler))
	t.Cleanup(mockSlack.Close)

	// Point the web/slack.go endpoints at the mock for the duration
	// of the test. Cleanup restores the production string.
	prevOverride := slackOAuthEndpointOverride
	slackOAuthEndpointOverride = mockSlack.URL
	t.Cleanup(func() { slackOAuthEndpointOverride = prevOverride })

	// Provide credentials for the OAuth path.
	t.Setenv("SLACK_CLIENT_ID", "test-client-id")
	t.Setenv("SLACK_CLIENT_SECRET", "test-client-secret")

	// Build a Server directly (no NewServer) so the OAuth-cleanup
	// background goroutine doesn't run during the test. None of the
	// Slack handlers under test render templates, so an empty templates
	// map is sufficient — if a future test needs template rendering it
	// must call NewServer instead and accept the goroutine.
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := &Server{
		tokens:       env.Tokens,
		connections:  env.Connections,
		policies:     env.Policies,
		roles:        env.Roles,
		registry:     env.Registry,
		approval:     env.Approval,
		audit:        env.Audit,
		settings:     env.Settings,
		scriptgen:    scriptgenSvc,
		oauthPending: make(map[string]pendingOAuth),
		githubApp:    newGitHubAppState(),
		stopCleanup:  make(chan struct{}),
	}
	t.Cleanup(func() { srv.Close() })
	return srv.Handler(), mockSlack, env
}

// slackMockHandler implements oauth.v2.access and auth.test. The
// production endpoints (see web/slack.go) are concatenated against
// the override base URL, so we listen at /api/oauth.v2.access and
// /api/auth.test.
func slackMockHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/oauth.v2.access":
		json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"access_token": "xoxb-test-installed",
			"token_type":   "bot",
			"scope":        "channels:read,chat:write",
			"bot_user_id":  "U0KRQLJ9H",
			"team":         map[string]any{"id": "T012", "name": "Acme"},
		})
	case "/api/auth.test":
		auth := r.Header.Get("Authorization")
		if auth == "Bearer xoxb-bad-token" {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid_auth"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"team":    "Acme",
			"team_id": "T012",
			"user":    "sieve-bot",
			"user_id": "U0KRQLJ9H",
		})
	default:
		http.NotFound(w, r)
	}
}

// formPost issues a POST with form-encoded body.
func formPost(handler http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestHandleSlackToken_HappyPath asserts a valid xoxb- token is
// validated against auth.test then persisted with status=active.
func TestHandleSlackToken_HappyPath(t *testing.T) {
	handler, _, env := slackTestServer(t)

	rec := formPost(handler, "/connections/slack/token", url.Values{
		"id":           {"acme"},
		"display_name": {"Acme Slack"},
		"bot_token":    {"xoxb-real-token"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	c, err := env.Connections.Get("acme")
	if err != nil {
		t.Fatalf("connection not persisted: %v", err)
	}
	if c.ConnectorType != "slack" {
		t.Fatalf("connector_type = %q, want slack", c.ConnectorType)
	}
	if c.Status != connections.StatusActive {
		t.Fatalf("status = %q, want active", c.Status)
	}
	full, _ := env.Connections.GetWithConfig("acme")
	if full.Config["bot_token"] != "xoxb-real-token" {
		t.Fatalf("bot_token not encrypted-and-stored: %v", full.Config["bot_token"])
	}
	if full.Config["team_id"] != "T012" {
		t.Fatalf("team_id not picked up from auth.test: %v", full.Config["team_id"])
	}
}

// TestHandleSlackToken_RejectsBadPrefix asserts non-bot tokens are
// rejected without an upstream call.
func TestHandleSlackToken_RejectsBadPrefix(t *testing.T) {
	handler, _, _ := slackTestServer(t)
	rec := formPost(handler, "/connections/slack/token", url.Values{
		"id":           {"bad"},
		"display_name": {"Bad"},
		"bot_token":    {"xoxp-user-token"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-bot token, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestHandleSlackToken_RejectsBadAuthTest — Slack auth.test returning
// invalid_auth must surface as a 400 (admin error) and NOT persist.
func TestHandleSlackToken_RejectsBadAuthTest(t *testing.T) {
	handler, _, env := slackTestServer(t)
	rec := formPost(handler, "/connections/slack/token", url.Values{
		"id":           {"bad-auth"},
		"display_name": {"BadAuth"},
		"bot_token":    {"xoxb-bad-token"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for failed auth.test, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if exists, _ := env.Connections.Exists("bad-auth"); exists {
		t.Fatal("connection persisted despite failed auth.test")
	}
}

// TestHandleSlackToken_RejectsAgentToken — FR-013: the admin-side
// path must reject any request carrying an agent bearer.
func TestHandleSlackToken_RejectsAgentToken(t *testing.T) {
	handler, _, _ := slackTestServer(t)
	form := url.Values{
		"id":           {"agent"},
		"display_name": {"Agent"},
		"bot_token":    {"xoxb-real"},
	}
	req := httptest.NewRequest(http.MethodPost, "/connections/slack/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer sieve_tok_abc")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for agent token, got %d", rec.Code)
	}
}

// TestHandleSlackOAuthStart_PendingState — the start handler must
// stash a pendingOAuth entry keyed by random state and redirect to
// the Slack authorize endpoint with that state.
func TestHandleSlackOAuthStart_PendingState(t *testing.T) {
	handler, mockSlack, _ := slackTestServer(t)

	rec := formPost(handler, "/connections/slack/oauth/start", url.Values{
		"id":           {"oauth-conn"},
		"display_name": {"OAuth Conn"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, mockSlack.URL+"/oauth/v2/authorize") {
		t.Fatalf("redirect target %q does not point at mock authorize endpoint", loc)
	}
	if !strings.Contains(loc, "state=") {
		t.Fatalf("redirect missing state param: %s", loc)
	}
	if !strings.Contains(loc, "client_id=test-client-id") {
		t.Fatalf("redirect missing client_id: %s", loc)
	}
}

// TestHandleSlackOAuthStart_RejectsExistingConnection — id collision
// must fail before the Slack redirect, otherwise the operator could
// shadow an existing connection.
func TestHandleSlackOAuthStart_RejectsExistingConnection(t *testing.T) {
	handler, _, env := slackTestServer(t)
	if err := env.Connections.Add("dup", "mock", "Dup", map[string]any{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rec := formPost(handler, "/connections/slack/oauth/start", url.Values{
		"id":           {"dup"},
		"display_name": {"Dup"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on id collision, got %d", rec.Code)
	}
}

// TestHandleSlackOAuthStart_NoCredentials — when SLACK_CLIENT_ID is
// missing we surface a clear 400 instead of redirecting to a malformed
// URL. The token-entry path remains usable.
func TestHandleSlackOAuthStart_NoCredentials(t *testing.T) {
	handler, _, _ := slackTestServer(t)
	t.Setenv("SLACK_CLIENT_ID", "")
	rec := formPost(handler, "/connections/slack/oauth/start", url.Values{
		"id":           {"x"},
		"display_name": {"X"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with missing SLACK_CLIENT_ID, got %d", rec.Code)
	}
}

// TestHandleOAuthCallback_SlackHappyPath drives the full state →
// exchange → persist flow. Pre-seeds an oauthPending entry, then
// hits /oauth/callback?code=&state= and asserts a connection lands
// with the canned mock data.
func TestHandleOAuthCallback_SlackHappyPath(t *testing.T) {
	handler, _, env := slackTestServer(t)

	// Pre-seed oauthPending. The struct itself is unexported but we
	// access it through the Server pointer the slackTestServer helper
	// returned — re-derive via a fresh start-handler call.
	startRec := formPost(handler, "/connections/slack/oauth/start", url.Values{
		"id":           {"acme-oauth"},
		"display_name": {"Acme OAuth"},
	})
	if startRec.Code != http.StatusFound {
		t.Fatalf("oauth/start failed: %d", startRec.Code)
	}
	loc, _ := url.Parse(startRec.Header().Get("Location"))
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("no state in start redirect")
	}

	// Hit the callback with a fake code.
	cbReq := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=fake-code&state="+state, nil)
	cbRec := httptest.NewRecorder()
	handler.ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 after callback, got %d (body: %s)", cbRec.Code, cbRec.Body.String())
	}

	c, err := env.Connections.Get("acme-oauth")
	if err != nil {
		t.Fatalf("connection not persisted: %v", err)
	}
	if c.ConnectorType != "slack" || c.Status != connections.StatusActive {
		t.Fatalf("connection metadata wrong: %+v", c)
	}
	full, _ := env.Connections.GetWithConfig("acme-oauth")
	if full.Config["auth_kind"] != slackconn.KindOAuth {
		t.Fatalf("expected auth_kind=oauth, got %v", full.Config["auth_kind"])
	}
	tokenMap, _ := full.Config["oauth_token"].(map[string]any)
	if tokenMap["access_token"] != "xoxb-test-installed" {
		t.Fatalf("access_token not persisted: %v", tokenMap)
	}
}

// TestHandleSlackReauth_TokenPath — re-pasting a fresh bot token on
// a reauth_required row clears the status by validating + UpdateConfig.
func TestHandleSlackReauth_TokenPath(t *testing.T) {
	handler, _, env := slackTestServer(t)

	// Seed a reauth_required Slack connection.
	if err := env.Connections.Add("seeded", "slack", "Seeded", map[string]any{
		"auth_kind":   slackconn.KindToken,
		"bot_token":   "xoxb-original",
		"team_id":     "T012",
		"team_name":   "Acme",
		"bot_user_id": "U0KRQLJ9H",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := env.Connections.SetStatus("seeded", connections.StatusReauthRequired); err != nil {
		t.Fatalf("set status: %v", err)
	}

	rec := formPost(handler, "/connections/slack/seeded/reauth", url.Values{
		"bot_token": {"xoxb-fresh-token"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	c, _ := env.Connections.Get("seeded")
	if c.Status != connections.StatusActive {
		t.Fatalf("expected status=active after reauth, got %q", c.Status)
	}
	full, _ := env.Connections.GetWithConfig("seeded")
	if full.Config["bot_token"] != "xoxb-fresh-token" {
		t.Fatalf("bot_token not refreshed: %v", full.Config["bot_token"])
	}
}

