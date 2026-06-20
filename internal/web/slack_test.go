package web

// Tests for the Slack admin-side handlers: OAuth start, OAuth callback,
// direct bot-token entry, and reauth.
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
	env = testenv.New(t).WithOperator("test-pass", "test-op")
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
		operatorSvc:  env.Operator,
		sessionMgr:   env.Session,
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

// formPost issues a POST with form-encoded body. Attaches the env's
// active operator session cookie + CSRF token so requests pass the
// requireOperatorSession middleware.
func formPost(handler http.Handler, env *testenv.Env, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c := env.SessionCookie(); c != nil {
		req.AddCookie(c)
	}
	if tok := env.CSRFToken(); tok != "" {
		req.Header.Set("X-CSRF-Token", tok)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// getRequest builds a GET request with the env's session cookie attached.
// Use for tests that want to assert on the response of an authenticated
// GET (info-disclosing pages like /connections, /tokens, etc.).
func getRequest(handler http.Handler, env *testenv.Env, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if c := env.SessionCookie(); c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestHandleSlackToken_HappyPath asserts a valid xoxb- token is
// validated against auth.test then persisted with status=active.
func TestHandleSlackToken_HappyPath(t *testing.T) {
	handler, _, env := slackTestServer(t)

	rec := formPost(handler, env, "/connections/slack/token", url.Values{
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
	handler, _, env := slackTestServer(t)
	rec := formPost(handler, env, "/connections/slack/token", url.Values{
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
	rec := formPost(handler, env, "/connections/slack/token", url.Values{
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

// TestHandleSlackToken_RejectsAgentToken — the admin-side path must
// reject any request carrying an agent bearer.
func TestHandleSlackToken_RejectsAgentToken(t *testing.T) {
	handler, _, _ := slackTestServer(t)
	form := url.Values{
		"id":           {"agent"},
		"display_name": {"Agent"},
		"bot_token":    {"xoxb-real"},
	}
	// Deliberately NO session cookie — the agent's bearer token must
	// surface 403 so a confused agent client gets a clear
	// "wrong port" signal rather than a 401 / redirect.
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
	handler, mockSlack, env := slackTestServer(t)

	rec := formPost(handler, env, "/connections/slack/oauth/start", url.Values{
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
	rec := formPost(handler, env, "/connections/slack/oauth/start", url.Values{
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
	handler, _, env := slackTestServer(t)
	t.Setenv("SLACK_CLIENT_ID", "")
	rec := formPost(handler, env, "/connections/slack/oauth/start", url.Values{
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
	startRec := formPost(handler, env, "/connections/slack/oauth/start", url.Values{
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

	// Hit the callback with a fake code. The callback must carry the
	// same operator session cookie the /start request used — the
	// pendingOAuth session-binding check rejects mismatches.
	cbReq := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=fake-code&state="+state, nil)
	if c := env.SessionCookie(); c != nil {
		cbReq.AddCookie(c)
	}
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

// slackUITestServer brings up a fully-templated Server (via NewServer)
// for tests that need to render the connections page. Use the lighter
// slackTestServer helper for handler-only tests — that path skips
// template parsing and the OAuth-cleanup goroutine.
func slackUITestServer(t *testing.T) (http.Handler, *testenv.Env) {
	t.Helper()
	env := testenv.New(t).WithOperator("test-pass", "test-op")
	env.Registry.Register(slackconn.Meta(), slackconn.Factory())
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := NewServer(
		env.Tokens, env.Connections, env.Policies, env.Roles, env.Registry,
		env.Approval, env.Audit, "", env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "",
	)
	srv.SetAuth(env.Operator, env.Session)
	t.Cleanup(func() { srv.Close() })
	return srv.Handler(), env
}

// TestConnectionsPage_SlackCard_OAuthEnabled asserts the connections
// page renders the Slack card with both a working OAuth-install form
// (POSTs to /connections/slack/oauth/start) AND the bot-token paste
// form (POSTs to /connections/slack/token) when SLACK_CLIENT_ID and
// SLACK_CLIENT_SECRET are set. The previous regression — the user
// report behind this fix — was that the Slack tile fell through to
// the generic /connections/add form, persisting an empty config.
func TestConnectionsPage_SlackCard_OAuthEnabled(t *testing.T) {
	t.Setenv("SLACK_CLIENT_ID", "test-client-id")
	t.Setenv("SLACK_CLIENT_SECRET", "test-client-secret")
	handler, env := slackUITestServer(t)

	rec := getRequest(handler, env, "/connections")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()

	if !strings.Contains(body, `action="/connections/slack/oauth/start"`) {
		t.Errorf("Slack card missing OAuth-start form (action=/connections/slack/oauth/start)")
	}
	if !strings.Contains(body, `action="/connections/slack/token"`) {
		t.Errorf("Slack card missing bot-token form (action=/connections/slack/token)")
	}
	// The Slack card must NOT have a generic /connections/add form
	// with connector_type=slack — that's the broken fallthrough this
	// fix closes. Look for the specific bad pattern.
	if strings.Contains(body, `<input type="hidden" name="connector_type" value="slack">`) {
		t.Errorf("Slack card should not render the generic /connections/add hidden input — it must use the Slack-specific routes")
	}
}

// TestConnectionsPage_SlackCard_OAuthDisabled asserts that when no
// Slack OAuth credentials are configured (neither in settings nor in
// env vars), the card replaces the install button with an in-UI
// configure form. The bot-token paste form remains available as a
// parallel install path.
// Critically: the configure form must POST to
// /connections/slack/oauth/configure (the new in-UI setup endpoint),
// NOT instruct the operator to set env vars and restart. Earlier
// versions of this code surfaced an env-var hint instead — that UX
// regression is what the user reported on 2026-05-04.
func TestConnectionsPage_SlackCard_OAuthDisabled(t *testing.T) {
	t.Setenv("SLACK_CLIENT_ID", "")
	t.Setenv("SLACK_CLIENT_SECRET", "")
	handler, env := slackUITestServer(t)

	rec := getRequest(handler, env, "/connections")
	body := rec.Body.String()

	if strings.Contains(body, `action="/connections/slack/oauth/start"`) {
		t.Errorf("OAuth-start form should be hidden when credentials are unset")
	}
	if !strings.Contains(body, `action="/connections/slack/oauth/configure"`) {
		t.Errorf("expected in-UI configure form (action=/connections/slack/oauth/configure) when OAuth is unset")
	}
	if !strings.Contains(body, `name="client_id"`) || !strings.Contains(body, `name="client_secret"`) {
		t.Errorf("configure form must accept both client_id and client_secret inputs")
	}
	if !strings.Contains(body, `action="/connections/slack/token"`) {
		t.Errorf("Bot-token form must still be available without OAuth credentials")
	}
}

// TestHandleSlackOAuthConfigure_HappyPath asserts that pasting valid-
// looking client_id + client_secret persists them via settings and
// redirects back to the connections page. Subsequent GETs show the
// install button instead of the configure form — no restart required.
func TestHandleSlackOAuthConfigure_HappyPath(t *testing.T) {
	// Clear env so settings is the only source.
	t.Setenv("SLACK_CLIENT_ID", "")
	t.Setenv("SLACK_CLIENT_SECRET", "")
	handler, env := slackUITestServer(t)

	rec := formPost(handler, env, "/connections/slack/oauth/configure", url.Values{
		"client_id":     {"1234567890.0987654321"},
		"client_secret": {"abcdef0123456789abcdef0123456789"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// Persisted as an envelope-encrypted _oauth_app:slack row.
	creds, err := env.Connections.GetOAuthApp("slack")
	if err != nil {
		t.Fatalf("GetOAuthApp: %v", err)
	}
	if creds == nil {
		t.Fatal("expected _oauth_app:slack row, got nil")
	}
	if creds.ClientID != "1234567890.0987654321" {
		t.Errorf("client_id not persisted: %q", creds.ClientID)
	}
	if creds.ClientSecret != "abcdef0123456789abcdef0123456789" {
		t.Errorf("client_secret not persisted: %q", creds.ClientSecret)
	}
	// Secret must not survive in the plaintext settings table.
	if v, _ := env.Settings.Get("slack_client_secret"); v != "" {
		t.Errorf("client_secret leaked into settings: %q", v)
	}

	// Subsequent /connections render shows the install button, no
	// configure form.
	rec2 := getRequest(handler, env, "/connections")
	body := rec2.Body.String()
	if !strings.Contains(body, `action="/connections/slack/oauth/start"`) {
		t.Errorf("install button should appear after configure")
	}
	if strings.Contains(body, `action="/connections/slack/oauth/configure"`) {
		t.Errorf("configure form should be hidden after credentials are set")
	}
}

// TestHandleSlackOAuthConfigure_ValidatesShape rejects obviously
// malformed credentials before persisting. We don't try to actually
// hit Slack here — that would require the OAuth flow to start, which
// only happens when the install button is clicked.
func TestHandleSlackOAuthConfigure_ValidatesShape(t *testing.T) {
	handler, env := slackUITestServer(t)

	cases := []struct {
		name string
		form url.Values
	}{
		{"missing client_id", url.Values{"client_secret": {"abcdef0123456789abcdef"}}},
		{"missing client_secret", url.Values{"client_id": {"123.456"}}},
		{"client_id without dot", url.Values{"client_id": {"plainstring"}, "client_secret": {"abcdef0123456789abcdef"}}},
		{"client_id too short", url.Values{"client_id": {"1.2"}, "client_secret": {"abcdef0123456789abcdef"}}},
		{"client_secret too short", url.Values{"client_id": {"1234567890.0987654321"}, "client_secret": {"short"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := formPost(handler, env, "/connections/slack/oauth/configure", tc.form)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d (body: %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestHandleSlackOAuthConfigure_RejectsAgentToken — the configure
// endpoint stores OAuth secrets, so it MUST reject agent tokens.
// A stolen agent token must not be able to swap the operator's
// Slack app credentials.
func TestHandleSlackOAuthConfigure_RejectsAgentToken(t *testing.T) {
	handler, _ := slackUITestServer(t)
	form := url.Values{
		"client_id":     {"1234567890.0987654321"},
		"client_secret": {"abcdef0123456789abcdef0123456789"},
	}
	req := httptest.NewRequest(http.MethodPost, "/connections/slack/oauth/configure", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer sieve_tok_attacker")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for agent token, got %d", rec.Code)
	}
}

// TestHandleSlackOAuthClearConfig wipes persisted creds. After clear
// the configure form returns and the install button disappears.
// Creds live in the _oauth_app:slack row, not settings.
func TestHandleSlackOAuthClearConfig(t *testing.T) {
	t.Setenv("SLACK_CLIENT_ID", "")
	t.Setenv("SLACK_CLIENT_SECRET", "")
	handler, env := slackUITestServer(t)

	// Pre-populate via the encrypted storage path.
	if err := env.Connections.PutOAuthApp("slack", connections.OAuthAppCredentials{
		ClientID:     "1234567890.0987654321",
		ClientSecret: "abcdef0123456789abcdef0123456789",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := formPost(handler, env, "/connections/slack/oauth/clear", url.Values{})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	creds, err := env.Connections.GetOAuthApp("slack")
	if err != nil {
		t.Fatalf("GetOAuthApp after clear: %v", err)
	}
	if creds != nil {
		t.Errorf("oauth_app:slack row not cleared: %+v", creds)
	}
}

// TestHandleConnectionAdd_RejectsSlack closes the regression: the
// generic /connections/add path used to silently create an empty-
// config Slack row when the template fell through to its hidden
// connector_type=slack input. Now it returns 400 with a clear
// message pointing at the Slack-specific routes.
func TestHandleConnectionAdd_RejectsSlack(t *testing.T) {
	handler, _, env := slackTestServer(t)

	form := url.Values{
		"id":             {"sneaky"},
		"display_name":   {"Sneaky"},
		"connector_type": {"slack"},
	}
	rec := formPost(handler, env, "/connections/add", form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if exists, _ := env.Connections.Exists("sneaky"); exists {
		t.Fatal("connection should NOT be persisted when using the wrong route")
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/connections/slack/oauth/start") && !strings.Contains(body, "/connections/slack/token") {
		t.Errorf("rejection message should point operator at the slack-specific routes, got: %s", body)
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

	rec := formPost(handler, env, "/connections/slack/seeded/reauth", url.Values{
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

// TestPoliciesPage_SlackScope asserts the policies create form renders
// the Slack-specific rule builder when ?scope=slack — Slack operation
// checkboxes (list_channels, post_message, etc.) and the Slack-specific
// filter fields (channel, user, text-contains) must all appear, and
// Gmail-only operations (list_emails, send_email) must not.
func TestPoliciesPage_SlackScope(t *testing.T) {
	handler, env := slackUITestServer(t)

	rec := getRequest(handler, env, "/policies?scope=slack")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	wantOps := []string{
		`value="list_channels"`,
		`value="list_users"`,
		`value="read_user_profile"`,
		`value="read_channel_history"`,
		`value="read_thread"`,
		`value="post_message"`,
		`value="search_messages"`,
	}
	for _, op := range wantOps {
		if !strings.Contains(body, op) {
			t.Errorf("slack scope rule builder missing op checkbox %q", op)
		}
	}
	wantFilters := []string{
		`id="filter-slack-channel"`,
		`id="filter-slack-user"`,
		`id="filter-slack-text"`,
		`id="rule-slack-channel"`,
		`id="rule-slack-user"`,
		`id="rule-slack-text"`,
	}
	for _, f := range wantFilters {
		if !strings.Contains(body, f) {
			t.Errorf("slack scope rule builder missing filter %q", f)
		}
	}
	// Gmail-only ops must not leak into Slack scope.
	for _, gmail := range []string{`value="list_emails"`, `value="send_email"`, `value="create_draft"`} {
		if strings.Contains(body, gmail) {
			t.Errorf("slack scope rule builder unexpectedly contains gmail op %q", gmail)
		}
	}
	// JS scope variable must reflect the URL scope so submit maps to engine fields.
	if !strings.Contains(body, `var SCOPE = "slack"`) {
		t.Errorf("expected JS SCOPE to be set to \"slack\"")
	}
}
