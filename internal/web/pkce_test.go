package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/testing/testenv"
	"golang.org/x/oauth2"
)

// TestPKCEChallengeParams proves the hand-rolled challenge params match what the
// oauth2 library derives from the same verifier — so a verifier minted here and
// sent to Slack via pkceChallengeParams is the same proof a library-based
// provider (google) would present via oauth2.S256ChallengeOption.
func TestPKCEChallengeParams(t *testing.T) {
	v1, v2 := newPKCEVerifier(), newPKCEVerifier()
	if v1 == "" || v2 == "" {
		t.Fatal("verifier must be non-empty")
	}
	if v1 == v2 {
		t.Fatal("verifiers must be unique per flow")
	}

	got := pkceChallengeParams(v1)
	if m := got.Get("code_challenge_method"); m != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", m)
	}
	if want := oauth2.S256ChallengeFromVerifier(v1); got.Get("code_challenge") != want {
		t.Errorf("code_challenge = %q, want %q (S256 of verifier)", got.Get("code_challenge"), want)
	}
}

// capturingTokenServer stands up a mock Slack token endpoint that records the
// form of the LAST oauth.v2.access request and returns a canned bot install.
// It replaces slackTestServer's endpoint override for the duration of the test.
func capturingTokenServer(t *testing.T, got *url.Values) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/oauth.v2.access" {
			_ = r.ParseForm()
			*got = r.PostForm
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true, "access_token": "xoxb-installed", "token_type": "bot",
				"scope": "channels:read", "bot_user_id": "U1",
				"team": map[string]any{"id": "T012", "name": "Acme"},
			})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	slackOAuthEndpointOverride = srv.URL // last write wins; slackTestServer's cleanup restores ""
}

// startInstallRedirect POSTs the fresh-install OAuth start and returns the state
// + the full authorize-redirect query (so PKCE params can be asserted).
func startInstallRedirect(t *testing.T, handler http.Handler, env *testenv.Env, id string) url.Values {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/connections/slack/oauth/start", strings.NewReader(url.Values{
		"id": {id}, "display_name": {"Acme"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c := env.SessionCookie(); c != nil {
		req.AddCookie(c)
	}
	if tok := env.CSRFToken(); tok != "" {
		req.Header.Set("X-CSRF-Token", tok)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("install start: want 302, got %d (%s)", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	return loc.Query()
}

func callback(t *testing.T, handler http.Handler, cookie *http.Cookie, code, state string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code="+code+"&state="+state, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestSlackOAuthPublicClientUsesPKCE proves that with NO client_secret (Sieve's
// shipped public app), the install sends a PKCE challenge on the authorize
// redirect and a code_verifier — and NEVER a client_secret — at token exchange.
func TestSlackOAuthPublicClientUsesPKCE(t *testing.T) {
	handler, _, env := slackTestServer(t)
	t.Setenv("SLACK_CLIENT_SECRET", "") // public client: id only

	var tokenForm url.Values
	capturingTokenServer(t, &tokenForm)

	q := startInstallRedirect(t, handler, env, "pub-conn")
	if q.Get("code_challenge") == "" {
		t.Error("public-client authorize redirect must carry a PKCE code_challenge")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}

	rec := callback(t, handler, env.SessionCookie(), "fake-code", q.Get("state"))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback: want 303, got %d (%s)", rec.Code, rec.Body.String())
	}
	if tokenForm.Get("code_verifier") == "" {
		t.Error("public-client token exchange must send code_verifier")
	}
	if tokenForm.Get("client_secret") != "" {
		t.Error("public-client token exchange must NOT send client_secret (Slack forbids both)")
	}
}

// TestGoogleOAuthConfig_PrefersShippedDesktopClient proves the zero-setup path:
// with GOOGLE_OAUTH_CLIENT_ID set, googleOAuthConfig builds a config from the
// shipped Desktop client (no per-user credentials.json) and the config drives a
// PKCE challenge on the authorize URL.
func TestGoogleOAuthConfig_PrefersShippedDesktopClient(t *testing.T) {
	t.Setenv("GOOGLE_OAUTH_CLIENT_ID", "shipped.apps.googleusercontent.com")
	t.Setenv("GOOGLE_OAUTH_CLIENT_SECRET", "desktop-nonconfidential")

	s := &Server{} // deliberately no googleCredentialsFile
	conf, err := s.googleOAuthConfig(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("shipped-client config must build without a credentials file: %v", err)
	}
	if conf.ClientID != "shipped.apps.googleusercontent.com" {
		t.Errorf("ClientID = %q, want the shipped client", conf.ClientID)
	}
	if conf.ClientSecret != "desktop-nonconfidential" {
		t.Errorf("ClientSecret = %q, want the shipped desktop secret", conf.ClientSecret)
	}
	if len(conf.Scopes) == 0 || conf.Endpoint.AuthURL == "" {
		t.Errorf("config must carry scopes and the Google endpoint")
	}
	u := conf.AuthCodeURL("state", oauth2.S256ChallengeOption(newPKCEVerifier()))
	if !strings.Contains(u, "code_challenge=") || !strings.Contains(u, "code_challenge_method=S256") {
		t.Errorf("authorize URL must carry the PKCE challenge: %s", u)
	}
}

// TestGoogleOAuthConfig_FallsBackToCredentialsFile proves the BYO path still
// works when no shipped client is configured.
func TestGoogleOAuthConfig_FallsBackToCredentialsFile(t *testing.T) {
	t.Setenv("GOOGLE_OAUTH_CLIENT_ID", "")
	t.Setenv("GOOGLE_OAUTH_CLIENT_SECRET", "")

	credsPath := filepath.Join(t.TempDir(), "credentials.json")
	creds := `{"installed":{"client_id":"byo.apps.googleusercontent.com",` +
		`"client_secret":"byo-secret","redirect_uris":["http://localhost"],` +
		`"auth_uri":"https://accounts.google.com/o/oauth2/auth",` +
		`"token_uri":"https://oauth2.googleapis.com/token"}}`
	if err := os.WriteFile(credsPath, []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &Server{googleCredentialsFile: credsPath}
	conf, err := s.googleOAuthConfig(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("BYO credentials-file config must build: %v", err)
	}
	if conf.ClientID != "byo.apps.googleusercontent.com" {
		t.Errorf("ClientID = %q, want the BYO client from the file", conf.ClientID)
	}
}

// TestGoogleOAuthConfig_LaunchValueBeatsEnv proves the launch-configured client
// (SetOAuthClients, i.e. --google-oauth-client-id) takes precedence over the env
// var — so operators can pin the client at startup.
func TestGoogleOAuthConfig_LaunchValueBeatsEnv(t *testing.T) {
	t.Setenv("GOOGLE_OAUTH_CLIENT_ID", "env.apps.googleusercontent.com")
	t.Setenv("GOOGLE_OAUTH_CLIENT_SECRET", "env-secret")

	s := &Server{}
	s.SetOAuthClients(OAuthClientConfig{
		GoogleClientID:     "launch.apps.googleusercontent.com",
		GoogleClientSecret: "launch-secret",
	})
	conf, err := s.googleOAuthConfig(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	if conf.ClientID != "launch.apps.googleusercontent.com" {
		t.Errorf("ClientID = %q, want the launch-configured value (must beat env)", conf.ClientID)
	}
	if conf.ClientSecret != "launch-secret" {
		t.Errorf("ClientSecret = %q, want the launch-configured value", conf.ClientSecret)
	}
}

// TestSlackOAuthCreds_LaunchValueAndPublic proves the launch-configured Slack
// client (SetOAuthClients, i.e. --slack-client-id) beats the env var and that a
// client_id with no secret resolves to public (PKCE) mode.
func TestSlackOAuthCreds_LaunchValueAndPublic(t *testing.T) {
	env := testenv.New(t)
	t.Setenv("SLACK_CLIENT_ID", "env-slack-id")
	t.Setenv("SLACK_CLIENT_SECRET", "")

	s := &Server{connections: env.Connections}
	s.SetOAuthClients(OAuthClientConfig{SlackClientID: "launch-slack-id"}) // no secret

	id, secret, err := s.slackOAuthCreds()
	if err != nil {
		t.Fatal(err)
	}
	if id != "launch-slack-id" {
		t.Errorf("client_id = %q, want the launch-configured value (must beat env)", id)
	}
	if secret != "" {
		t.Errorf("client_secret = %q, want empty (public PKCE client)", secret)
	}
}

// TestGoogleOAuthConfig_UnconfiguredErrors proves a clear error when neither a
// shipped client nor a credentials file is present.
func TestGoogleOAuthConfig_UnconfiguredErrors(t *testing.T) {
	t.Setenv("GOOGLE_OAUTH_CLIENT_ID", "")
	t.Setenv("GOOGLE_OAUTH_CLIENT_SECRET", "")
	s := &Server{}
	if _, err := s.googleOAuthConfig(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatal("expected an error when Google OAuth is unconfigured")
	}
}

// TestSlackOAuthConfidentialUsesSecret proves that with a client_secret present
// (BYO app), the install stays on the confidential flow: no PKCE challenge on
// the redirect, and client_secret (not code_verifier) at token exchange.
func TestSlackOAuthConfidentialUsesSecret(t *testing.T) {
	handler, _, env := slackTestServer(t) // sets SLACK_CLIENT_SECRET=test-client-secret

	var tokenForm url.Values
	capturingTokenServer(t, &tokenForm)

	q := startInstallRedirect(t, handler, env, "conf-conn")
	if q.Get("code_challenge") != "" {
		t.Error("confidential-client redirect must NOT carry a PKCE challenge")
	}

	rec := callback(t, handler, env.SessionCookie(), "fake-code", q.Get("state"))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback: want 303, got %d (%s)", rec.Code, rec.Body.String())
	}
	if tokenForm.Get("client_secret") == "" {
		t.Error("confidential-client token exchange must send client_secret")
	}
	if tokenForm.Get("code_verifier") != "" {
		t.Error("confidential-client token exchange must NOT send code_verifier")
	}
}
