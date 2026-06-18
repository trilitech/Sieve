package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/csrf"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/session"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// login/logout/setup HTTP handlers + the requireOperatorSession
// middleware. This file exercises the auth flow in isolation —
// the next commit wraps every admin endpoint with the middleware
// and updates every existing test to seed an operator + attach
// the session cookie.

func newAuthTestServer(t *testing.T) (*httptest.Server, *testenv.Env, *Server) {
	t.Helper()
	env := testenv.New(t)
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := NewServer(
		env.Tokens, env.Connections, env.Policies, env.Roles,
		env.Registry, env.Approval, env.Audit,
		"", env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "127.0.0.1:0",
	)
	srv.SetAuth(env.Operator, env.Session)
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, env, srv
}

// noRedirectClient returns an *http.Client that surfaces 3xx
// responses to the caller instead of following them. The auth
// handlers redirect on success/failure; tests assert on the 303.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// TestSetup_FirstRunPath — fresh install, no credential. GET /setup
// renders the setup form. POST /setup with matching credentials
// creates the credential, auto-logs the operator in, and redirects
// to /. Subsequent GET /setup returns 404.
func TestSetup_FirstRunPath(t *testing.T) {
	ts, _, _ := newAuthTestServer(t)
	resp, err := http.Get(ts.URL + "/setup")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /setup: status=%d", resp.StatusCode)
	}
	body := readAll(t, resp.Body)
	resp.Body.Close()
	if !strings.Contains(body, "display name") {
		t.Errorf("setup page missing expected text: %s", body)
	}

	form := url.Values{}
	form.Set("display_name", "alice-laptop")
	form.Set("credential", "secret123")
	form.Set("confirm_credential", "secret123")
	resp, err = noRedirectClient().PostForm(ts.URL+"/setup", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body := readAll(t, resp.Body)
		t.Fatalf("POST /setup status=%d body=%s", resp.StatusCode, body)
	}
	// Auto-login: response sets the session cookie.
	cookies := resp.Cookies()
	var sessCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == session.CookieName {
			sessCookie = c
			break
		}
	}
	if sessCookie == nil {
		t.Fatal("POST /setup did not set the session cookie")
	}
	if !sessCookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	// GET /setup is now 404.
	resp2, _ := http.Get(ts.URL + "/setup")
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("post-setup GET /setup status=%d, want 404", resp2.StatusCode)
	}
	resp2.Body.Close()
}

func TestSetup_RejectsMismatchedConfirmation(t *testing.T) {
	ts, _, _ := newAuthTestServer(t)
	form := url.Values{}
	form.Set("display_name", "alice")
	form.Set("credential", "secret")
	form.Set("confirm_credential", "DIFFERENT")
	resp, err := noRedirectClient().PostForm(ts.URL+"/setup", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200 (re-render with error)", resp.StatusCode)
	}
	body := readAll(t, resp.Body)
	if !strings.Contains(body, "do not match") {
		t.Errorf("error message missing: %s", body)
	}
}

func TestLogin_HappyPath(t *testing.T) {
	ts, env, _ := newAuthTestServer(t)
	env.WithOperator("real-password", "alice")

	form := url.Values{}
	form.Set("credential", "real-password")
	resp, err := noRedirectClient().PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body := readAll(t, resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	// Session cookie + sieve_csrf cookie set; redirect to /.
	var sessionCookie, csrfCookie *http.Cookie
	for _, c := range resp.Cookies() {
		switch c.Name {
		case session.CookieName:
			sessionCookie = c
		case session.CSRFCookieName:
			csrfCookie = c
		}
	}
	if sessionCookie == nil {
		t.Error("login did not set session cookie")
	}
	if csrfCookie == nil {
		t.Error("login did not set sieve_csrf cookie")
	} else {
		if csrfCookie.HttpOnly {
			t.Error("sieve_csrf cookie must be non-HttpOnly (page script needs to read it)")
		}
		if csrfCookie.Value == "" {
			t.Error("sieve_csrf cookie value must not be empty after a successful login")
		}
	}
	if resp.Header.Get("Location") != "/" {
		t.Errorf("Location = %q, want /", resp.Header.Get("Location"))
	}
}

func TestLogin_WrongCredential(t *testing.T) {
	ts, env, _ := newAuthTestServer(t)
	env.WithOperator("right", "alice")

	form := url.Values{}
	form.Set("credential", "wrong")
	resp, err := noRedirectClient().PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == session.CookieName {
			t.Error("failed login must NOT set session cookie")
		}
		if c.Name == session.CSRFCookieName {
			t.Error("failed login must NOT set sieve_csrf cookie")
		}
	}
}

func TestLogin_NoCredentialConfiguredRedirectsToSetup(t *testing.T) {
	ts, _, _ := newAuthTestServer(t)
	resp, err := noRedirectClient().Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status=%d, want 303 (redirect to /setup)", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "/setup" {
		t.Errorf("Location = %q", resp.Header.Get("Location"))
	}
}

func TestLogout_DeletesCookieAndSession(t *testing.T) {
	ts, env, _ := newAuthTestServer(t)
	env.WithOperator("pw", "alice")
	cookie := env.SessionCookie()

	form := url.Values{}
	req, _ := http.NewRequest("POST", ts.URL+"/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("logout status=%d", resp.StatusCode)
	}
	// Lookup on the old cookie should fail.
	if _, err := env.Session.Lookup(cookie.Value); err == nil {
		t.Error("logout did not delete the session row")
	}
	// Both the session cookie and the sieve_csrf cookie should carry
	// a deletion directive (MaxAge<0 / empty value) so the browser
	// drops them. Without clearing sieve_csrf, a subsequent login
	// would race against the stale cookie still being sent up.
	var sessionCleared, csrfCleared bool
	for _, c := range resp.Cookies() {
		switch c.Name {
		case session.CookieName:
			if c.MaxAge < 0 || c.Value == "" {
				sessionCleared = true
			}
		case session.CSRFCookieName:
			if c.MaxAge < 0 || c.Value == "" {
				csrfCleared = true
			}
		}
	}
	if !sessionCleared {
		t.Error("logout did not clear the session cookie")
	}
	if !csrfCleared {
		t.Error("logout did not clear the sieve_csrf cookie")
	}
}

// --- Middleware tests ---

// testProtectedHandler wraps a trivial 204 with requireOperatorSession
// so we can drive the middleware directly without needing an existing
// admin endpoint.
func testProtectedHandler(srv *Server) http.Handler {
	return srv.requireOperatorSession(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(204)
		},
	))
}

func TestMiddleware_RedirectsGETWithoutCookieToLogin(t *testing.T) {
	_, env, srv := newAuthTestServer(t)
	env.WithOperator("p", "a")

	h := testProtectedHandler(srv)
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := noRedirectClient().Get(ts.URL + "/anywhere")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status=%d, want 303 redirect", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "/login" {
		t.Errorf("Location = %q, want /login", resp.Header.Get("Location"))
	}
}

func TestMiddleware_Returns401POSTWithoutCookie(t *testing.T) {
	_, env, srv := newAuthTestServer(t)
	env.WithOperator("p", "a")

	h := testProtectedHandler(srv)
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/anywhere", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401", resp.StatusCode)
	}
}

func TestMiddleware_AllowsValidSessionOnGET(t *testing.T) {
	_, env, srv := newAuthTestServer(t)
	env.WithOperator("p", "a")

	h := testProtectedHandler(srv)
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/anywhere", nil)
	req.AddCookie(env.SessionCookie())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Errorf("status=%d, want 204", resp.StatusCode)
	}
}

func TestMiddleware_POSTRequiresCSRFToken(t *testing.T) {
	_, env, srv := newAuthTestServer(t)
	env.WithOperator("p", "a")

	h := testProtectedHandler(srv)
	ts := httptest.NewServer(h)
	defer ts.Close()

	// POST with cookie but NO csrf token → 403.
	req, _ := http.NewRequest("POST", ts.URL+"/anywhere", nil)
	req.AddCookie(env.SessionCookie())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status=%d, want 403 (CSRF missing)", resp.StatusCode)
	}

	// POST with cookie + correct CSRF in header → 204.
	req, _ = http.NewRequest("POST", ts.URL+"/anywhere", nil)
	req.AddCookie(env.SessionCookie())
	req.Header.Set(csrf.HeaderName, env.CSRFToken())
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Errorf("status=%d, want 204 (valid CSRF)", resp.StatusCode)
	}
}

func TestMiddleware_RedirectsToSetupWhenNoCredential(t *testing.T) {
	_, _, srv := newAuthTestServer(t)
	// Deliberately NOT calling WithOperator — no credential exists.

	h := testProtectedHandler(srv)
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := noRedirectClient().Get(ts.URL + "/anywhere")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status=%d, want 303", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "/setup" {
		t.Errorf("Location = %q, want /setup", resp.Header.Get("Location"))
	}
}

func TestMiddleware_500WhenAuthNotWired(t *testing.T) {
	// Server constructed without SetAuth — middleware MUST refuse
	// to serve admin routes per. This replaces the earlier
	// transitional pass-through.
	env := testenv.New(t)
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := NewServer(
		env.Tokens, env.Connections, env.Policies, env.Roles,
		env.Registry, env.Approval, env.Audit,
		"", env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "127.0.0.1:0",
	)
	t.Cleanup(srv.Close)
	// SetAuth NOT called.

	h := testProtectedHandler(srv)
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/anywhere")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Errorf("status=%d, want 500 (auth not configured)", resp.StatusCode)
	}
}
