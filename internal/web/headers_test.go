package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// a newly-issued bearer token or other one-time credential MUST carry
// cache-prevention headers so an intermediate proxy can't store the
// response and replay the secret to a later requester.

// Expected header set per contracts/admin-auth.md and the spec.
var sensitiveHeaders = map[string]string{
	"Cache-Control": "no-store, no-cache, max-age=0, must-revalidate, private",
	"Pragma":        "no-cache",
	"Expires":       "0",
	"Vary":          "Authorization, Cookie",
}

func newHeadersTestServer(t *testing.T) (*httptest.Server, *testenv.Env) {
	t.Helper()
	env := testenv.New(t).WithOperator("test-pass", "test-op")
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := NewServer(
		env.Tokens, env.Connections, env.Roles,
		env.Registry, env.Approval, env.Audit,
		"", env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "127.0.0.1:0",
	)
	srv.SetAuth(env.Operator, env.Session)
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, env
}

func assertSensitiveHeaders(t *testing.T, h http.Header) {
	t.Helper()
	for k, want := range sensitiveHeaders {
		got := h.Get(k)
		if got != want {
			t.Errorf("%s: got %q, want %q", k, got, want)
		}
	}
}

// TestTokenCreateResponseHeaders proves the token-create endpoint returns
// the documented cache-prevention header set on a successful create.
// Pre-fix noted the response carries the plaintext
// bearer token in the body and zero cache-control hygiene; an upstream
// proxy could store it.
func TestTokenCreateResponseHeaders(t *testing.T) {
	ts, env := newHeadersTestServer(t)
	// Seed a role so we have something to bind to.
	role, err := env.Roles.Create("test-role", nil)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	form.Set("name", "headers-test")
	form.Set("role_id", role.ID)
	req, _ := http.NewRequest("POST", ts.URL+"/tokens/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body := readAll(t, resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	assertSensitiveHeaders(t, resp.Header)
}

// TestAdminMutationPostResponseHeaders confirms that a representative
// mutating admin POST (token creation) returns the same sensitive-header
// set as a GET. The headers come from the shared admin middleware, so
// this test guards the middleware's coverage of write-path responses
// rather than any specific handler's behaviour.
// TestCSPFormActionAllowsOAuthHosts guards the CSP form-action allowlist: a
// modern browser enforces form-action on the REDIRECT target of a form
// submission, so an OAuth-provider host missing here silently blocks the
// install (the redirect to the provider's authorize URL is dropped with no
// error). Every connector whose install POSTs and 302s to a provider host must
// be listed. (Notion regression: api.notion.com was missing → the Notion OAuth
// install dead-ended.)
func TestCSPFormActionAllowsOAuthHosts(t *testing.T) {
	rec := httptest.NewRecorder()
	writeSecurityHeaders(rec)
	csp := rec.Header().Get("Content-Security-Policy")
	i := strings.Index(csp, "form-action")
	if i < 0 {
		t.Fatalf("no form-action directive in CSP: %s", csp)
	}
	formAction := csp[i:]
	for _, host := range []string{
		"'self'",
		"https://accounts.google.com",
		"https://slack.com",
		"https://github.com",
		// Notion's OAuth redirect chain hops api.notion.com -> app.notion.com;
		// both must be allowed or the browser stops at the blocked hop.
		"https://api.notion.com",
		"https://app.notion.com",
	} {
		if !strings.Contains(formAction, host) {
			t.Errorf("form-action missing %q; a form POST that 302s there is blocked by CSP.\nform-action: %s", host, formAction)
		}
	}
}

func TestAdminMutationPostResponseHeaders(t *testing.T) {
	ts, env := newHeadersTestServer(t)
	role, err := env.Roles.Create("conn-test-role", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Use token-create as a representative mutating admin POST.
	form := url.Values{}
	form.Set("name", "mutation-test")
	form.Set("role_id", role.ID)
	req, _ := http.NewRequest("POST", ts.URL+"/tokens/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assertSensitiveHeaders(t, resp.Header)
}
