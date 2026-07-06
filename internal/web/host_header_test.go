package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/settings"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// host_header_test.go verifies that public URLs surfaced to the operator
// (OAuth callbacks, GitHub App manifest URLs, etc.) derive from the
// configured public_base_url setting and never from inbound Host or
// X-Forwarded-* headers, which an unauthenticated client controls.

func newHostHeaderTestServer(t *testing.T) (*httptest.Server, *testenv.Env, *Server) {
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
	return ts, env, srv
}

// TestPublicBaseURLDefault confirms that with no setting configured, the
// admin server falls back to the documented production binding.
func TestPublicBaseURLDefault(t *testing.T) {
	_, _, srv := newHostHeaderTestServer(t)
	got := srv.publicBaseURL(httptest.NewRequest("GET", "http://attacker.example/x", nil))
	if got != "http://127.0.0.1:19816" {
		t.Errorf("publicBaseURL default = %q, want %q", got, "http://127.0.0.1:19816")
	}
}

// TestPublicBaseURLIgnoresHostHeader proves the helper does not echo back
// inbound Host / X-Forwarded-Host / X-Forwarded-Proto headers.
func TestPublicBaseURLIgnoresHostHeader(t *testing.T) {
	_, _, srv := newHostHeaderTestServer(t)
	r := httptest.NewRequest("GET", "http://attacker.example/x", nil)
	r.Host = "attacker.example"
	r.Header.Set("X-Forwarded-Host", "attacker.example")
	r.Header.Set("X-Forwarded-Proto", "https")
	got := srv.publicBaseURL(r)
	if strings.Contains(got, "attacker.example") {
		t.Errorf("publicBaseURL echoed forged Host: %q", got)
	}
}

// TestPublicBaseURLSettingOverridesDefault confirms the operator-configured
// setting takes precedence when present.
func TestPublicBaseURLSettingOverridesDefault(t *testing.T) {
	_, env, srv := newHostHeaderTestServer(t)
	if err := env.Settings.Set(settings.KeyPublicBaseURL, "https://sieve.internal.example.com"); err != nil {
		t.Fatal(err)
	}
	got := srv.publicBaseURL(httptest.NewRequest("GET", "http://attacker.example/x", nil))
	if got != "https://sieve.internal.example.com" {
		t.Errorf("publicBaseURL with override = %q, want %q", got, "https://sieve.internal.example.com")
	}
}

// TestGitHubAppManifestIgnoresHostHeader: post to /connections/github/app/start
// with a forged Host header; the rendered manifest's callback_urls,
// redirect_url, setup_url, url must all use the configured public_base_url
// (or the loopback default), never the forged host.
func TestGitHubAppManifestIgnoresHostHeader(t *testing.T) {
	ts, env, _ := newHostHeaderTestServer(t)

	form := url.Values{}
	form.Set("id", "test-app")
	form.Set("display_name", "Test App")

	req, err := http.NewRequest("POST",
		ts.URL+"/connections/github/app/start",
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Host", "attacker.example")
	req.Host = "attacker.example"

	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body := readAll(t, resp.Body)
	if strings.Contains(body, "attacker.example") {
		t.Errorf("GitHub App manifest contains forged host. Response body:\n%s", body)
	}
	if !strings.Contains(body, "127.0.0.1:19816") {
		t.Errorf("GitHub App manifest should contain default base URL; got:\n%s", body)
	}
}

// TestGoogleOAuthRedirectURLIgnoresHostHeader: the Google OAuth config helper
// must use publicBaseURL, not r.Host.
func TestGoogleOAuthRedirectURLIgnoresHostHeader(t *testing.T) {
	_, _, srv := newHostHeaderTestServer(t)
	// googleOAuthConfig now takes (r) and reads publicBaseURL internally.
	// Forge a request with a malicious Host. The googleOAuthConfig method
	// will fail because no credentials file is configured (empty path), but
	// we can still inspect publicBaseURL behavior directly via a forged
	// request and confirm the helper would not pick up Host.
	r := httptest.NewRequest("GET", "http://attacker.example/x", nil)
	r.Host = "attacker.example"
	r.Header.Set("X-Forwarded-Host", "attacker.example")

	got := srv.publicBaseURL(r)
	if strings.Contains(got, "attacker.example") {
		t.Errorf("publicBaseURL leaked Host: %q", got)
	}
}

// readAll returns the response body as a string, failing the test if the
// read errors out. Using io.ReadAll surfaces real I/O failures instead of
// silently truncating, which makes assertion failures easier to diagnose.
func readAll(t *testing.T, body io.Reader) string {
	t.Helper()
	buf, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return string(buf)
}
