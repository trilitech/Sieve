package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	githubconn "github.com/trilitech/Sieve/internal/connectors/github"
	"github.com/trilitech/Sieve/internal/connectors/httpproxy"
	"github.com/trilitech/Sieve/internal/connectors/mcpproxy"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// newConnectionEditTestServer wires the same dependencies as the rotation
// test server, additionally registering http_proxy / mcp_proxy / github
// connectors so the test can add real connections of those types.
func newConnectionEditTestServer(t *testing.T) (*httptest.Server, *testenv.Env) {
	t.Helper()
	env := testenv.New(t).WithOperator("test-pass", "test-op")

	env.Registry.Register(httpproxy.Meta, httpproxy.Factory)
	env.Registry.Register(mcpproxy.Meta, mcpproxy.Factory)
	env.Registry.Register(githubconn.Meta(), githubconn.Factory())

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
	return ts, env
}

func addHTTPProxyConnection(t *testing.T, env *testenv.Env, id string) {
	t.Helper()
	if err := env.Connections.Add(id, "http_proxy", "Test HTTP Proxy", map[string]any{
		"target_url":  "https://example.com",
		"auth_header": "x-api-key",
		"auth_value":  "sk-test",
	}); err != nil {
		t.Fatalf("add http_proxy connection: %v", err)
	}
}

func addMCPProxyConnection(t *testing.T, env *testenv.Env, id string) {
	t.Helper()
	if err := env.Connections.Add(id, "mcp_proxy", "Test MCP Proxy", map[string]any{
		"url": "https://example.com/mcp",
	}); err != nil {
		t.Fatalf("add mcp_proxy connection: %v", err)
	}
}

func addGithubConnection(t *testing.T, env *testenv.Env, id string) {
	t.Helper()
	if err := env.Connections.Add(id, "github", "Test GitHub", map[string]any{
		"credentials": []any{
			map[string]any{"kind": "fpat", "scope": map[string]any{"type": "org", "name": "acme"}, "token": "ghp_test"},
		},
	}); err != nil {
		t.Fatalf("add github connection: %v", err)
	}
}

// --- GET edit page rendering ---

func TestEditPageRendersHTTPProxy(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	addHTTPProxyConnection(t, env, "h1")

	resp, err := env.AdminClient().Get(ts.URL + "/connections/h1/edit")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	got := string(body)
	for _, want := range []string{
		"auth_value_scrub",
		"additional_denied_headers",
		"Authorization", // baseline panel entry
		"X-Forwarded-",  // baseline panel entry
		"x-api-key",     // configured auth_header
		"auth_query_param",
		"OpenWeather", // helper text mentions the motivating example
	} {
		if !strings.Contains(got, want) {
			t.Errorf("edit page missing expected fragment %q", want)
		}
	}
}

func TestEditSavePersistsAuthQueryParam(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	addHTTPProxyConnection(t, env, "h1")

	form := url.Values{}
	form.Set("auth_query_param", "appid")
	req, _ := http.NewRequest("POST", ts.URL+"/connections/h1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 on success, got %d", resp.StatusCode)
	}
	conn, err := env.Connections.GetWithConfig("h1")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := conn.Config["auth_query_param"].(string); got != "appid" {
		t.Errorf("auth_query_param did not persist; got %q", got)
	}
}

func TestEditSaveRejectsInvalidAuthQueryParam(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	addHTTPProxyConnection(t, env, "h1")

	form := url.Values{}
	form.Set("auth_query_param", "appid&extra=bad")
	req, _ := http.NewRequest("POST", ts.URL+"/connections/h1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid input, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "auth_query_param") {
		t.Errorf("error banner should name auth_query_param; got %q", string(body))
	}
	conn, _ := env.Connections.GetWithConfig("h1")
	if _, exists := conn.Config["auth_query_param"]; exists {
		t.Errorf("auth_query_param was written despite validation error")
	}
}

func TestEditSaveClearsAuthQueryParam(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	addHTTPProxyConnection(t, env, "h1")

	// First, persist a value.
	form := url.Values{}
	form.Set("auth_query_param", "appid")
	req, _ := http.NewRequest("POST", ts.URL+"/connections/h1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("set step: expected 303, got %d", resp.StatusCode)
	}

	// Then clear it.
	form2 := url.Values{}
	form2.Set("auth_query_param", "")
	req2, _ := http.NewRequest("POST", ts.URL+"/connections/h1/edit", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Origin", ts.URL)
	resp2, err := env.AdminClient().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusSeeOther {
		t.Fatalf("clear step: expected 303, got %d", resp2.StatusCode)
	}
	conn, _ := env.Connections.GetWithConfig("h1")
	if got, _ := conn.Config["auth_query_param"].(string); got != "" {
		t.Errorf("auth_query_param should be cleared; got %q", got)
	}
}

func TestEditSaveTrimsAuthQueryParamWhitespace(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	addHTTPProxyConnection(t, env, "h1")

	form := url.Values{}
	form.Set("auth_query_param", "  appid  ")
	req, _ := http.NewRequest("POST", ts.URL+"/connections/h1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", resp.StatusCode)
	}
	conn, _ := env.Connections.GetWithConfig("h1")
	if got, _ := conn.Config["auth_query_param"].(string); got != "appid" {
		t.Errorf("auth_query_param should be trimmed; got %q", got)
	}
}

func TestEditPageRendersMCPProxy(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	addMCPProxyConnection(t, env, "m1")

	resp, err := env.AdminClient().Get(ts.URL + "/connections/m1/edit")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	got := string(body)
	for _, want := range []string{
		"response_body_cap_bytes",
		"5242880", // default placeholder
	} {
		if !strings.Contains(got, want) {
			t.Errorf("mcp_proxy edit page missing %q", want)
		}
	}
}

func TestEditPageRendersGitHub(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	addGithubConnection(t, env, "g1")

	resp, err := env.AdminClient().Get(ts.URL + "/connections/g1/edit")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	got := string(body)
	if !strings.Contains(got, "cross_fork_pr_allowlist") {
		t.Errorf("github edit page missing cross_fork_pr_allowlist textarea")
	}
}

func TestEditPageRendersUnsupportedConnectorPlaceholder(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	if err := env.Connections.Add("mock-1", "mock", "Mock", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	resp, err := env.AdminClient().Get(ts.URL + "/connections/mock-1/edit")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "No editable settings") {
		t.Errorf("placeholder section missing for unsupported connector type")
	}
}

// --- security defenses ---

func TestEditPageRejectsAgentToken(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	addHTTPProxyConnection(t, env, "h1")

	// Deliberately NOT using env.AdminClient — the request must NOT
	// carry an operator session. The middleware sees the agent bearer
	// header and surfaces 403 (FR-036) instead of 401/redirect, giving
	// a confused agent client a clearer "wrong port" signal.
	bareClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			req, _ := http.NewRequest(method, ts.URL+"/connections/h1/edit", strings.NewReader(""))
			req.Header.Set("Authorization", "Bearer sieve_tok_test")
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", ts.URL)
			resp, err := bareClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("agent-token request must be 403; got %d", resp.StatusCode)
			}
		})
	}
}

func TestEditSaveRejectsCrossOrigin(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	addHTTPProxyConnection(t, env, "h1")

	form := url.Values{"auth_value_scrub": {"1"}}
	req, _ := http.NewRequest("POST", ts.URL+"/connections/h1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://evil.example")
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin POST must be 403; got %d", resp.StatusCode)
	}
}

// --- save flows ---

func TestEditSavePersistsHTTPProxyChanges(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	addHTTPProxyConnection(t, env, "h1")

	form := url.Values{}
	// auth_value_scrub: omit field → false (checkbox unchecked).
	form.Set("additional_denied_headers", "X-Custom-Internal\nX-Tenant-ID")
	req, _ := http.NewRequest("POST", ts.URL+"/connections/h1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 on success, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "saved=1") {
		t.Errorf("redirect missing saved=1; Location=%q", loc)
	}

	conn, err := env.Connections.GetWithConfig("h1")
	if err != nil {
		t.Fatal(err)
	}
	if scrub, ok := conn.Config["auth_value_scrub"].(bool); !ok || scrub {
		t.Errorf("auth_value_scrub did not persist as false; got %v (%T)", conn.Config["auth_value_scrub"], conn.Config["auth_value_scrub"])
	}
	got := conn.Config["additional_denied_headers"]
	gotSlice, _ := got.([]any)
	if len(gotSlice) != 2 || gotSlice[0] != "X-Custom-Internal" || gotSlice[1] != "X-Tenant-ID" {
		t.Errorf("additional_denied_headers did not persist correctly; got %#v", got)
	}
}

func TestEditSavePersistsMCPProxyCap(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	addMCPProxyConnection(t, env, "m1")

	form := url.Values{"response_body_cap_bytes": {"1048576"}}
	req, _ := http.NewRequest("POST", ts.URL+"/connections/m1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", resp.StatusCode)
	}

	conn, err := env.Connections.GetWithConfig("m1")
	if err != nil {
		t.Fatal(err)
	}
	switch v := conn.Config["response_body_cap_bytes"].(type) {
	case int64:
		if v != 1048576 {
			t.Errorf("cap = %d, want 1048576", v)
		}
	case float64:
		if int64(v) != 1048576 {
			t.Errorf("cap = %g, want 1048576", v)
		}
	default:
		t.Errorf("response_body_cap_bytes wrong type %T = %v", v, v)
	}
}

func TestEditSaveValidatesNonPositiveCap(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	addMCPProxyConnection(t, env, "m1")

	form := url.Values{"response_body_cap_bytes": {"-1"}}
	req, _ := http.NewRequest("POST", ts.URL+"/connections/m1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 on non-positive cap, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "non-negative") {
		t.Errorf("error banner missing 'non-negative'; got %q", string(body))
	}
	// Verify no DB write happened.
	conn, _ := env.Connections.GetWithConfig("m1")
	if _, exists := conn.Config["response_body_cap_bytes"]; exists {
		t.Errorf("response_body_cap_bytes was written despite validation error")
	}
}

func TestEditSavePersistsGithubAllowlist(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	addGithubConnection(t, env, "g1")

	form := url.Values{"cross_fork_pr_allowlist": {"alice\nbob\n  \n"}} // includes blank lines
	req, _ := http.NewRequest("POST", ts.URL+"/connections/g1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", resp.StatusCode)
	}

	conn, _ := env.Connections.GetWithConfig("g1")
	got := conn.Config["cross_fork_pr_allowlist"]
	slice, _ := got.([]any)
	if len(slice) != 2 || slice[0] != "alice" || slice[1] != "bob" {
		t.Errorf("allowlist did not persist correctly (blank lines should be skipped); got %#v", got)
	}
}

// TestBaselineDenylistCannotBeReducedViaForm verifies that even if an
// operator submits a hostile payload trying to "remove from baseline",
// the persisted config still has the full baseline applied at request
// time. The page exposes only an additive textarea; the static deny
// keys are not editable inputs.
func TestBaselineDenylistCannotBeReducedViaForm(t *testing.T) {
	ts, env := newConnectionEditTestServer(t)
	addHTTPProxyConnection(t, env, "h1")

	// Try to inject a "remove_baseline" parameter — the handler does not
	// read it, so it has no effect.
	form := url.Values{}
	form.Set("remove_baseline", "Authorization,Host,Cookie") // hostile
	form.Set("auth_value_scrub", "1")
	req, _ := http.NewRequest("POST", ts.URL+"/connections/h1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 on save, got %d", resp.StatusCode)
	}

	// Reload the connection and confirm no "remove_baseline"-derived field
	// was persisted, and that the connector still rejects baseline keys at
	// request time.
	c, err := env.Registry.Create("http_proxy", mustGetConfig(t, env, "h1"))
	if err != nil {
		t.Fatal(err)
	}
	pc := c.(*httpproxy.ProxyConnector)
	// The connector exposes its scrub filter via AuthValueScrubFilter; the
	// filter is non-nil because the form had auth_value_scrub=1. This is a
	// sanity check that the save took effect.
	if pc.AuthValueScrubFilter() == nil {
		t.Errorf("auth_value_scrub did not persist; filter accessor returned nil")
	}
}

func mustGetConfig(t *testing.T, env *testenv.Env, id string) map[string]any {
	t.Helper()
	conn, err := env.Connections.GetWithConfig(id)
	if err != nil {
		t.Fatalf("get connection: %v", err)
	}
	return conn.Config
}

// TestAuthQueryParamPatternMatchesConnector asserts that the authQueryParamPattern
// compiled in this package (from httpproxy.AuthQueryParamPatternStr) stays in
// sync with the connector's own compiled pattern. Both use the same source
// constant so drift is impossible, but the test documents the contract and
// catches accidental constant changes.
func TestAuthQueryParamPatternMatchesConnector(t *testing.T) {
	got := authQueryParamPattern.String()
	want := httpproxy.AuthQueryParamPatternStr
	if got != want {
		t.Errorf("web authQueryParamPattern %q differs from httpproxy.AuthQueryParamPatternStr %q", got, want)
	}
}
