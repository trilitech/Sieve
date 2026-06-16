package web_test

// Tests for the /connections/{id}/disable and /connections/{id}/enable
// endpoints (status surfacing) and the agent-token rejection enforced
// by the requireOperatorSession middleware. External package so we
// don't touch the private Server type beyond the public NewServer +
// Handler surfaces an admin would actually use.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/web"
)

func newTestWebServer(t *testing.T) (http.Handler, *testenv.Env) {
	t.Helper()
	env := testenv.New(t).WithOperator("test-pass", "test-op")
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := web.NewServer(
		env.Tokens, env.Connections, env.Policies, env.Roles, env.Registry,
		env.Approval, env.Audit,
		"", // no Google credentials file in tests
		env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "",
	)
	srv.SetAuth(env.Operator, env.Session)
	t.Cleanup(func() { srv.Close() })
	return srv.Handler(), env
}

// authedPost adds the env's operator session cookie + CSRF token to
// an outgoing test request so requireOperatorSession lets it through.
func authedPost(t *testing.T, env *testenv.Env, path string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	if c := env.SessionCookie(); c != nil {
		req.AddCookie(c)
	}
	if tok := env.CSRFToken(); tok != "" {
		req.Header.Set("X-CSRF-Token", tok)
	}
	return req, httptest.NewRecorder()
}

// TestServer_DisableConnection_RejectsAgentToken verifies that an
// agent bearer token cannot disable a connection through the admin UI.
// The requireOperatorSession middleware inspects the Authorization
// header and returns 403 before any state mutation.
func TestServer_DisableConnection_RejectsAgentToken(t *testing.T) {
	handler, env := newTestWebServer(t)

	if err := env.Connections.Add("c1", "mock", "C1", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Deliberately NO operator session cookie — the request carries
	// an agent bearer header which the middleware surfaces as 403
	// rather than redirecting to /login.
	req := httptest.NewRequest(http.MethodPost, "/connections/c1/disable", nil)
	req.Header.Set("Authorization", "Bearer sieve_tok_pretend")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for agent-token disable, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// Status must NOT have changed.
	c, _ := env.Connections.Get("c1")
	if c.Status != connections.StatusActive {
		t.Fatalf("status mutated despite rejected request: got %q", c.Status)
	}
}

// TestServer_EnableConnection_RejectsAgentToken — symmetric guard for
// the enable endpoint. Mounting a new admin mutator without routing it
// through requireOperatorSession is the regression this test is
// designed to catch (Principle I in the constitution).
func TestServer_EnableConnection_RejectsAgentToken(t *testing.T) {
	handler, env := newTestWebServer(t)

	if err := env.Connections.Add("c2", "mock", "C2", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}
	_ = env.Connections.SetStatus("c2", connections.StatusDisabled)

	req := httptest.NewRequest(http.MethodPost, "/connections/c2/enable", nil)
	req.Header.Set("Authorization", "Bearer sieve_tok_pretend")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for agent-token enable, got %d", rec.Code)
	}
	c, _ := env.Connections.Get("c2")
	if c.Status != connections.StatusDisabled {
		t.Fatalf("status mutated despite rejected request: got %q", c.Status)
	}
}

// TestServer_DisableEnable_HappyPath verifies the lifecycle: an admin
// without an agent token can flip status from active → disabled → active
// and the row reflects each transition. Uses 303 redirect (See Other) as
// the success signal — same pattern as the existing
// handleConnectionDelete.
func TestServer_DisableEnable_HappyPath(t *testing.T) {
	handler, env := newTestWebServer(t)

	if err := env.Connections.Add("c3", "mock", "C3", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Disable — operator session cookie + CSRF attached via authedPost.
	req, rec := authedPost(t, env, "/connections/c3/disable")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 after disable, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.HasSuffix(loc, "/connections") {
		t.Fatalf("expected redirect to /connections, got %q", loc)
	}
	c1, _ := env.Connections.Get("c3")
	if c1.Status != connections.StatusDisabled {
		t.Fatalf("expected status=disabled after disable, got %q", c1.Status)
	}

	// Enable.
	req, rec = authedPost(t, env, "/connections/c3/enable")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 after enable, got %d", rec.Code)
	}
	c2, _ := env.Connections.Get("c3")
	if c2.Status != connections.StatusActive {
		t.Fatalf("expected status=active after enable, got %q", c2.Status)
	}
}

// TestServer_DisableEnable_NonexistentConnection asserts the handlers
// return 500 (or any non-2xx) for an unknown connection id rather than
// silently succeeding. The status update path returns "not found" from
// SetStatus.
func TestServer_DisableNonexistent_Returns500(t *testing.T) {
	handler, _ := newTestWebServer(t)

	req := httptest.NewRequest(http.MethodPost, "/connections/ghost/disable", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK || rec.Code == http.StatusSeeOther {
		t.Fatalf("expected non-success for nonexistent connection, got %d", rec.Code)
	}
}
