package web_test

// Tests for the /connections/{id}/disable and /connections/{id}/enable
// endpoints (status surfacing) and the rejectIfAgentToken protection.
//
// External package so we don't touch the private Server type beyond the
// public NewServer + Handler() surfaces an admin would actually use.

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
	env := testenv.New(t)
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := web.NewServer(
		env.Tokens, env.Connections, env.Policies, env.Roles, env.Registry,
		env.Approval, env.Audit,
		"", // no Google credentials file in tests
		env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "",
	)
	t.Cleanup(func() { srv.Close() })
	return srv.Handler(), env
}

// TestServer_DisableConnection_RejectsAgentToken verifies that an agent
// bearer token cannot disable a connection through the admin UI.
// rejectIfAgentToken inspects the Authorization header and returns 403
// before any state mutation.
func TestServer_DisableConnection_RejectsAgentToken(t *testing.T) {
	handler, env := newTestWebServer(t)

	if err := env.Connections.Add("c1", "mock", "C1", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}

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
// the enable endpoint. The mistake of forgetting rejectIfAgentToken on
// one of the two handlers is the kind of regression the constitution's
// Principle I is designed to catch.
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

	// Disable.
	req := httptest.NewRequest(http.MethodPost, "/connections/c3/disable", nil)
	rec := httptest.NewRecorder()
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
	req = httptest.NewRequest(http.MethodPost, "/connections/c3/enable", nil)
	rec = httptest.NewRecorder()
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
