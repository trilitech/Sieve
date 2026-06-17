package web_test

// Regression test: handleConnectionEnable inspects reauth_reason and
// routes a previously-disabled-but-broken connection into
// reauth_required instead of unconditionally back to active.

import (
	"net/http"
	"testing"

	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/web"
)

func newEnableTestServer(t *testing.T) (http.Handler, *testenv.Env) {
	t.Helper()
	env := testenv.New(t).WithOperator("test-pass", "test-op")
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := web.NewServer(
		env.Tokens, env.Connections, env.Policies, env.Roles, env.Registry,
		env.Approval, env.Audit,
		"",
		env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "",
	)
	srv.SetAuth(env.Operator, env.Session)
	t.Cleanup(func() { srv.Close() })
	if err := env.Connections.Add("c", "mock", "C", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}
	return srv.Handler(), env
}

// TestEnable_DisabledWithEmptyReason_GoesActive verifies the common case:
// a connection disabled by an operator (no underlying credential breakage)
// is brought back to status='active' by the Enable action.
func TestEnable_DisabledWithEmptyReason_GoesActive(t *testing.T) {
	handler, env := newEnableTestServer(t)

	if err := env.Connections.SetStatus("c", connections.StatusDisabled); err != nil {
		t.Fatalf("seed disabled: %v", err)
	}

	req, rec := authedPost(t, env, "/connections/c/enable")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	got, _ := env.Connections.Get("c")
	if got.Status != connections.StatusActive {
		t.Fatalf("status after enable: got %q, want active", got.Status)
	}
}

// TestEnable_DisabledWithReauthReason_GoesReauthRequired verifies the
// invariant: a connection disabled while credentials were broken
// (non-empty reauth_reason) is brought into reauth_required, not active,
// so it cannot serve agent traffic with known-bad credentials.
func TestEnable_DisabledWithReauthReason_GoesReauthRequired(t *testing.T) {
	handler, env := newEnableTestServer(t)

	// Seed the "broken then disabled" sequence: reauth_required (with a
	// reason) → disabled (operator action, reason preserved by SetStatus
	// for non-active transitions).
	if err := env.Connections.SetStatusWithReason("c", connections.StatusReauthRequired, "refresh failed: invalid_grant"); err != nil {
		t.Fatalf("seed reauth_required: %v", err)
	}
	if err := env.Connections.SetStatus("c", connections.StatusDisabled); err != nil {
		t.Fatalf("seed disabled: %v", err)
	}

	pre, _ := env.Connections.Get("c")
	if pre.ReauthReason == "" {
		t.Fatal("precondition: reauth_reason should be preserved on disable")
	}

	req, rec := authedPost(t, env, "/connections/c/enable")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	got, _ := env.Connections.Get("c")
	if got.Status != connections.StatusReauthRequired {
		t.Fatalf("status after enable: got %q, want reauth_required (broken-cred route)", got.Status)
	}
	if got.ReauthReason == "" {
		t.Fatalf("reason after enable: got empty, want preserved")
	}
}
