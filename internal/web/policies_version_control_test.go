package web_test

// Regression test for the synthetic "version_control" policy scope that
// groups github + gitlab policies under one sidebar tab. The filter is
// implemented in server.go's handlePolicies; this test pins the
// inclusion rule so a future refactor can't silently drop github/gitlab
// from the group or accidentally widen it to other scopes.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// getPoliciesPage is a thin wrapper around an authenticated GET so the
// test reads as a query-and-assert.
func getPoliciesPage(t *testing.T, handler http.Handler, env *testenv.Env, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if c := env.SessionCookie(); c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestPoliciesPage_VersionControlScope asserts:
//   - ?scope=version_control includes policies tagged github and gitlab.
//   - That synthetic scope does NOT include policies for unrelated
//     connectors (slack, gmail).
//   - The narrower ?scope=github tab shows only github (legacy/empty
//     scopes also show, but explicitly-scoped gitlab policies do not).
func TestPoliciesPage_VersionControlScope(t *testing.T) {
	handler, env := newTestWebServer(t)

	// Seed four policies, three of which carry an explicit scope.
	mustSeedPolicy(t, env, "github-allow", "github")
	mustSeedPolicy(t, env, "gitlab-allow", "gitlab")
	mustSeedPolicy(t, env, "slack-allow", "slack")
	mustSeedPolicy(t, env, "legacy-no-scope", "") // empty scope — shows under all tabs

	t.Run("version_control includes github + gitlab, excludes slack", func(t *testing.T) {
		rec := getPoliciesPage(t, handler, env, "/policies?scope=version_control")
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (body: %s)", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		for _, want := range []string{"github-allow", "gitlab-allow", "legacy-no-scope"} {
			if !strings.Contains(body, want) {
				t.Errorf("version_control scope missing policy %q", want)
			}
		}
		if strings.Contains(body, "slack-allow") {
			t.Errorf("version_control scope incorrectly includes slack policy")
		}
	})

	t.Run("github scope excludes gitlab", func(t *testing.T) {
		rec := getPoliciesPage(t, handler, env, "/policies?scope=github")
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "github-allow") {
			t.Errorf("github scope missing github-allow policy")
		}
		if strings.Contains(body, "gitlab-allow") {
			t.Errorf("github scope incorrectly includes gitlab-allow")
		}
	})

	t.Run("slack scope excludes both vcs policies", func(t *testing.T) {
		rec := getPoliciesPage(t, handler, env, "/policies?scope=slack")
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		body := rec.Body.String()
		for _, unwanted := range []string{"github-allow", "gitlab-allow"} {
			if strings.Contains(body, unwanted) {
				t.Errorf("slack scope incorrectly includes %q", unwanted)
			}
		}
	})
}

// mustSeedPolicy creates a minimal rules-evaluator policy carrying the
// given scope (empty string = unscoped). The rules body is intentionally
// trivial — we're testing the scope filter, not the evaluator.
func mustSeedPolicy(t *testing.T, env *testenv.Env, name, scope string) {
	t.Helper()
	cfg := map[string]any{
		"rules": []any{
			map[string]any{"action": "allow"},
		},
	}
	if scope != "" {
		cfg["scope"] = scope
	}
	if _, err := env.Policies.Create(name, "rules", cfg); err != nil {
		t.Fatalf("seed policy %q: %v", name, err)
	}
}
