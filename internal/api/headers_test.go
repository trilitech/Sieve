package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// Spec 001-fix-security-vulns US11 / FR-045: every agent-API response
// MUST carry the documented cache-prevention header set so an
// intermediate proxy cannot store agent-visible entity data and serve
// it back to a different (or invalid) bearer token.

func TestAgentAPIResponseHeaders(t *testing.T) {
	env := testenv.New(t)
	auditLog := audit.NewLogger(env.DB)
	rt := NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, auditLog)
	ts := httptest.NewServer(rt.Handler())
	defer ts.Close()

	// An unauthenticated GET returns 401 — that's fine, we're testing
	// that the response headers are set regardless of auth outcome.
	resp, err := http.Get(ts.URL + "/api/v1/connections")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	for k, want := range map[string]string{
		"Cache-Control": "no-store, no-cache, max-age=0, must-revalidate, private",
		"Pragma":        "no-cache",
		"Expires":       "0",
		"Vary":          "Authorization",
	} {
		got := resp.Header.Get(k)
		if got != want {
			t.Errorf("%s: got %q, want %q", k, got, want)
		}
	}
}
