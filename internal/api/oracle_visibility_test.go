package api_test

// Regression tests for the connection-existence/status oracle: the REST API
// must not let an unauthorized token distinguish a missing connection from an
// existing one, nor observe its status (needs_reauth) or type. The IAM Decide
// is the sole gate and runs before anything connection-specific is revealed;
// every unauthorized-or-missing outcome returns the identical response.

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// TestExecuteOperation_NoExistenceOracle: for a token with no grant on the
// target, a missing id, an existing-ungranted connection in needs_reauth, and
// an existing-ungranted active connection all return the IDENTICAL response —
// so the response can't be used to probe existence or status.
func TestExecuteOperation_NoExistenceOracle(t *testing.T) {
	env := testenv.New(t)
	// Token granted read-only on test-conn ONLY.
	role := env.SetupConnectionAndRole(t, "test-conn", "read-only")
	tok := env.CreateToken(t, role.ID)
	// A second connection the token has NO grant for.
	if err := env.Connections.Add("other-conn", "mock", "Other", map[string]any{}); err != nil {
		t.Fatalf("add other-conn: %v", err)
	}
	srv := httptest.NewServer(api.NewRouter(
		env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit,
	).Handler())
	t.Cleanup(srv.Close)

	get := func(connID string) (int, string) {
		resp := doRequest(t, "POST", srv.URL+"/api/v1/connections/"+connID+"/ops/list_emails", tok, "{}")
		return resp.StatusCode, readBody(t, resp)
	}

	// (i) missing/guessed id.
	missStatus, missBody := get("ghost-conn")
	// (ii) existing, ungranted, in needs_reauth.
	if err := env.Connections.SetStatus("other-conn", connections.StatusReauthRequired); err != nil {
		t.Fatalf("set reauth: %v", err)
	}
	reauthStatus, reauthBody := get("other-conn")
	// (iii) existing, ungranted, active.
	if err := env.Connections.SetStatus("other-conn", connections.StatusActive); err != nil {
		t.Fatalf("set active: %v", err)
	}
	activeStatus, activeBody := get("other-conn")

	if missStatus != reauthStatus || missStatus != activeStatus {
		t.Fatalf("status is an oracle: missing=%d reauth-ungranted=%d active-ungranted=%d",
			missStatus, reauthStatus, activeStatus)
	}
	if missBody != reauthBody || missBody != activeBody {
		t.Fatalf("body is an oracle:\n missing=%q\n reauth-ungranted=%q\n active-ungranted=%q",
			missBody, reauthBody, activeBody)
	}
	// ...and it's the uniform not-authorized response.
	if missStatus != 403 {
		t.Fatalf("expected 403, got %d (body %s)", missStatus, missBody)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(missBody), &got); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, missBody)
	}
	if got["error"] != "policy denied" {
		t.Fatalf("expected uniform error=\"policy denied\", got %q", got["error"])
	}
}

// TestExecuteOperation_AuthorizedStillSeesReauth: the fix preserves the reauth
// fast-path for an AUTHORIZED caller — a token granted on a connection in
// needs_reauth gets the structured reauth_required envelope, not the uniform
// deny (status is revealed only after an authorizing decision).
func TestExecuteOperation_AuthorizedStillSeesReauth(t *testing.T) {
	env := testenv.New(t)
	role := env.SetupConnectionAndRole(t, "test-conn", "read-only")
	tok := env.CreateToken(t, role.ID)
	if err := env.Connections.SetStatus("test-conn", connections.StatusReauthRequired); err != nil {
		t.Fatalf("set reauth: %v", err)
	}
	srv := httptest.NewServer(api.NewRouter(
		env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit,
	).Handler())
	t.Cleanup(srv.Close)

	resp := doRequest(t, "POST", srv.URL+"/api/v1/connections/test-conn/ops/list_emails", tok, "{}")
	body := readBody(t, resp)
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d (%s)", resp.StatusCode, body)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, body)
	}
	if got["error"] != "reauth_required" {
		t.Fatalf("authorized caller should see reauth_required, got %q (%s)", got["error"], body)
	}
}
