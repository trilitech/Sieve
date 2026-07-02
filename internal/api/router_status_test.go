package api_test

// Tests for sentinel mapping in the REST API.
// When connections.GetConnector returns ErrReauthRequired or
// ErrConnectionDisabled, the router translates the sentinel into a
// structured 403 response: {"error": "<code>", "message": "..."}.
// Agents key off the stable error code, not the message text.

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// setupForStatus mirrors `setup` in router_test.go but returns the env
// and connection id so tests can mutate connection status mid-flight.
func setupForStatus(t *testing.T) (serverURL, token, connID string, env *testenv.Env) {
	t.Helper()
	env = testenv.New(t)
	role := env.SetupConnectionAndRole(t, "test-conn", "read-only")
	tok := env.CreateToken(t, role.ID)

	router := api.NewRouter(
		env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit,
	)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	return srv.URL, tok, "test-conn", env
}

// TestRouter_ReauthRequired_Returns403 verifies the API sentinel mapping
// for ErrReauthRequired: response is HTTP 403 with body
// {"error":"reauth_required","message":...}. Agents key off the stable
// error code without parsing the message.
func TestRouter_ReauthRequired_Returns403(t *testing.T) {
	url, tok, connID, env := setupForStatus(t)

	if err := env.Connections.SetStatus(connID, connections.StatusReauthRequired); err != nil {
		t.Fatalf("set status: %v", err)
	}

	resp := doRequest(t, "POST", url+"/api/v1/connections/"+connID+"/ops/test_op", tok, "{}")
	body := readBody(t, resp)

	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d (body: %s)", resp.StatusCode, body)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("body is not JSON: %v (body: %s)", err, body)
	}
	if got["error"] != "reauth_required" {
		t.Fatalf("expected error=\"reauth_required\", got %q (body: %s)", got["error"], body)
	}
	if got["message"] == "" {
		t.Fatal("expected non-empty human-readable message")
	}
}

// TestRouter_Disabled_Returns403 verifies the API sentinel mapping for
// ErrConnectionDisabled: HTTP 403 with body
// {"error":"disabled","message":...}.
func TestRouter_Disabled_Returns403(t *testing.T) {
	url, tok, connID, env := setupForStatus(t)

	if err := env.Connections.SetStatus(connID, connections.StatusDisabled); err != nil {
		t.Fatalf("set status: %v", err)
	}

	resp := doRequest(t, "POST", url+"/api/v1/connections/"+connID+"/ops/test_op", tok, "{}")
	body := readBody(t, resp)

	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d (body: %s)", resp.StatusCode, body)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("body is not JSON: %v (body: %s)", err, body)
	}
	if got["error"] != "disabled" {
		t.Fatalf("expected error=\"disabled\", got %q (body: %s)", got["error"], body)
	}
}

// TestRouter_ListConnections_IncludesStatus verifies T011: the
// /api/v1/connections response includes a `status` field per
// connection so agents see at a glance which connections are usable.
// Adds a second connection and disables it to assert mixed statuses.
func TestRouter_ListConnections_IncludesStatus(t *testing.T) {
	url, tok, primaryID, env := setupForStatus(t)

	if err := env.Connections.Add("disabled-one", "mock", "Disabled One", map[string]any{}); err != nil {
		t.Fatalf("add second conn: %v", err)
	}
	if err := env.Connections.SetStatus("disabled-one", connections.StatusDisabled); err != nil {
		t.Fatalf("disable: %v", err)
	}
	// Bind the second connection to the same role so both appear in the
	// list response.
	role, err := env.Roles.GetByName("test-role")
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	bindings := append(role.Bindings, roles.Binding{
		ConnectionID: "disabled-one",
		PolicyIDs:    nil, // no policies = deny-all, but list endpoint doesn't gate on policy
	})
	if err := env.Roles.Update(role.ID, role.Name, bindings); err != nil {
		t.Fatalf("update role: %v", err)
	}

	resp := doRequest(t, "GET", url+"/api/v1/connections", tok, "")
	body := readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d (body: %s)", resp.StatusCode, body)
	}
	var got []map[string]string
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("body is not JSON: %v (body: %s)", err, body)
	}
	statuses := map[string]string{}
	for _, c := range got {
		statuses[c["id"]] = c["status"]
	}
	if statuses[primaryID] != "active" {
		t.Fatalf("expected %s status=active, got %q (full: %v)", primaryID, statuses[primaryID], statuses)
	}
	if statuses["disabled-one"] != "disabled" {
		t.Fatalf("expected disabled-one status=disabled, got %q (full: %v)", statuses["disabled-one"], statuses)
	}
}
