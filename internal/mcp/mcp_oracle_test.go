package mcp_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/mcp"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// callConn invokes a tool for an explicit connection via the MCP tools/call
// "connection" argument, using a fixed request id so responses are comparable.
func callConn(t *testing.T, ts *httptest.Server, tok, connID, op string) jsonRPCResponse {
	t.Helper()
	return doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0", ID: 1, Method: "tools/call",
		Params: map[string]any{
			"name":      op,
			"arguments": map[string]any{"connection": connID},
		},
	})
}

// TestToolsCall_NoExistenceOracle: on the MCP tool-call path the IAM decision is
// the sole gate and runs on metadata BEFORE any connection-specific reveal, so a
// token with no grant cannot distinguish a missing connection from an
// ungranted-but-existing one (active or needs_reauth). All three must produce a
// byte-identical "policy denied" tool result.
func TestToolsCall_NoExistenceOracle(t *testing.T) {
	ts, tok, env := setup(t) // token granted on "test-conn" only

	// An existing, ungranted, ACTIVE connection.
	if err := env.Connections.Add("other-conn", "mock", "Ungranted", map[string]any{}); err != nil {
		t.Fatalf("add other-conn: %v", err)
	}
	// An existing, ungranted connection in needs_reauth.
	if err := env.Connections.Add("reauth-conn", "mock", "Ungranted Reauth", map[string]any{}); err != nil {
		t.Fatalf("add reauth-conn: %v", err)
	}
	if err := env.Connections.SetStatusWithReason("reauth-conn", connections.StatusReauthRequired, "token expired"); err != nil {
		t.Fatalf("set reauth: %v", err)
	}

	// (i) missing/guessed id, (ii) ungranted+reauth, (iii) ungranted+active.
	respMissing := callConn(t, ts, tok, "ghost-conn", "list_emails")
	respReauth := callConn(t, ts, tok, "reauth-conn", "list_emails")
	respActive := callConn(t, ts, tok, "other-conn", "list_emails")

	norm := func(r jsonRPCResponse) string {
		if r.Error != nil {
			t.Fatalf("expected a uniform tool result, got JSON-RPC error: %v", r.Error)
		}
		b, _ := json.Marshal(r.Result)
		return string(b)
	}
	missing, reauth, active := norm(respMissing), norm(respReauth), norm(respActive)

	if missing != reauth || missing != active {
		t.Fatalf("existence/status oracle: responses differ\n missing=%s\n reauth =%s\n active =%s", missing, reauth, active)
	}
	// And the uniform response must not leak a reason or a reauth envelope.
	if strings.Contains(missing, "reauth_required") || strings.Contains(strings.ToLower(missing), "not found") {
		t.Fatalf("uniform response leaks status/existence: %s", missing)
	}
	if !strings.Contains(missing, "Policy denied") {
		t.Fatalf("expected a policy-denied result, got: %s", missing)
	}
}

// TestToolsCall_AuthorizedStillSeesReauth: a token that IS granted on a
// connection still gets the structured reauth envelope when that connection is
// in needs_reauth — the oracle fix only changes the UNauthorized path.
func TestToolsCall_AuthorizedStillSeesReauth(t *testing.T) {
	ts, tok, env := setup(t) // token granted on "test-conn"

	if err := env.Connections.SetStatusWithReason("test-conn", connections.StatusReauthRequired, "token expired"); err != nil {
		t.Fatalf("set reauth: %v", err)
	}

	resp := callConn(t, ts, tok, "test-conn", "list_emails")
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %v", resp.Error)
	}
	body := resultText(resp.Result)
	if !strings.Contains(body, "reauth_required") {
		t.Fatalf("authorized caller should see reauth_required, got: %s", body)
	}
}

// TestToolsList_AdvertisesWriteOnlyGrant: discovery must consider the operations
// it advertises, not just a representative read op. A token granted only a WRITE
// op (send_email) must still see that connection and receive the send_email tool
// schema, while the read ops it can't call stay hidden.
func TestToolsList_AdvertisesWriteOnlyGrant(t *testing.T) {
	env := testenv.New(t)
	if err := env.Connections.Add("wo-conn", "mock", "WriteOnly", map[string]any{}); err != nil {
		t.Fatalf("add wo-conn: %v", err)
	}
	role, err := env.Roles.Create("wo-role", nil)
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	// Grant ONLY send_email on wo-conn (a write op; list_emails stays denied).
	grant, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: role.ID, Effect: "allow", ConnectorType: "mock",
		OpScope: "specific", Operations: []string{"send_email"},
		ConnectionIDs: []string{"wo-conn"},
	}, env.Mock.Meta().Operations)
	if err != nil {
		t.Fatalf("build grant: %v", err)
	}
	if _, err := env.IAM.CreatePolicy("wo-grant", "", grant, true); err != nil {
		t.Fatalf("create grant: %v", err)
	}
	if err := env.Settings.Set("iam_enabled", "true"); err != nil {
		t.Fatalf("enable iam: %v", err)
	}
	tok := env.CreateToken(t, role.ID)

	srv := mcp.NewServer(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp := doRPC(t, ts, tok, jsonRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/list"})
	if resp.Error != nil {
		t.Fatalf("tools/list error: %v", resp.Error)
	}
	toolsRaw, _ := resp.Result["tools"].([]any)
	var names []string
	for _, tr := range toolsRaw {
		m, _ := tr.(map[string]any)
		if n, _ := m["name"].(string); n != "" {
			names = append(names, n)
		}
	}
	joined := strings.Join(names, ",")
	// Single visible connection ⇒ tool names are unprefixed.
	if !contains(names, "send_email") {
		t.Fatalf("write-only grant should advertise the send_email tool; got: %s", joined)
	}
	if contains(names, "list_emails") {
		t.Fatalf("read op the token can't call must not be advertised; got: %s", joined)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
