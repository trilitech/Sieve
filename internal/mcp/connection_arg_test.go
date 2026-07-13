package mcp_test

import (
	"net/http/httptest"
	"testing"

	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/mcp"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// grantAllOnConn adds a second mock connection and grants the role all ops on
// it, so the token sees >1 connection and MCP switches to multi-connection mode
// (tool names prefixed with the connection id).
func grantAllOnConn(t *testing.T, env *testenv.Env, roleID, connID string) {
	t.Helper()
	if err := env.Connections.Add(connID, "mock", connID, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	cedar, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: roleID, Effect: "allow", ConnectorType: "mock",
		OpScope: "all", ConnectionIDs: []string{connID},
	}, env.Mock.Meta().Operations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreatePolicy("grant-"+connID, "", cedar, true); err != nil {
		t.Fatal(err)
	}
}

// TestToolsCall_ConnectionArgIsNoOp reproduces the tezos_ops P0 (2026-07-13):
// per-connection MCP tools advertise a "connection" argument, but passing it —
// even with the correct value matching the tool's bound connection — flipped
// the call to "Policy denied". Root cause: in multi-connection mode tool names
// are prefixed with the connection id ("conn-a_list_labels"), but the
// connection-arg path stripped the connector *type* prefix ("mock_"), so the
// resolved op became the whole tool name → no such op → default-deny. The op
// must resolve identically with and without the arg.
func TestToolsCall_ConnectionArgIsNoOp(t *testing.T) {
	env := testenv.New(t)
	role := env.SetupConnectionAndRole(t, "conn-a") // conn-a + role, all ops
	grantAllOnConn(t, env, role.ID, "conn-b")       // second conn ⇒ multi-connection mode
	tok := env.CreateToken(t, role.ID)
	env.Mock.SetResponse("list_labels", map[string]any{"labels": []any{"INBOX"}})

	srv := mcp.NewServer(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	call := func(name string, args map[string]any) jsonRPCResponse {
		return doRPC(t, ts, tok, jsonRPCRequest{
			JSONRPC: "2.0", ID: 1, Method: "tools/call",
			Params: map[string]any{"name": name, "arguments": args},
		})
	}

	// Baseline: the advertised prefixed tool name, no connection arg → allow.
	if r := call("conn-a_list_labels", map[string]any{}); isToolError(r) {
		t.Fatalf("baseline (no connection arg) should allow; got result=%+v error=%+v", r.Result, r.Error)
	}
	// The reported break: same prefixed tool name + the matching connection arg.
	if r := call("conn-a_list_labels", map[string]any{"connection": "conn-a"}); isToolError(r) {
		t.Errorf("prefixed tool + matching connection arg must be a no-op (allow); got result=%+v error=%+v", r.Result, r.Error)
	}
	// A bare op name + connection arg (the other supported call shape) also works.
	if r := call("list_labels", map[string]any{"connection": "conn-a"}); isToolError(r) {
		t.Errorf("bare op + connection arg should allow; got result=%+v error=%+v", r.Result, r.Error)
	}
}
