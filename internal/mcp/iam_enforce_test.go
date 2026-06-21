package mcp_test

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/mcp"
	"github.com/trilitech/Sieve/internal/policy"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

const mcpGuardScript = `import sys, json
req = json.load(sys.stdin)
b = ((req.get("params") or {}).get("body")) or ""
print(json.dumps({"action": "deny", "reason": "blocked"} if "secret" in b.lower() else {"action": "allow"}))
`

// TestMCP_ScriptGuardEnforced proves the SECOND agent surface (MCP) enforces an
// operator-authored script guard identically to REST: a tool call whose body
// contains "secret" returns a tool error; a clean one succeeds. Without this,
// "the gateway provably enforces" would be proven for only one surface.
func TestMCP_ScriptGuardEnforced(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	policy.SetCommandAllowlist([]string{py})
	defer policy.SetCommandAllowlist(nil)

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "block_secret.py")
	if err := os.WriteFile(scriptPath, []byte(mcpGuardScript), 0o600); err != nil {
		t.Fatal(err)
	}
	policy.SetScriptDirs([]string{dir})
	defer policy.SetScriptDirs(nil)

	env := testenv.New(t)
	role := env.SetupConnectionAndRole(t, "test-conn", "read-only")
	tok := env.CreateToken(t, role.ID)
	env.Mock.SetResponse("send_email", map[string]any{"id": "1"})

	if _, err := env.IAM.CreateFilter("block-secret", "", iam.KindScriptGuard, 0,
		map[string]any{"command": py, "path": scriptPath}); err != nil {
		t.Fatal(err)
	}
	spec := iampolicies.RuleSpec{
		RoleID: role.ID, Effect: "allow", ConnectorType: "mock", OpScope: "write",
		ConnectionIDs: []string{"test-conn"}, Filters: []string{"block-secret"},
	}
	grant, err := iampolicies.BuildRuleCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreatePolicy("send-guarded", "", grant, true); err != nil {
		t.Fatal(err)
	}
	guard, err := iampolicies.BuildGuardrailCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreateGuardrail("send-guarded-g", "", guard, true); err != nil {
		t.Fatal(err)
	}

	srv := mcp.NewServer(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	if err := env.Settings.Set("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	call := func(body string) jsonRPCResponse {
		return doRPC(t, ts, tok, jsonRPCRequest{
			JSONRPC: "2.0", ID: 1, Method: "tools/call",
			Params: map[string]any{
				"name":      "send_email",
				"arguments": map[string]any{"to": "a@b.com", "subject": "s", "body": body},
			},
		})
	}

	if clean := call("weekly status"); isToolError(clean) {
		t.Errorf("clean send should succeed over MCP, got error: %+v", clean.Result)
	}
	if blocked := call("the secret plan"); !isToolError(blocked) {
		t.Errorf("send with 'secret' should be blocked over MCP, got: %+v", blocked.Result)
	}
}

func isToolError(r jsonRPCResponse) bool {
	if r.Result == nil {
		return true // transport/JSON-RPC error counts as not-allowed
	}
	b, _ := r.Result["isError"].(bool)
	return b
}
