package mcp_test

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	slackconn "github.com/trilitech/Sieve/internal/connectors/slack"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/mcp"
	"github.com/trilitech/Sieve/internal/policy"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/testing/mockslack"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/tokens"
)

const mcpGuardScript = `import sys, json
req = json.load(sys.stdin)
b = ((req.get("params") or {}).get("body")) or ""
print(json.dumps({"action": "deny", "reason": "blocked"} if "secret" in b.lower() else {"action": "allow"}))
`

// TestMCP_ScriptConditionEnforced proves the SECOND agent surface (MCP) enforces a
// rule's script-mode CONDITION (spec §5.4) identically to REST: a tool call whose
// body contains "secret" returns a tool error; a clean one succeeds. Without this,
// "the gateway provably enforces" would be proven for only one surface.
func TestMCP_ScriptConditionEnforced(t *testing.T) {
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

	// The send rule's CONDITION is a script (spec §5.4). The seed role grant is
	// read-only, so this rule is the sole authorizer of the write → the script gates it.
	grant, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: role.ID, Effect: "allow", ConnectorType: "mock", OpScope: "write",
		ConnectionIDs:   []string{"test-conn"},
		ConditionMode:   "script",
		ConditionScript: iampolicies.ScriptCondSpec{Command: py, Path: scriptPath},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreatePolicy("send-scripted", "", grant, true); err != nil {
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

// addSlackConn adds a Slack connection pointed at the mock server and grants
// slack/search_messages on it to the given role.
func addSlackConn(t *testing.T, env *testenv.Env, mock *mockslack.Server, id, roleID string, cfg map[string]any) {
	t.Helper()
	cfg["_base_url"] = mock.URL
	cfg["outbound_allowlist"] = []any{"127.0.0.0/8"}
	if err := env.Connections.Add(id, "slack", id, cfg); err != nil {
		t.Fatal(err)
	}
	grant, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: roleID, Effect: "allow", ConnectorType: "slack",
		OpScope: "specific", Operations: []string{"search_messages"},
		ConnectionIDs: []string{id},
	}, slackconn.Meta().Operations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreatePolicy("search-"+id, "", grant, true); err != nil {
		t.Fatal(err)
	}
}

// TestMCP_SlackSearchByIdentityEnforced mirrors the REST enforcement test on
// the MCP surface: with slack/search_messages granted, a user-token
// connection runs the search tool, while a bot-token connection with the
// same grant returns a tool error carrying the operation_not_enabled prefix.
// One token binds both connections, so tools are connection-prefixed.
func TestMCP_SlackSearchByIdentityEnforced(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)

	env := testenv.New(t)
	env.Registry.Register(slackconn.Meta(), slackconn.Factory())

	role, err := env.Roles.Create("searcher", []roles.Binding{
		{ConnectionID: "slack-user"}, {ConnectionID: "slack-bot"},
	})
	if err != nil {
		t.Fatal(err)
	}
	addSlackConn(t, env, mock, "slack-user", role.ID,
		map[string]any{"auth_kind": slackconn.KindUserToken, "user_token": "xoxp-user-tok", "team_id": "T012"})
	addSlackConn(t, env, mock, "slack-bot", role.ID,
		map[string]any{"auth_kind": slackconn.KindToken, "bot_token": "xoxb-bot-tok", "team_id": "T012"})
	tok, err := env.Tokens.Create(&tokens.CreateRequest{Name: "t", RoleID: role.ID})
	if err != nil {
		t.Fatal(err)
	}

	if err := env.Settings.Set("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	srv := mcp.NewServer(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// The token holds two connections, so tools are connection-prefixed.
	call := func(tool string) jsonRPCResponse {
		return doRPC(t, ts, tok.PlaintextToken, jsonRPCRequest{
			JSONRPC: "2.0", ID: 1, Method: "tools/call",
			Params: map[string]any{
				"name":      tool,
				"arguments": map[string]any{"query": "deploy"},
			},
		})
	}

	if r := call("slack-user_search_messages"); isToolError(r) {
		t.Errorf("user-token search should succeed over MCP, got error: %+v", r.Result)
	}
	botResp := call("slack-bot_search_messages")
	if !isToolError(botResp) {
		t.Errorf("bot-token search should be a tool error over MCP, got: %+v", botResp.Result)
	}
	// The error must carry the canonical operation_not_enabled prefix.
	if content, _ := botResp.Result["content"].([]any); len(content) > 0 {
		if first, _ := content[0].(map[string]any); first != nil {
			if text, _ := first["text"].(string); !strings.Contains(text, "operation_not_enabled") {
				t.Errorf("bot error should carry operation_not_enabled prefix, got %q", text)
			}
		}
	}
}
