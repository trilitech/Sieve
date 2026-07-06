package mcp_test

import (
	"strings"
	"testing"
)

// A token granted only on one connection must not discover tools (or the
// connection id/name) for a connection it has no grant on — MCP tools/list is
// IAM-gated the same way the REST discovery surface is.
func TestToolsList_FilteredByIAM(t *testing.T) {
	ts, tok, env := setup(t) // grants role on "test-conn"

	// A second mock connection with NO IAM grant for the token's role.
	if err := env.Connections.Add("other-conn", "mock", "Ungranted", map[string]any{}); err != nil {
		t.Fatalf("add other-conn: %v", err)
	}

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0", ID: 1, Method: "tools/list",
	})
	if resp.Error != nil {
		t.Fatalf("tools/list error: %v", resp.Error)
	}
	toolsRaw, _ := resp.Result["tools"].([]any)
	if len(toolsRaw) == 0 {
		t.Fatal("expected some tools for the granted connection")
	}
	sawGranted := false
	for _, tr := range toolsRaw {
		m, _ := tr.(map[string]any)
		name, _ := m["name"].(string)
		if strings.Contains(name, "other-conn") {
			t.Errorf("tools/list leaked a tool for the ungranted connection: %q", name)
		}
		if name != "list_connections" {
			sawGranted = true
		}
	}
	if !sawGranted {
		t.Fatal("expected the granted connection's operation tools to be listed")
	}

	// list_connections must likewise not disclose the ungranted connection.
	lc := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0", ID: 2, Method: "tools/call",
		Params: map[string]any{"name": "list_connections", "arguments": map[string]any{}},
	})
	if lc.Error != nil {
		t.Fatalf("list_connections error: %v", lc.Error)
	}
	if body := resultText(lc.Result); strings.Contains(body, "other-conn") {
		t.Errorf("list_connections leaked the ungranted connection: %s", body)
	}
}

// resultText pulls the first text content block out of a tools/call result.
func resultText(result map[string]any) string {
	content, _ := result["content"].([]any)
	var b strings.Builder
	for _, c := range content {
		m, _ := c.(map[string]any)
		if s, _ := m["text"].(string); s != "" {
			b.WriteString(s)
		}
	}
	return b.String()
}
