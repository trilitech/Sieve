package mcp_test

// MCP-side coverage for sentinel surfacing.
// When connections.GetConnector returns ErrReauthRequired or
// ErrConnectionDisabled, the MCP server returns a tool-call result
// with IsError=true and a text body that begins with the stable
// error code ("reauth_required:..." / "disabled:...").
// This is the agent-facing equivalent of the REST 403-mapping tested
// in internal/api/router_status_test.go. Together they verify that
// every agent surface exposes the same machine-readable error code.

import (
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connections"
)

// TestMCP_ReauthRequired_Surface verifies T017: a tool/call against a
// reauth_required connection returns IsError=true with text starting
// "reauth_required:". The mock connector is NOT invoked.
func TestMCP_ReauthRequired_Surface(t *testing.T) {
	ts, tok, env := setup(t)

	if err := env.Connections.SetStatus("test-conn", connections.StatusReauthRequired); err != nil {
		t.Fatalf("set status: %v", err)
	}

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      100,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "list_emails",
			"arguments": map[string]any{},
		},
	})

	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC transport error: %+v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatalf("expected tool-call result body")
	}
	isErr, _ := resp.Result["isError"].(bool)
	if !isErr {
		t.Fatalf("expected IsError=true, got %+v", resp.Result)
	}
	content, ok := resp.Result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("expected content blocks, got %+v", resp.Result)
	}
	block, _ := content[0].(map[string]any)
	text, _ := block["text"].(string)
	if !strings.HasPrefix(text, "reauth_required:") {
		t.Fatalf("expected text to start with \"reauth_required:\", got %q", text)
	}

	// Mock MUST NOT be invoked — the sentinel short-circuits before the
	// connector instance is constructed, so any successful call would
	// indicate the gate is broken.
	calls := env.Mock.GetCalls()
	for _, c := range calls {
		if c.Operation == "list_emails" {
			t.Fatalf("mock list_emails was called despite reauth_required gate")
		}
	}
}

// TestMCP_Disabled_Surface verifies the same surface for the disabled
// sentinel. The text begins with "disabled:" so agents can branch
// without parsing the message.
func TestMCP_Disabled_Surface(t *testing.T) {
	ts, tok, env := setup(t)

	if err := env.Connections.SetStatus("test-conn", connections.StatusDisabled); err != nil {
		t.Fatalf("set status: %v", err)
	}

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      101,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "list_emails",
			"arguments": map[string]any{},
		},
	})

	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC transport error: %+v", resp.Error)
	}
	isErr, _ := resp.Result["isError"].(bool)
	if !isErr {
		t.Fatalf("expected IsError=true, got %+v", resp.Result)
	}
	content, _ := resp.Result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("expected content blocks")
	}
	block, _ := content[0].(map[string]any)
	text, _ := block["text"].(string)
	if !strings.HasPrefix(text, "disabled:") {
		t.Fatalf("expected text to start with \"disabled:\", got %q", text)
	}
}

// TestMCP_ListConnections_IncludesStatus verifies the built-in
// `list_connections` tool emits a `status` field per connection so
// agents see at a glance which connections are usable.
func TestMCP_ListConnections_IncludesStatus(t *testing.T) {
	ts, tok, env := setup(t)

	// Disable the bound connection so we have a non-active row to
	// observe.
	if err := env.Connections.SetStatus("test-conn", connections.StatusDisabled); err != nil {
		t.Fatalf("set status: %v", err)
	}

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      102,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "list_connections",
			"arguments": map[string]any{},
		},
	})
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	content, _ := resp.Result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("expected content blocks")
	}
	block, _ := content[0].(map[string]any)
	text, _ := block["text"].(string)
	// The list_connections tool emits JSON-encoded array text. The
	// status field must appear with the disabled value.
	if !strings.Contains(text, `"status":"disabled"`) {
		t.Fatalf("expected list_connections text to include status=disabled, got: %s", text)
	}
}
