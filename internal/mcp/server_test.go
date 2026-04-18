package mcp_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/murbard/Sieve/internal/connector"
	"github.com/murbard/Sieve/internal/mcp"
	mockconn "github.com/murbard/Sieve/internal/testing/mockconnector"
	"github.com/murbard/Sieve/internal/roles"
	"github.com/murbard/Sieve/internal/testing/testenv"
	"github.com/murbard/Sieve/internal/tokens"
)

type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      any            `json:"id"`
	Result  map[string]any `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func setup(t *testing.T) (*httptest.Server, string, *testenv.Env) {
	t.Helper()

	env := testenv.New(t)
	role := env.SetupConnectionAndRole(t, "test-conn", "read-only")
	plaintext := env.CreateToken(t, role.ID)

	srv := mcp.NewServer(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return ts, plaintext, env
}

func doRPC(t *testing.T, ts *httptest.Server, token string, req jsonRPCRequest) jsonRPCResponse {
	t.Helper()

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	httpReq, err := http.NewRequest("POST", ts.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	var rpcResp jsonRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return rpcResp
}

func TestInitialize(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("expected result")
	}

	serverInfo, ok := resp.Result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatal("expected serverInfo in result")
	}
	if serverInfo["name"] != "sieve" {
		t.Fatalf("expected server name 'sieve', got %q", serverInfo["name"])
	}
}

func TestToolsList(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	tools, ok := resp.Result["tools"].([]any)
	if !ok {
		t.Fatal("expected tools array")
	}

	// Should include connector operations + built-in tools.
	if len(tools) < 4 {
		t.Fatalf("expected at least 4 tools (built-in), got %d", len(tools))
	}

	// Check that built-in tools are present.
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolMap, ok := tool.(map[string]any)
		if !ok {
			continue
		}
		name, _ := toolMap["name"].(string)
		toolNames[name] = true
	}

	for _, expected := range []string{"list_connections", "list_policies", "get_my_policy", "propose_policy"} {
		if !toolNames[expected] {
			t.Errorf("missing built-in tool %q", expected)
		}
	}
}

func TestNoAuth(t *testing.T) {
	env := testenv.New(t)
	srv := mcp.NewServer(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	body, _ := json.Marshal(jsonRPCRequest{JSONRPC: "2.0", ID: 1, Method: "initialize"})
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	var rpcResp jsonRPCResponse
	json.NewDecoder(resp.Body).Decode(&rpcResp)

	if rpcResp.Error == nil {
		t.Fatal("expected error for missing auth")
	}
	if rpcResp.Error.Code != -32000 {
		t.Fatalf("expected code -32000, got %d", rpcResp.Error.Code)
	}
}

func TestBadToken(t *testing.T) {
	ts, _, _ := setup(t)

	resp := doRPC(t, ts, "sieve_tok_bogus1234567890abcdef0123456789", jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	})

	if resp.Error == nil {
		t.Fatal("expected error for bad token")
	}
}

func TestMethodNotFound(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "nonexistent/method",
	})

	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != -32601 {
		t.Fatalf("expected code -32601, got %d", resp.Error.Code)
	}
}

func TestToolCallAllowed(t *testing.T) {
	ts, tok, env := setup(t)

	// Set a response on the mock.
	env.Mock.SetResponse("list_emails", map[string]any{"emails": []any{}, "total": 0})

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "list_emails",
			"arguments": map[string]any{},
		},
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	// Check mock was called.
	calls := env.Mock.GetCalls()
	if len(calls) == 0 {
		t.Fatal("expected mock to be called")
	}
	if calls[0].Operation != "list_emails" {
		t.Fatalf("expected list_emails call, got %q", calls[0].Operation)
	}
}

func TestToolCallDenied(t *testing.T) {
	env := testenv.New(t)

	// Create a policy that denies send_email.
	pol, err := env.Policies.Create("deny-send", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "sending blocked",
			},
		},
		"default_action": "allow",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	// Set up connection + role with the deny policy.
	err = env.Connections.Add("deny-conn", "mock", "Deny Test", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}
	role, err := env.Roles.Create("deny-role", []roles.Binding{
		{ConnectionID: "deny-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	result, err := env.Tokens.Create(&tokens.CreateRequest{Name: "deny-tok", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	srv := mcp.NewServer(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp := doRPC(t, ts, result.PlaintextToken, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "send_email",
			"arguments": map[string]any{"to": []string{"a@b.com"}, "subject": "Hi", "body": "Hello"},
		},
	})

	if resp.Error != nil {
		t.Fatalf("unexpected RPC error: %v", resp.Error)
	}

	// The result should indicate an error with policy denial.
	content, ok := resp.Result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("expected content in result")
	}
	block, ok := content[0].(map[string]any)
	if !ok {
		t.Fatal("expected content block")
	}
	text, _ := block["text"].(string)
	if text == "" {
		t.Fatal("expected text in content block")
	}
	if !strings.Contains(strings.ToLower(text), "denied") && !strings.Contains(strings.ToLower(text), "deny") {
		t.Fatalf("expected denial text to contain 'denied' or 'deny', got %q", text)
	}
	if !strings.Contains(text, "sending blocked") {
		t.Fatalf("expected denial text to contain the reason 'sending blocked', got %q", text)
	}

	// Verify isError flag is set.
	isError, _ := resp.Result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for denied tool call")
	}

	// Mock should NOT have been called.
	calls := env.Mock.GetCalls()
	if len(calls) > 0 {
		t.Fatalf("expected no mock calls for denied operation, got %d", len(calls))
	}
}

func TestToolCallApprovalRequired(t *testing.T) {
	env := testenv.New(t)

	pol, err := env.Policies.Create("approval-pol", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "approval_required",
			},
		},
		"default_action": "allow",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	err = env.Connections.Add("appr-conn", "mock", "Approval Test", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}
	role, err := env.Roles.Create("appr-role", []roles.Binding{
		{ConnectionID: "appr-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	result, err := env.Tokens.Create(&tokens.CreateRequest{Name: "appr-tok", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	srv := mcp.NewServer(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp := doRPC(t, ts, result.PlaintextToken, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "send_email",
			"arguments": map[string]any{"to": []string{"a@b.com"}, "subject": "Hi", "body": "Hello"},
		},
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	// Check approval was submitted.
	pending, err := env.Approval.ListPending()
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending approval, got %d", len(pending))
	}
	if pending[0].Operation != "send_email" {
		t.Fatalf("expected send_email, got %q", pending[0].Operation)
	}
}

func TestListConnections(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      6,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "list_connections",
			"arguments": map[string]any{},
		},
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	// Verify the result actually contains connection data.
	content, ok := resp.Result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("expected content in list_connections result")
	}
	block, ok := content[0].(map[string]any)
	if !ok {
		t.Fatal("expected content block")
	}
	text, _ := block["text"].(string)
	if text == "" {
		t.Fatal("expected non-empty text in list_connections result")
	}
	if !strings.Contains(text, "test-conn") {
		t.Fatalf("expected list_connections result to contain 'test-conn', got %q", text)
	}
	if !strings.Contains(text, "mock") {
		t.Fatalf("expected list_connections result to contain connector type 'mock', got %q", text)
	}
}

func TestProposePolicy(t *testing.T) {
	ts, tok, env := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      7,
		Method:  "tools/call",
		Params: map[string]any{
			"name": "propose_policy",
			"arguments": map[string]any{
				"name":        "my-proposal",
				"description": "Allow reading only",
				"rules": []any{
					map[string]any{
						"match":  map[string]any{"operations": []any{"list_emails"}},
						"action": "allow",
					},
				},
			},
		},
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	// Should be in approval queue.
	pending, err := env.Approval.ListPending()
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
	if pending[0].Operation != "propose_policy" {
		t.Fatalf("expected propose_policy, got %q", pending[0].Operation)
	}
}

func TestGetOnly(t *testing.T) {
	env := testenv.New(t)
	srv := mcp.NewServer(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	var rpcResp jsonRPCResponse
	json.NewDecoder(resp.Body).Decode(&rpcResp)

	if rpcResp.Error == nil {
		t.Fatal("expected error for GET request")
	}
}

func TestGetMyPolicy(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      10,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "get_my_policy",
			"arguments": map[string]any{},
		},
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	content, ok := resp.Result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("expected content in get_my_policy result")
	}
	block, ok := content[0].(map[string]any)
	if !ok {
		t.Fatal("expected content block")
	}
	text, _ := block["text"].(string)
	if text == "" {
		t.Fatal("expected non-empty text in get_my_policy result")
	}
	// The result should contain the connection ID and policy details.
	if !strings.Contains(text, "test-conn") {
		t.Fatalf("expected get_my_policy result to contain connection 'test-conn', got %q", text)
	}
	if !strings.Contains(text, "read-only") {
		t.Fatalf("expected get_my_policy result to contain policy name 'read-only', got %q", text)
	}
}

func TestListPolicies(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      11,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "list_policies",
			"arguments": map[string]any{},
		},
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	content, ok := resp.Result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("expected content in list_policies result")
	}
	block, ok := content[0].(map[string]any)
	if !ok {
		t.Fatal("expected content block")
	}
	text, _ := block["text"].(string)
	if text == "" {
		t.Fatal("expected non-empty text in list_policies result")
	}
	// Should contain at least the preset policies.
	if !strings.Contains(text, "read-only") {
		t.Fatalf("expected list_policies result to contain 'read-only' preset, got %q", text)
	}
}

func TestMultiConnectionToolNamePrefixing(t *testing.T) {
	env := testenv.New(t)

	// Create two connections of different types.
	err := env.Connections.Add("conn-a", "mock", "Connection A", map[string]any{})
	if err != nil {
		t.Fatalf("add conn-a: %v", err)
	}

	// Register a second mock connector under a different type.
	mock2 := mockconn.New("mock2")
	env.Registry.Register(mock2.Meta(), mock2.Factory())
	err = env.Connections.Add("conn-b", "mock2", "Connection B", map[string]any{})
	if err != nil {
		t.Fatalf("add conn-b: %v", err)
	}

	polReadOnly, err := env.Policies.GetByName("read-only")
	if err != nil {
		t.Fatalf("get read-only policy: %v", err)
	}

	role, err := env.Roles.Create("multi-conn-role", []roles.Binding{
		{ConnectionID: "conn-a", PolicyIDs: []string{polReadOnly.ID}},
		{ConnectionID: "conn-b", PolicyIDs: []string{polReadOnly.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	result, err := env.Tokens.Create(&tokens.CreateRequest{Name: "multi-tok", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	srv := mcp.NewServer(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// List tools and verify prefixed names.
	resp := doRPC(t, ts, result.PlaintextToken, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      12,
		Method:  "tools/list",
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	tools, ok := resp.Result["tools"].([]any)
	if !ok {
		t.Fatal("expected tools array")
	}

	// With multi-connection, tool names should be prefixed with connector type.
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolMap, ok := tool.(map[string]any)
		if !ok {
			continue
		}
		name, _ := toolMap["name"].(string)
		toolNames[name] = true
	}

	// Tool names should be prefixed with connection ID (not connector type).
	if !toolNames["conn-a_list_emails"] {
		t.Fatalf("expected prefixed tool 'conn-a_list_emails' in multi-connection mode, got tools: %v", toolNames)
	}
	if !toolNames["conn-b_list_emails"] {
		t.Fatalf("expected prefixed tool 'conn-b_list_emails' in multi-connection mode, got tools: %v", toolNames)
	}
}

func TestToolCallConnectionNotInRole(t *testing.T) {
	env := testenv.New(t)

	// Create two connections but only bind one to the role.
	err := env.Connections.Add("allowed-conn", "mock", "Allowed", map[string]any{})
	if err != nil {
		t.Fatalf("add allowed-conn: %v", err)
	}
	err = env.Connections.Add("forbidden-conn", "mock", "Forbidden", map[string]any{})
	if err != nil {
		t.Fatalf("add forbidden-conn: %v", err)
	}

	polReadOnly, err := env.Policies.GetByName("read-only")
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}

	// Only bind allowed-conn.
	role, err := env.Roles.Create("limited-role", []roles.Binding{
		{ConnectionID: "allowed-conn", PolicyIDs: []string{polReadOnly.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	result, err := env.Tokens.Create(&tokens.CreateRequest{Name: "limited-tok", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	srv := mcp.NewServer(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Try to call a tool on the forbidden connection by passing connection argument.
	resp := doRPC(t, ts, result.PlaintextToken, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      13,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "list_emails",
			"arguments": map[string]any{"connection": "forbidden-conn"},
		},
	})

	if resp.Error == nil {
		t.Fatal("expected error when calling tool on connection not in role")
	}
	if !strings.Contains(resp.Error.Message, "not allowed") {
		t.Fatalf("expected error about connection not allowed, got %q", resp.Error.Message)
	}
}

// --- User story tests ---

// Story 144: tools/list returns built-in tools plus connector operations.
func TestStory144_ToolsListReturnsBuiltInAndConnectorOps(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      100,
		Method:  "tools/list",
	})

	if resp.Error != nil {
		t.Fatalf("story 144: unexpected error: %v", resp.Error)
	}

	tools, ok := resp.Result["tools"].([]any)
	if !ok {
		t.Fatal("story 144: expected tools array in result")
	}

	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolMap, ok := tool.(map[string]any)
		if !ok {
			continue
		}
		name, _ := toolMap["name"].(string)
		toolNames[name] = true
	}

	// Built-in tools
	for _, builtin := range []string{"list_connections", "list_policies", "get_my_policy", "propose_policy"} {
		if !toolNames[builtin] {
			t.Fatalf("story 144: missing built-in tool %q in tools/list", builtin)
		}
	}

	// Connector operations from mock (list_emails, read_email, send_email, list_labels)
	for _, connOp := range []string{"list_emails", "read_email", "send_email", "list_labels"} {
		if !toolNames[connOp] {
			t.Fatalf("story 144: missing connector operation %q in tools/list", connOp)
		}
	}

	// Total should be builtins (4) + connector ops (4) = 8
	if len(tools) < 8 {
		t.Fatalf("story 144: expected at least 8 tools (4 builtin + 4 connector), got %d", len(tools))
	}
}

// Story 146: list_connections returns connection data.
func TestStory146_ListConnectionsReturnsData(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      101,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "list_connections",
			"arguments": map[string]any{},
		},
	})

	if resp.Error != nil {
		t.Fatalf("story 146: unexpected error: %v", resp.Error)
	}

	content, ok := resp.Result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("story 146: expected content in list_connections result")
	}
	block, ok := content[0].(map[string]any)
	if !ok {
		t.Fatal("story 146: expected content block")
	}
	text, _ := block["text"].(string)
	if !strings.Contains(text, "test-conn") {
		t.Fatalf("story 146: expected connection ID 'test-conn' in result, got %q", text)
	}
	if !strings.Contains(text, "mock") {
		t.Fatalf("story 146: expected connector type 'mock' in result, got %q", text)
	}
}

// Story 147: get_my_policy returns policy details.
func TestStory147_GetMyPolicyReturnsDetails(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      102,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "get_my_policy",
			"arguments": map[string]any{},
		},
	})

	if resp.Error != nil {
		t.Fatalf("story 147: unexpected error: %v", resp.Error)
	}

	content, ok := resp.Result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("story 147: expected content in get_my_policy result")
	}
	block, ok := content[0].(map[string]any)
	if !ok {
		t.Fatal("story 147: expected content block")
	}
	text, _ := block["text"].(string)
	if text == "" {
		t.Fatal("story 147: expected non-empty text in get_my_policy result")
	}
	if !strings.Contains(text, "test-conn") {
		t.Fatalf("story 147: expected connection ID in policy details, got %q", text)
	}
	if !strings.Contains(text, "read-only") {
		t.Fatalf("story 147: expected policy name 'read-only' in policy details, got %q", text)
	}
	// Verify it contains actual policy config details
	if !strings.Contains(text, "rules") {
		t.Fatalf("story 147: expected 'rules' in policy config, got %q", text)
	}
}

// Story 150: initialize returns server info.
func TestStory150_InitializeReturnsServerInfo(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      103,
		Method:  "initialize",
	})

	if resp.Error != nil {
		t.Fatalf("story 150: unexpected error: %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("story 150: expected non-nil result")
	}

	serverInfo, ok := resp.Result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatal("story 150: expected serverInfo in result")
	}
	if serverInfo["name"] != "sieve" {
		t.Fatalf("story 150: expected server name 'sieve', got %v", serverInfo["name"])
	}
	if serverInfo["version"] == nil || serverInfo["version"] == "" {
		t.Fatal("story 150: expected non-empty version in serverInfo")
	}

	// Verify protocolVersion
	if resp.Result["protocolVersion"] == nil {
		t.Fatal("story 150: expected protocolVersion in result")
	}

	// Verify capabilities
	caps, ok := resp.Result["capabilities"].(map[string]any)
	if !ok {
		t.Fatal("story 150: expected capabilities in result")
	}
	if _, ok := caps["tools"]; !ok {
		t.Fatal("story 150: expected 'tools' in capabilities")
	}
}

// Story 343: Invalid JSON-RPC version → error -32600.
func TestStory343_InvalidJSONRPCVersion(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "1.0",
		ID:      104,
		Method:  "initialize",
	})

	if resp.Error == nil {
		t.Fatal("story 343: expected error for invalid JSON-RPC version")
	}
	if resp.Error.Code != -32600 {
		t.Fatalf("story 343: expected error code -32600, got %d", resp.Error.Code)
	}
}

// Story 344: Unknown method → error -32601.
func TestStory344_UnknownMethod(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      105,
		Method:  "totally/bogus",
	})

	if resp.Error == nil {
		t.Fatal("story 344: expected error for unknown method")
	}
	if resp.Error.Code != -32601 {
		t.Fatalf("story 344: expected error code -32601, got %d", resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "method not found") {
		t.Fatalf("story 344: expected 'method not found' in error, got %q", resp.Error.Message)
	}
}

// Story 346: GET request → error.
func TestStory346_GetRequestReturnsError(t *testing.T) {
	env := testenv.New(t)
	srv := mcp.NewServer(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("story 346: request error: %v", err)
	}
	defer resp.Body.Close()

	var rpcResp jsonRPCResponse
	json.NewDecoder(resp.Body).Decode(&rpcResp)

	if rpcResp.Error == nil {
		t.Fatal("story 346: expected error for GET request")
	}
	if rpcResp.Error.Code != -32600 {
		t.Fatalf("story 346: expected error code -32600, got %d", rpcResp.Error.Code)
	}
}

// Story 145: Multi-connection tool name prefixing.
// Verify tool names are prefixed with connector type when a token has two connections.
func TestStory145_MultiConnectionToolNamePrefixing(t *testing.T) {
	env := testenv.New(t)

	// Create two connections of different types.
	err := env.Connections.Add("conn-gmail", "mock", "Gmail Connection", map[string]any{})
	if err != nil {
		t.Fatalf("add conn-gmail: %v", err)
	}

	mock2 := mockconn.New("mock2")
	env.Registry.Register(mock2.Meta(), mock2.Factory())
	err = env.Connections.Add("conn-drive", "mock2", "Drive Connection", map[string]any{})
	if err != nil {
		t.Fatalf("add conn-drive: %v", err)
	}

	polReadOnly, err := env.Policies.GetByName("read-only")
	if err != nil {
		t.Fatalf("get read-only policy: %v", err)
	}

	role, err := env.Roles.Create("multi-role-145", []roles.Binding{
		{ConnectionID: "conn-gmail", PolicyIDs: []string{polReadOnly.ID}},
		{ConnectionID: "conn-drive", PolicyIDs: []string{polReadOnly.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	result, err := env.Tokens.Create(&tokens.CreateRequest{Name: "multi-tok-145", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	srv := mcp.NewServer(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp := doRPC(t, ts, result.PlaintextToken, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      200,
		Method:  "tools/list",
	})

	if resp.Error != nil {
		t.Fatalf("story 145: unexpected error: %v", resp.Error)
	}

	tools, ok := resp.Result["tools"].([]any)
	if !ok {
		t.Fatal("story 145: expected tools array")
	}

	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolMap, ok := tool.(map[string]any)
		if !ok {
			continue
		}
		name, _ := toolMap["name"].(string)
		toolNames[name] = true
	}

	// With two connections, tool names should be prefixed with connection ID.
	if !toolNames["conn-gmail_list_emails"] {
		t.Fatalf("story 145: expected 'conn-gmail_list_emails' (prefixed by connection ID), got tools: %v", toolNames)
	}
	if !toolNames["conn-drive_list_emails"] {
		t.Fatalf("story 145: expected 'conn-drive_list_emails' (prefixed by connection ID), got tools: %v", toolNames)
	}
	if !toolNames["conn-gmail_send_email"] {
		t.Fatalf("story 145: expected 'conn-gmail_send_email' (prefixed by connection ID), got tools: %v", toolNames)
	}

	// Unprefixed tool names should NOT exist.
	if toolNames["list_emails"] {
		t.Fatal("story 145: 'list_emails' should not exist unprefixed in multi-connection mode")
	}
}

// Story 149: denormalizeDots — tool call with name "drive_list_files" gets
// converted to "drive.list_files" before execution. We test this by creating
// a mock connector with a namespaced operation and calling it via the tool name.
func TestStory149_DenormalizeDots(t *testing.T) {
	env := testenv.New(t)

	// Create a mock connector with a namespaced operation name "drive.list_files".
	driveMock := mockconn.NewMinimal("drive_mock")
	driveMock.Ops = []connector.OperationDef{
		{Name: "drive.list_files", Description: "List files in Drive", ReadOnly: true},
	}
	driveMock.SetResponse("drive.list_files", map[string]any{"files": []any{"file1.txt", "file2.txt"}})
	env.Registry.Register(driveMock.Meta(), driveMock.Factory())

	err := env.Connections.Add("drive-conn", "drive_mock", "Drive", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	// Use a permissive policy that allows all operations (the read-only preset
	// only allows specific Gmail operations, which would deny drive.list_files).
	allowAllPol, err := env.Policies.Create("allow-all-149", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"action": "allow",
			},
		},
		"default_action": "allow",
	})
	if err != nil {
		t.Fatalf("create allow-all policy: %v", err)
	}

	role, err := env.Roles.Create("drive-role", []roles.Binding{
		{ConnectionID: "drive-conn", PolicyIDs: []string{allowAllPol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	result, err := env.Tokens.Create(&tokens.CreateRequest{Name: "drive-tok", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	mcpSrv := mcp.NewServer(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(mcpSrv.Handler())
	t.Cleanup(ts.Close)

	// First verify that tools/list shows the denormalized name (dots → underscores).
	listResp := doRPC(t, ts, result.PlaintextToken, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      201,
		Method:  "tools/list",
	})

	if listResp.Error != nil {
		t.Fatalf("story 149: tools/list error: %v", listResp.Error)
	}

	tools, ok := listResp.Result["tools"].([]any)
	if !ok {
		t.Fatal("story 149: expected tools array")
	}

	foundDriveListFiles := false
	for _, tool := range tools {
		toolMap, ok := tool.(map[string]any)
		if !ok {
			continue
		}
		name, _ := toolMap["name"].(string)
		if name == "drive_list_files" {
			foundDriveListFiles = true
		}
	}
	if !foundDriveListFiles {
		t.Fatal("story 149: expected 'drive_list_files' in tools/list (dots normalized to underscores)")
	}

	// Now call the tool using the underscore name — it should be denormalized
	// back to "drive.list_files" before execution.
	callResp := doRPC(t, ts, result.PlaintextToken, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      202,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "drive_list_files",
			"arguments": map[string]any{},
		},
	})

	if callResp.Error != nil {
		t.Fatalf("story 149: tools/call error: %v", callResp.Error)
	}

	// Verify the mock was called with the original dotted name.
	calls := driveMock.GetCalls()
	if len(calls) == 0 {
		t.Fatal("story 149: expected mock to be called")
	}
	if calls[0].Operation != "drive.list_files" {
		t.Fatalf("story 149: expected operation 'drive.list_files' (denormalized), got %q", calls[0].Operation)
	}

	// Verify the response contains the mock data.
	content, ok := callResp.Result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("story 149: expected content in result")
	}
	block, ok := content[0].(map[string]any)
	if !ok {
		t.Fatal("story 149: expected content block")
	}
	text, _ := block["text"].(string)
	if !strings.Contains(text, "file1.txt") {
		t.Fatalf("story 149: expected response to contain 'file1.txt', got %q", text)
	}
}

// Story 148: propose_policy submits to approval queue and returns approval ID.
func TestStory148_ProposePolicySubmitsAndReturnsApprovalID(t *testing.T) {
	ts, tok, env := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      203,
		Method:  "tools/call",
		Params: map[string]any{
			"name": "propose_policy",
			"arguments": map[string]any{
				"name":        "my-proposed-policy",
				"description": "A test policy proposal",
				"rules": []any{
					map[string]any{
						"match":  map[string]any{"operations": []any{"list_emails"}},
						"action": "allow",
					},
				},
			},
		},
	})

	if resp.Error != nil {
		t.Fatalf("story 148: unexpected error: %v", resp.Error)
	}

	// Verify it's in the approval queue.
	pending, err := env.Approval.ListPending()
	if err != nil {
		t.Fatalf("story 148: list pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("story 148: expected 1 pending approval, got %d", len(pending))
	}
	if pending[0].Operation != "propose_policy" {
		t.Fatalf("story 148: expected propose_policy operation, got %q", pending[0].Operation)
	}

	// Verify the response text contains the approval ID.
	content, ok := resp.Result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("story 148: expected content in result")
	}
	block, ok := content[0].(map[string]any)
	if !ok {
		t.Fatal("story 148: expected content block")
	}
	text, _ := block["text"].(string)

	if !strings.Contains(text, pending[0].ID) {
		t.Fatalf("story 148: expected approval ID %q in response, got %q", pending[0].ID, text)
	}
	if !strings.Contains(text, "Approval ID") {
		t.Fatalf("story 148: expected 'Approval ID' label in response, got %q", text)
	}

	// Verify the request data contains the proposed rules.
	reqData := pending[0].RequestData
	if reqData["name"] != "my-proposed-policy" {
		t.Fatalf("story 148: expected proposal name 'my-proposed-policy', got %v", reqData["name"])
	}
	if reqData["description"] != "A test policy proposal" {
		t.Fatalf("story 148: expected description, got %v", reqData["description"])
	}
}

func TestMalformedJSONRPC(t *testing.T) {
	env := testenv.New(t)
	role := env.SetupConnectionAndRole(t, "test-conn", "read-only")
	plaintext := env.CreateToken(t, role.ID)

	srv := mcp.NewServer(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Send invalid JSON body.
	httpReq, err := http.NewRequest("POST", ts.URL, bytes.NewReader([]byte("{this is not json")))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+plaintext)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	var rpcResp jsonRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if rpcResp.Error == nil {
		t.Fatal("expected JSON-RPC error for malformed JSON body")
	}
	if rpcResp.Error.Code != -32700 {
		t.Fatalf("expected parse error code -32700, got %d", rpcResp.Error.Code)
	}
	if !strings.Contains(rpcResp.Error.Message, "parse error") {
		t.Fatalf("expected error message to contain 'parse error', got %q", rpcResp.Error.Message)
	}
}

// --- Story 140: MCP approval_required returns immediately with approval ID ---
func TestStory140_MCPApprovalReturnsImmediatelyWithID(t *testing.T) {
	env := testenv.New(t)

	pol, err := env.Policies.Create("mcp-approval-pol", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "approval_required",
			},
		},
		"default_action": "allow",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	err = env.Connections.Add("mcp-appr-conn", "mock", "MCP Approval", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}
	role, err := env.Roles.Create("mcp-appr-role", []roles.Binding{
		{ConnectionID: "mcp-appr-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	result, err := env.Tokens.Create(&tokens.CreateRequest{Name: "mcp-appr-tok", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	srv := mcp.NewServer(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp := doRPC(t, ts, result.PlaintextToken, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      300,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "send_email",
			"arguments": map[string]any{"to": []string{"bob@company.com"}, "subject": "Urgent", "body": "Please review"},
		},
	})

	if resp.Error != nil {
		t.Fatalf("story 140: unexpected error: %v", resp.Error)
	}

	// Verify response contains approval text and an approval ID.
	content, ok := resp.Result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("story 140: expected content in result")
	}
	block := content[0].(map[string]any)
	text, _ := block["text"].(string)

	if !strings.Contains(text, "approval") && !strings.Contains(text, "Approval") {
		t.Fatalf("story 140: expected 'approval' in response text, got %q", text)
	}
	if !strings.Contains(text, "Approval ID") {
		t.Fatalf("story 140: expected 'Approval ID' in response, got %q", text)
	}

	// Verify the item exists in the queue.
	pending, err := env.Approval.ListPending()
	if err != nil {
		t.Fatalf("story 140: list pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("story 140: expected 1 pending, got %d", len(pending))
	}
	if pending[0].Operation != "send_email" {
		t.Fatalf("story 140: expected send_email operation, got %q", pending[0].Operation)
	}

	// Verify the approval ID from the queue is in the response text.
	if !strings.Contains(text, pending[0].ID) {
		t.Fatalf("story 140: expected approval ID %q in response, got %q", pending[0].ID, text)
	}
}

// --- Story 296: Agent inspects its own policy via get_my_policy with rule content ---
func TestStory296_GetMyPolicyReturnsRuleContent(t *testing.T) {
	env := testenv.New(t)

	// Create a policy with specific rules we can verify.
	pol, err := env.Policies.Create("detailed-policy", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails", "read_email"}},
				"action": "allow",
			},
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "sending restricted",
			},
		},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	err = env.Connections.Add("policy-conn", "mock", "Policy Test", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}
	role, err := env.Roles.Create("policy-role", []roles.Binding{
		{ConnectionID: "policy-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	result, err := env.Tokens.Create(&tokens.CreateRequest{Name: "policy-tok", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	srv := mcp.NewServer(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp := doRPC(t, ts, result.PlaintextToken, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      301,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "get_my_policy",
			"arguments": map[string]any{},
		},
	})

	if resp.Error != nil {
		t.Fatalf("story 296: unexpected error: %v", resp.Error)
	}

	content, ok := resp.Result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("story 296: expected content in result")
	}
	block := content[0].(map[string]any)
	text, _ := block["text"].(string)

	// Verify the response contains specific rule operations and actions.
	if !strings.Contains(text, "list_emails") {
		t.Fatalf("story 296: expected 'list_emails' in policy, got %q", text)
	}
	if !strings.Contains(text, "read_email") {
		t.Fatalf("story 296: expected 'read_email' in policy, got %q", text)
	}
	if !strings.Contains(text, "send_email") {
		t.Fatalf("story 296: expected 'send_email' in policy, got %q", text)
	}
	if !strings.Contains(text, "deny") {
		t.Fatalf("story 296: expected 'deny' action in policy, got %q", text)
	}
	if !strings.Contains(text, "allow") {
		t.Fatalf("story 296: expected 'allow' action in policy, got %q", text)
	}
	if !strings.Contains(text, "sending restricted") {
		t.Fatalf("story 296: expected reason 'sending restricted' in policy, got %q", text)
	}
	if !strings.Contains(text, "detailed-policy") {
		t.Fatalf("story 296: expected policy name 'detailed-policy', got %q", text)
	}
	if !strings.Contains(text, "policy-conn") {
		t.Fatalf("story 296: expected connection ID 'policy-conn', got %q", text)
	}
}

// --- Story 144 extended: tools/list includes connector operations with correct schemas ---
func TestStory144_Extended_ToolsSchemasVerification(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      302,
		Method:  "tools/list",
	})

	if resp.Error != nil {
		t.Fatalf("story 144 ext: unexpected error: %v", resp.Error)
	}

	tools, ok := resp.Result["tools"].([]any)
	if !ok {
		t.Fatal("story 144 ext: expected tools array")
	}

	// Build a map of tool name -> tool definition.
	toolMap := make(map[string]map[string]any)
	for _, tool := range tools {
		tm, ok := tool.(map[string]any)
		if !ok {
			continue
		}
		name, _ := tm["name"].(string)
		toolMap[name] = tm
	}

	// Verify list_emails schema.
	listTool, ok := toolMap["list_emails"]
	if !ok {
		t.Fatal("story 144 ext: missing 'list_emails' tool")
	}
	listSchema, ok := listTool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatal("story 144 ext: missing inputSchema for list_emails")
	}
	listProps, ok := listSchema["properties"].(map[string]any)
	if !ok {
		t.Fatal("story 144 ext: missing properties in list_emails schema")
	}
	if _, ok := listProps["query"]; !ok {
		t.Fatal("story 144 ext: list_emails missing 'query' param")
	}
	if _, ok := listProps["max_results"]; !ok {
		t.Fatal("story 144 ext: list_emails missing 'max_results' param")
	}

	// Verify send_email schema.
	sendTool, ok := toolMap["send_email"]
	if !ok {
		t.Fatal("story 144 ext: missing 'send_email' tool")
	}
	sendSchema, ok := sendTool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatal("story 144 ext: missing inputSchema for send_email")
	}
	sendProps, ok := sendSchema["properties"].(map[string]any)
	if !ok {
		t.Fatal("story 144 ext: missing properties in send_email schema")
	}
	if _, ok := sendProps["to"]; !ok {
		t.Fatal("story 144 ext: send_email missing 'to' param")
	}
	if _, ok := sendProps["subject"]; !ok {
		t.Fatal("story 144 ext: send_email missing 'subject' param")
	}
	if _, ok := sendProps["body"]; !ok {
		t.Fatal("story 144 ext: send_email missing 'body' param")
	}

	// Verify 'to' is required.
	sendRequired, ok := sendSchema["required"].([]any)
	if !ok {
		t.Fatal("story 144 ext: missing required array in send_email schema")
	}
	foundToRequired := false
	for _, r := range sendRequired {
		if r == "to" {
			foundToRequired = true
		}
	}
	if !foundToRequired {
		t.Fatalf("story 144 ext: 'to' should be required for send_email, required=%v", sendRequired)
	}

	// Verify read_email has message_id.
	readTool, ok := toolMap["read_email"]
	if !ok {
		t.Fatal("story 144 ext: missing 'read_email' tool")
	}
	readSchema := readTool["inputSchema"].(map[string]any)
	readProps := readSchema["properties"].(map[string]any)
	if _, ok := readProps["message_id"]; !ok {
		t.Fatal("story 144 ext: read_email missing 'message_id' param")
	}

	// Verify message_id is required.
	readRequired, ok := readSchema["required"].([]any)
	if !ok {
		t.Fatal("story 144 ext: missing required array in read_email schema")
	}
	foundMsgIdRequired := false
	for _, r := range readRequired {
		if r == "message_id" {
			foundMsgIdRequired = true
		}
	}
	if !foundMsgIdRequired {
		t.Fatalf("story 144 ext: 'message_id' should be required for read_email, required=%v", readRequired)
	}
}

// Test get_policy_schema returns complete schema with all match fields.
func TestGetPolicySchema(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      300,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      "get_policy_schema",
			"arguments": map[string]any{},
		},
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	content, ok := resp.Result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("expected content in result")
	}
	block := content[0].(map[string]any)
	text, _ := block["text"].(string)

	// Verify schema is organized by scope with per-scope operations and match fields.
	for _, scope := range []string{
		"gmail", "llm", "http_proxy", "drive", "calendar", "people",
		"sheets", "docs", "ec2", "s3", "lambda", "ses", "dynamodb", "hyperstack",
	} {
		if !strings.Contains(text, `"`+scope+`"`) {
			t.Errorf("schema missing scope %q", scope)
		}
	}

	// Verify key match fields appear under their respective scopes.
	for _, field := range []string{
		"from", "to", "labels", "subject_contains",
		"model", "providers", "max_tokens", "max_cost",
		"path", "body_contains",
		"instance_type", "region", "max_count", "ami", "ports", "cidr",
		"bucket", "key_prefix",
		"calendar_id", "attendee",
		"spreadsheet_id", "range_pattern",
		"document_id", "title_contains",
		"table_name", "function_name",
		"flavor", "max_vms",
		"filter_exclude", "redact_patterns",
	} {
		if !strings.Contains(text, field) {
			t.Errorf("schema missing field %q", field)
		}
	}
}

// TestToolsListIncludesAllGoogleOps verifies that tools/list returns all 36
// operations from the mock connector (which now mirrors the real Google
// connector's operation set: 13 Gmail + 23 new Google ops).
func TestToolsListIncludesAllGoogleOps(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      400,
		Method:  "tools/list",
	})

	if resp.Error != nil {
		t.Fatalf("tools/list error: %v", resp.Error)
	}

	tools, ok := resp.Result["tools"].([]any)
	if !ok {
		t.Fatal("expected tools array in result")
	}

	toolNames := make(map[string]bool)
	for _, tool := range tools {
		tm, ok := tool.(map[string]any)
		if !ok {
			continue
		}
		name, _ := tm["name"].(string)
		toolNames[name] = true
	}

	// Verify Drive operations appear (dots normalized to underscores in MCP).
	driveOps := []string{
		"drive_list_files", "drive_get_file", "drive_download_file",
		"drive_upload_file", "drive_share_file",
	}
	for _, op := range driveOps {
		if !toolNames[op] {
			t.Errorf("missing Drive tool %q in tools/list", op)
		}
	}

	// Verify Calendar operations.
	calOps := []string{
		"calendar_list_events", "calendar_get_event", "calendar_create_event",
		"calendar_update_event", "calendar_delete_event",
	}
	for _, op := range calOps {
		if !toolNames[op] {
			t.Errorf("missing Calendar tool %q in tools/list", op)
		}
	}

	// Verify People operations.
	peopleOps := []string{
		"people_list_contacts", "people_get_contact", "people_create_contact",
		"people_update_contact", "people_delete_contact",
	}
	for _, op := range peopleOps {
		if !toolNames[op] {
			t.Errorf("missing People tool %q in tools/list", op)
		}
	}

	// Verify Sheets operations.
	sheetsOps := []string{
		"sheets_get_spreadsheet", "sheets_read_range",
		"sheets_write_range", "sheets_create_spreadsheet",
	}
	for _, op := range sheetsOps {
		if !toolNames[op] {
			t.Errorf("missing Sheets tool %q in tools/list", op)
		}
	}

	// Verify Docs operations.
	docsOps := []string{
		"docs_get_document", "docs_list_documents",
		"docs_create_document", "docs_update_document",
	}
	for _, op := range docsOps {
		if !toolNames[op] {
			t.Errorf("missing Docs tool %q in tools/list", op)
		}
	}

	// Built-in tools (4) + connector ops (36) = at least 40.
	if len(tools) < 40 {
		t.Errorf("expected at least 40 tools (4 builtin + 36 connector), got %d", len(tools))
	}
}

// TestToolsListGoogleOpsHaveCorrectSchemas verifies that the new Google
// operations have proper inputSchema with required fields and properties.
func TestToolsListGoogleOpsHaveCorrectSchemas(t *testing.T) {
	ts, tok, _ := setup(t)

	resp := doRPC(t, ts, tok, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      401,
		Method:  "tools/list",
	})

	if resp.Error != nil {
		t.Fatalf("tools/list error: %v", resp.Error)
	}

	tools, ok := resp.Result["tools"].([]any)
	if !ok {
		t.Fatal("expected tools array")
	}

	toolMap := make(map[string]map[string]any)
	for _, tool := range tools {
		tm, ok := tool.(map[string]any)
		if !ok {
			continue
		}
		name, _ := tm["name"].(string)
		toolMap[name] = tm
	}

	// Verify drive_get_file has file_id as required.
	driveGetFile, ok := toolMap["drive_get_file"]
	if !ok {
		t.Fatal("missing drive_get_file tool")
	}
	schema, ok := driveGetFile["inputSchema"].(map[string]any)
	if !ok {
		t.Fatal("missing inputSchema for drive_get_file")
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatal("missing properties in drive_get_file schema")
	}
	if _, ok := props["file_id"]; !ok {
		t.Fatal("drive_get_file missing 'file_id' property")
	}

	// Verify sheets_read_range has spreadsheet_id and range as required.
	sheetsRead, ok := toolMap["sheets_read_range"]
	if !ok {
		t.Fatal("missing sheets_read_range tool")
	}
	schema = sheetsRead["inputSchema"].(map[string]any)
	props = schema["properties"].(map[string]any)
	if _, ok := props["spreadsheet_id"]; !ok {
		t.Fatal("sheets_read_range missing 'spreadsheet_id' property")
	}
	if _, ok := props["range"]; !ok {
		t.Fatal("sheets_read_range missing 'range' property")
	}
	required, ok := schema["required"].([]any)
	if !ok {
		t.Fatal("sheets_read_range missing required array")
	}
	reqSet := make(map[string]bool)
	for _, r := range required {
		reqSet[r.(string)] = true
	}
	if !reqSet["spreadsheet_id"] {
		t.Fatal("sheets_read_range: spreadsheet_id should be required")
	}
	if !reqSet["range"] {
		t.Fatal("sheets_read_range: range should be required")
	}

	// Verify calendar_create_event has summary, start, end as required.
	calCreate, ok := toolMap["calendar_create_event"]
	if !ok {
		t.Fatal("missing calendar_create_event tool")
	}
	schema = calCreate["inputSchema"].(map[string]any)
	props = schema["properties"].(map[string]any)
	for _, field := range []string{"summary", "start", "end"} {
		if _, ok := props[field]; !ok {
			t.Fatalf("calendar_create_event missing %q property", field)
		}
	}
	required = schema["required"].([]any)
	reqSet = make(map[string]bool)
	for _, r := range required {
		reqSet[r.(string)] = true
	}
	for _, field := range []string{"summary", "start", "end"} {
		if !reqSet[field] {
			t.Fatalf("calendar_create_event: %q should be required", field)
		}
	}
}
