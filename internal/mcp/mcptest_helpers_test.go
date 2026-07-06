package mcp_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trilitech/Sieve/internal/mcp"
	"github.com/trilitech/Sieve/internal/testing/testenv"
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
	Result  map[string]any `json:"result"`
	Error   map[string]any `json:"error"`
}

// doRPC posts a JSON-RPC request to the MCP endpoint with a bearer token and
// returns the decoded response.
func doRPC(t *testing.T, ts *httptest.Server, token string, req jsonRPCRequest) jsonRPCResponse {
	t.Helper()
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequest(http.MethodPost, ts.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out jsonRPCResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

// setup builds an IAM-seeded MCP server over a mock connection and returns the
// httptest server, an agent token, and the env.
func setup(t *testing.T) (*httptest.Server, string, *testenv.Env) {
	t.Helper()
	env := testenv.New(t)
	role := env.SetupConnectionAndRole(t, "test-conn")
	tok := env.CreateToken(t, role.ID)
	srv := mcp.NewServer(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, tok, env
}
