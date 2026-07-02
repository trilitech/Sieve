package api_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/connectors/httpproxy"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/tokens"
)

// TestProxyApprovalCreatesRecord proves an approval-required decision on a proxy
// request actually SUBMITS an approval record. Previously the proxy path returned
// 429 WITHOUT calling approval.Submit, so the agent was told to wait for an
// approval that never existed (unapprovable by construction). Non-blocking, like
// MCP: the 429 response carries the approval id + poll URL.
func TestProxyApprovalCreatesRecord(t *testing.T) {
	env := testenv.New(t)

	// Upstream the proxy would forward to — never reached, approval gates first.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	env.Registry.Register(httpproxy.Meta, httpproxy.Factory)
	if err := env.Connections.Add("proxy-conn", "http_proxy", "Proxy", map[string]any{
		"target_url":  target.URL,
		"auth_header": "x-api-key",
		"auth_value":  "sk-secret",
	}); err != nil {
		t.Fatal(err)
	}
	role, err := env.Roles.Create("proxy-role", []roles.Binding{{ConnectionID: "proxy-conn"}})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := env.Tokens.Create(&tokens.CreateRequest{Name: "t", RoleID: role.ID})
	if err != nil {
		t.Fatal(err)
	}
	// Require approval for proxy requests on this connection.
	cedar := fmt.Sprintf("@approval(\"required\")\npermit(principal in Sieve::Role::%q, action, resource in Sieve::Connection::\"proxy-conn\");", role.ID)
	if _, err := env.IAM.CreatePolicy("proxy-approval", "", cedar, true); err != nil {
		t.Fatal(err)
	}
	if err := env.Settings.Set("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/proxy/proxy-conn/v1/messages", strings.NewReader(`{"model":"claude"}`))
	req.Header.Set("Authorization", "Bearer "+tok.PlaintextToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429 for approval_required, got %d (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(body, "approval_id") {
		t.Errorf("response should carry the approval id so the agent can poll: %s", body)
	}
	pending, err := env.Approval.ListPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("proxy approval must create exactly one approval record, got %d", len(pending))
	}
}
