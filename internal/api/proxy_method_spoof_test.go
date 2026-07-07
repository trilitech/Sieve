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

// TestProxyMethodSpoofDoesNotBypassPolicy proves the http_proxy policy decision
// can't be fooled by the agent-controlled request body. The rule permits only
// http_method == "GET". A real GET is allowed; a real POST carrying a spoof body
// {"method":"GET"} must be DENIED — before the fix, the body field overwrote the
// trusted method in policyParams, so the POST was judged as a GET and forwarded.
func TestProxyMethodSpoofDoesNotBypassPolicy(t *testing.T) {
	env := testenv.New(t)

	var upstreamMethods []string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamMethods = append(upstreamMethods, r.Method)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(target.Close)

	env.Registry.Register(httpproxy.Meta, httpproxy.Factory)
	if err := env.Connections.Add("proxy-conn", "http_proxy", "Proxy", map[string]any{
		"target_url":         target.URL,
		"auth_header":        "x-api-key",
		"auth_value":         "sk-secret",
		"outbound_allowlist": []string{"127.0.0.0/8"}, // allow the loopback test upstream
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
	// Permit ONLY when the HTTP method is GET.
	cedar := fmt.Sprintf(`permit(principal in Sieve::Role::%q, action, resource in Sieve::Connection::"proxy-conn") when { context.http_method == "GET" };`, role.ID)
	if _, err := env.IAM.CreatePolicy("get-only", "", cedar, true); err != nil {
		t.Fatal(err)
	}
	if err := env.Settings.Set("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	// A real GET is permitted and forwarded.
	getReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/proxy/proxy-conn/v1/thing", nil)
	getReq.Header.Set("Authorization", "Bearer "+tok.PlaintextToken)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatal(err)
	}
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("real GET should be allowed, got %d", getResp.StatusCode)
	}

	// A real POST carrying a spoof body {"method":"GET"} must be DENIED — the
	// body must not override the trusted method used for the decision.
	postReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/proxy/proxy-conn/v1/thing", strings.NewReader(`{"method":"GET"}`))
	postReq.Header.Set("Authorization", "Bearer "+tok.PlaintextToken)
	postResp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		t.Fatal(err)
	}
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST with spoof body {\"method\":\"GET\"} must be denied (403), got %d — policy bypass", postResp.StatusCode)
	}

	// The upstream must never have seen the spoofed POST.
	for _, m := range upstreamMethods {
		if m == http.MethodPost {
			t.Fatalf("spoofed POST reached the upstream — policy bypass; upstream saw methods %v", upstreamMethods)
		}
	}
}
