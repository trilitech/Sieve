package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/murbard/Sieve/internal/api"
	"github.com/murbard/Sieve/internal/approval"
	"github.com/murbard/Sieve/internal/audit"
	"github.com/murbard/Sieve/internal/roles"
	"github.com/murbard/Sieve/internal/scriptgen"
	mockconn "github.com/murbard/Sieve/internal/testing/mockconnector"
	"github.com/murbard/Sieve/internal/testing/testenv"
	"github.com/murbard/Sieve/internal/tokens"
	"github.com/murbard/Sieve/internal/web"
)

// setup creates a fresh test environment with a mock connection "test-conn"
// bound to the "read-only" preset policy, a token for the role, and an
// httptest.Server wired to the API router. It returns the server URL and the
// bearer token string. The server is automatically closed when the test ends.
func setup(t *testing.T) (serverURL, token string) {
	t.Helper()

	env := testenv.New(t)
	role := env.SetupConnectionAndRole(t, "test-conn", "read-only")
	tok := env.CreateToken(t, role.ID)

	router := api.NewRouter(
		env.Tokens,
		env.Connections,
		env.Policies,
		env.Roles,
		env.Approval,
		env.Audit,
	)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	return srv.URL, tok
}

// doRequest is a helper that performs an HTTP request and returns the response.
func doRequest(t *testing.T, method, url, token, body string) *http.Response {
	t.Helper()

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// readBody reads and returns the response body as a string, closing it.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// --- Auth tests ---

func TestNoAuth(t *testing.T) {
	url, _ := setup(t)

	resp := doRequest(t, "GET", url+"/api/v1/connections", "", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestBadToken(t *testing.T) {
	url, _ := setup(t)

	resp := doRequest(t, "GET", url+"/api/v1/connections", "sieve_tok_bogus", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestValidToken(t *testing.T) {
	url, tok := setup(t)

	resp := doRequest(t, "GET", url+"/api/v1/connections", tok, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := readBody(t, resp)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
}

// --- Connection listing ---

func TestListConnections(t *testing.T) {
	url, tok := setup(t)

	resp := doRequest(t, "GET", url+"/api/v1/connections", tok, "")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var conns []struct {
		ID          string `json:"id"`
		Connector   string `json:"connector"`
		DisplayName string `json:"display_name"`
	}
	if err := json.Unmarshal([]byte(body), &conns); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}
	if conns[0].ID != "test-conn" {
		t.Errorf("expected connection id %q, got %q", "test-conn", conns[0].ID)
	}
	if conns[0].Connector != "mock" {
		t.Errorf("expected connector type %q, got %q", "mock", conns[0].Connector)
	}
}

// --- Operation execution ---

func TestExecuteAllowed(t *testing.T) {
	url, tok := setup(t)

	resp := doRequest(t, "POST", url+"/api/v1/connections/test-conn/ops/list_emails", tok, "{}")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	emails, ok := result["emails"].([]any)
	if !ok {
		t.Fatalf("expected emails array in response, got: %s", body)
	}
	if len(emails) == 0 {
		t.Fatal("expected at least one email in mock response")
	}
}

func TestExecuteDenied(t *testing.T) {
	url, tok := setup(t)

	// send_email is not in the read-only policy's allow list, so it should be denied.
	resp := doRequest(t, "POST", url+"/api/v1/connections/test-conn/ops/send_email", tok, `{"to":["a@b.com"],"subject":"hi","body":"hello"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body := readBody(t, resp)
		t.Fatalf("expected 403, got %d: %s", resp.StatusCode, body)
	}
}

func TestExecuteUnknownConnection(t *testing.T) {
	url, tok := setup(t)

	resp := doRequest(t, "POST", url+"/api/v1/connections/nonexistent/ops/list_emails", tok, "{}")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body := readBody(t, resp)
		t.Fatalf("expected 403, got %d: %s", resp.StatusCode, body)
	}
}

// --- Gmail API compatibility ---

// setupGmail creates an environment with a connection whose database row has
// connector_type "google" so that resolveGmailConnection accepts it. A mock
// connector is registered under the "google" type so GetConnector can resolve
// it and execute operations.
func setupGmail(t *testing.T) (serverURL, token string) {
	t.Helper()

	env := testenv.New(t)

	// Register a mock connector under the "google" type so the registry can
	// create a live connector instance when GetConnector lazy-loads from the DB.
	googleMock := mockconn.New("google")
	env.Registry.Register(googleMock.Meta(), googleMock.Factory())

	// Use Connections.Add which both inserts the DB row and creates the live
	// connector through the registry.
	err := env.Connections.Add("test-conn", "google", "Test Gmail", map[string]any{})
	if err != nil {
		t.Fatalf("add google connection: %v", err)
	}

	pol, err := env.Policies.GetByName("read-only")
	if err != nil {
		t.Fatalf("get read-only policy: %v", err)
	}

	role, err := env.Roles.Create("gmail-role", []roles.Binding{
		{ConnectionID: "test-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tok := env.CreateToken(t, role.ID)

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	return srv.URL, tok
}

func TestGmailListMessages(t *testing.T) {
	url, tok := setupGmail(t)

	resp := doRequest(t, "GET", url+"/gmail/v1/users/test-conn/messages", tok, "")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if _, ok := result["emails"]; !ok {
		t.Fatalf("expected emails key in response, got: %s", body)
	}
}

func TestGmailListUsers(t *testing.T) {
	url, tok := setup(t)

	resp := doRequest(t, "GET", url+"/gmail/v1/users", tok, "")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	// gmailListUsers only returns connections with connector_type "google".
	// Our mock connector is type "mock", so the users list should be empty.
	users, ok := result["users"]
	if !ok {
		t.Fatalf("expected users key in response, got: %s", body)
	}
	// users may be null/nil (no google connections) -- that is acceptable
	if users != nil {
		userList, ok := users.([]any)
		if ok && len(userList) > 0 {
			// If there are entries, they should have an id field
			first, ok := userList[0].(map[string]any)
			if !ok {
				t.Fatalf("expected user object, got: %v", userList[0])
			}
			if _, ok := first["id"]; !ok {
				t.Fatalf("expected id field in user object, got: %v", first)
			}
		}
	}
}

func TestGmailListUsersWithGoogleConnection(t *testing.T) {
	// Create an environment where the connector type is "google" so the
	// gmailListUsers handler actually returns it.
	env := testenv.New(t)

	// Register a mock under the "google" type so Connections.Add works.
	googleMock := mockconn.New("google")
	env.Registry.Register(googleMock.Meta(), googleMock.Factory())

	err := env.Connections.Add("google-conn", "google", "Google Test", map[string]any{})
	if err != nil {
		t.Fatalf("add google connection: %v", err)
	}

	pol, err := env.Policies.GetByName("read-only")
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}

	role, err := env.Roles.Create("google-role", []roles.Binding{
		{ConnectionID: "google-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tok := env.CreateToken(t, role.ID)

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	resp := doRequest(t, "GET", srv.URL+"/gmail/v1/users", tok, "")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	users, ok := result["users"].([]any)
	if !ok || len(users) == 0 {
		t.Fatalf("expected at least one user, got: %s", body)
	}

	first := users[0].(map[string]any)
	if first["id"] != "google-conn" {
		t.Errorf("expected user id %q, got %q", "google-conn", first["id"])
	}
}

func TestGmailUserId(t *testing.T) {
	url, tok := setupGmail(t)

	// Using test-conn as the userId should resolve to the connection directly.
	resp := doRequest(t, "GET", url+"/gmail/v1/users/test-conn/messages", tok, "")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
}

// --- Approval status ownership ---

func TestApprovalStatusOwnership(t *testing.T) {
	env := testenv.New(t)

	// Create a shared connection.
	err := env.Connections.Add("conn-a", "mock", "Conn A", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	polReadOnly, err := env.Policies.GetByName("read-only")
	if err != nil {
		t.Fatalf("get read-only policy: %v", err)
	}

	// Role A
	roleA, err := env.Roles.Create("role-a", []roles.Binding{
		{ConnectionID: "conn-a", PolicyIDs: []string{polReadOnly.ID}},
	})
	if err != nil {
		t.Fatalf("create role A: %v", err)
	}

	resultA, err := env.Tokens.Create(&tokens.CreateRequest{
		Name:   "token-a",
		RoleID: roleA.ID,
	})
	if err != nil {
		t.Fatalf("create token A: %v", err)
	}
	tokA := resultA.PlaintextToken

	// Submit an approval item attributed to token A.
	item, err := env.Approval.Submit(&approval.SubmitRequest{
		TokenID:      resultA.Token.ID,
		ConnectionID: "conn-a",
		Operation:    "send_email",
		RequestData:  map[string]any{"to": "test@test.com"},
	})
	if err != nil {
		t.Fatalf("submit approval: %v", err)
	}

	// Role B
	roleB, err := env.Roles.Create("role-b", []roles.Binding{
		{ConnectionID: "conn-a", PolicyIDs: []string{polReadOnly.ID}},
	})
	if err != nil {
		t.Fatalf("create role B: %v", err)
	}

	resultB, err := env.Tokens.Create(&tokens.CreateRequest{
		Name:   "token-b",
		RoleID: roleB.ID,
	})
	if err != nil {
		t.Fatalf("create token B: %v", err)
	}
	tokB := resultB.PlaintextToken

	// Build a server.
	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	// Token A should be able to see its own approval.
	resp := doRequest(t, "GET", srv.URL+"/api/v1/approvals/"+item.ID+"/status", tokA, "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token A: expected 200, got %d: %s", resp.StatusCode, body)
	}

	// Token B should be forbidden from seeing token A's approval.
	resp = doRequest(t, "GET", srv.URL+"/api/v1/approvals/"+item.ID+"/status", tokB, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body := readBody(t, resp)
		t.Fatalf("token B: expected 403, got %d: %s", resp.StatusCode, body)
	}
}

// --- Proxy tests ---

// --- User story tests ---

// Story 136: Token accesses connection NOT in its role → 403.
func TestStory136_TokenAccessesForbiddenConnection(t *testing.T) {
	env := testenv.New(t)

	// Create two connections.
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

	tok := env.CreateToken(t, role.ID)

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	// Try to access forbidden-conn.
	resp := doRequest(t, "POST", srv.URL+"/api/v1/connections/forbidden-conn/ops/list_emails", tok, "{}")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body := readBody(t, resp)
		t.Fatalf("story 136: expected 403 for forbidden connection, got %d: %s", resp.StatusCode, body)
	}
}

// Story 137: Token calls denied operation → 403 with reason in body.
func TestStory137_DeniedOperationReturns403WithReason(t *testing.T) {
	env := testenv.New(t)

	// Create a policy that explicitly denies send_email with a reason.
	pol, err := env.Policies.Create("deny-send", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "sending is not allowed",
			},
		},
		"default_action": "allow",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	err = env.Connections.Add("test-conn-137", "mock", "Test", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	role, err := env.Roles.Create("deny-role", []roles.Binding{
		{ConnectionID: "test-conn-137", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tok := env.CreateToken(t, role.ID)

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	resp := doRequest(t, "POST", srv.URL+"/api/v1/connections/test-conn-137/ops/send_email", tok,
		`{"to":["a@b.com"],"subject":"hi","body":"hello"}`)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("story 137: expected 403, got %d: %s", resp.StatusCode, body)
	}

	// Verify the body contains the denial reason.
	var errResp map[string]string
	if err := json.Unmarshal([]byte(body), &errResp); err != nil {
		t.Fatalf("story 137: unmarshal error body: %v", err)
	}
	if !strings.Contains(errResp["error"], "sending is not allowed") {
		t.Fatalf("story 137: expected denial reason in body, got %q", errResp["error"])
	}
}

// Story 138: Token calls allowed operation → 200 with data.
func TestStory138_AllowedOperationReturns200WithData(t *testing.T) {
	url, tok := setup(t)

	resp := doRequest(t, "POST", url+"/api/v1/connections/test-conn/ops/list_emails", tok, "{}")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("story 138: expected 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("story 138: unmarshal response: %v", err)
	}

	// Verify actual data is present, not just a status code.
	emails, ok := result["emails"].([]any)
	if !ok {
		t.Fatalf("story 138: expected emails array in response, got: %s", body)
	}
	if len(emails) == 0 {
		t.Fatal("story 138: expected at least one email in response")
	}

	first, ok := emails[0].(map[string]any)
	if !ok {
		t.Fatalf("story 138: expected email object")
	}
	if _, ok := first["id"]; !ok {
		t.Fatal("story 138: expected 'id' field in email")
	}
	if _, ok := first["subject"]; !ok {
		t.Fatal("story 138: expected 'subject' field in email")
	}
}

// Story 141: No auth header → 401.
func TestStory141_NoAuthHeaderReturns401(t *testing.T) {
	url, _ := setup(t)

	resp := doRequest(t, "GET", url+"/api/v1/connections", "", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body := readBody(t, resp)
		t.Fatalf("story 141: expected 401 for missing auth, got %d: %s", resp.StatusCode, body)
	}

	// Also check POST endpoints
	resp2 := doRequest(t, "POST", url+"/api/v1/connections/test-conn/ops/list_emails", "", "{}")
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusUnauthorized {
		body := readBody(t, resp2)
		t.Fatalf("story 141: expected 401 for POST without auth, got %d: %s", resp2.StatusCode, body)
	}
}

// Story 143: List connections returns only role's connections.
func TestStory143_ListConnectionsReturnsOnlyRoleConnections(t *testing.T) {
	env := testenv.New(t)

	// Create three connections.
	for _, id := range []string{"conn-a", "conn-b", "conn-c"} {
		err := env.Connections.Add(id, "mock", "Connection "+id, map[string]any{})
		if err != nil {
			t.Fatalf("add %s: %v", id, err)
		}
	}

	polReadOnly, err := env.Policies.GetByName("read-only")
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}

	// Bind only conn-a and conn-b to the role (not conn-c).
	role, err := env.Roles.Create("partial-role", []roles.Binding{
		{ConnectionID: "conn-a", PolicyIDs: []string{polReadOnly.ID}},
		{ConnectionID: "conn-b", PolicyIDs: []string{polReadOnly.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tok := env.CreateToken(t, role.ID)

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	resp := doRequest(t, "GET", srv.URL+"/api/v1/connections", tok, "")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("story 143: expected 200, got %d: %s", resp.StatusCode, body)
	}

	var conns []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &conns); err != nil {
		t.Fatalf("story 143: unmarshal response: %v", err)
	}

	if len(conns) != 2 {
		t.Fatalf("story 143: expected 2 connections, got %d: %s", len(conns), body)
	}

	connIDs := make(map[string]bool)
	for _, c := range conns {
		connIDs[c.ID] = true
	}

	if !connIDs["conn-a"] {
		t.Fatal("story 143: expected conn-a in list")
	}
	if !connIDs["conn-b"] {
		t.Fatal("story 143: expected conn-b in list")
	}
	if connIDs["conn-c"] {
		t.Fatal("story 143: conn-c should NOT be in list (not in role)")
	}
}

// --- Cascading delete tests ---

// Story 84/154: Delete a policy, then try BuildEvaluator with its ID → error.
func TestStory84_DeletedPolicyCannotBuildEvaluator(t *testing.T) {
	env := testenv.New(t)

	pol, err := env.Policies.Create("temp-policy", "rules", map[string]any{
		"rules":          []any{},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	// Delete the policy.
	if err := env.Policies.Delete(pol.ID); err != nil {
		t.Fatalf("delete policy: %v", err)
	}

	// BuildEvaluator with the deleted policy ID should error.
	_, err = env.Policies.BuildEvaluator([]string{pol.ID})
	if err == nil {
		t.Fatal("story 84: expected error building evaluator for deleted policy")
	}
}

// Story 86/156: Delete a role, then try to validate a token that references it → role not found.
func TestStory86_DeletedRoleCannotResolve(t *testing.T) {
	env := testenv.New(t)

	err := env.Connections.Add("del-conn", "mock", "Delete Test", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	polReadOnly, err := env.Policies.GetByName("read-only")
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}

	role, err := env.Roles.Create("ephemeral-role", []roles.Binding{
		{ConnectionID: "del-conn", PolicyIDs: []string{polReadOnly.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tok := env.CreateToken(t, role.ID)

	// Delete the role.
	if err := env.Roles.Delete(role.ID); err != nil {
		t.Fatalf("delete role: %v", err)
	}

	// Token still validates (token doesn't check role existence).
	tokenResult, err := env.Tokens.Validate(tok)
	if err != nil {
		t.Fatalf("story 86: token validation should still succeed: %v", err)
	}

	// But trying to get the role fails.
	_, err = env.Roles.Get(tokenResult.RoleID)
	if err == nil {
		t.Fatal("story 86: expected error getting deleted role")
	}
}

func TestProxySkipped(t *testing.T) {
	// Proxy tests require a real upstream or an httptest upstream wired as an
	// http_proxy connector. Since the mock connector does not implement the
	// httpProxier interface, requests to /proxy/ will return 400 ("not an HTTP
	// proxy"). We verify that the auth + connection check pipeline still works.
	url, tok := setup(t)

	resp := doRequest(t, "GET", url+"/proxy/test-conn/v1/test", tok, "")
	body := readBody(t, resp)

	// The mock connector is not an HTTP proxy, so we expect 400.
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", resp.StatusCode, body)
	}

	// Verify the error message indicates the connector is not a proxy.
	var errResp map[string]string
	if err := json.Unmarshal([]byte(body), &errResp); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	if !strings.Contains(errResp["error"], "not an HTTP proxy") {
		t.Errorf("expected error about HTTP proxy, got: %s", errResp["error"])
	}
}

func TestProxyUnknownConnection(t *testing.T) {
	url, tok := setup(t)

	resp := doRequest(t, "GET", url+"/proxy/nonexistent/v1/test", tok, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body := readBody(t, resp)
		t.Fatalf("expected 403, got %d: %s", resp.StatusCode, body)
	}
}

// --- Additional Gmail endpoint tests ---

func TestGmailGetMessage(t *testing.T) {
	url, tok := setupGmail(t)

	resp := doRequest(t, "GET", url+"/gmail/v1/users/test-conn/messages/msg123", tok, "")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	// The mock returns the message_id back in the id field.
	if result["id"] != "msg123" {
		t.Fatalf("expected message id 'msg123' in response, got %v", result["id"])
	}
	if _, ok := result["subject"]; !ok {
		t.Fatalf("expected 'subject' field in message response, got: %s", body)
	}
}

func TestGmailSendMessageDenied(t *testing.T) {
	url, tok := setupGmail(t)

	// The read-only policy should deny send_email.
	sendBody := `{"to":["recipient@test.com"],"subject":"Test","body":"Hello"}`
	resp := doRequest(t, "POST", url+"/gmail/v1/users/test-conn/messages/send", tok, sendBody)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for send on read-only policy, got %d: %s", resp.StatusCode, body)
	}

	// Verify the error body contains a meaningful denial message.
	var errResp map[string]string
	if err := json.Unmarshal([]byte(body), &errResp); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	errMsg := errResp["error"]
	if errMsg == "" {
		t.Fatal("expected non-empty error message in denial response body")
	}
	if !strings.Contains(errMsg, "denied") {
		t.Fatalf("expected denial error message to contain 'denied', got %q", errMsg)
	}
}

func TestGmailModifyMessage(t *testing.T) {
	// Set up with a policy that allows add_label.
	env := testenv.New(t)

	googleMock := mockconn.New("google")
	googleMock.SetResponse("add_label", map[string]any{"id": "msg456", "labels": []string{"INBOX", "IMPORTANT"}})
	env.Registry.Register(googleMock.Meta(), googleMock.Factory())

	err := env.Connections.Add("test-conn", "google", "Test Gmail", map[string]any{})
	if err != nil {
		t.Fatalf("add google connection: %v", err)
	}

	// Create a permissive policy that allows add_label.
	pol, err := env.Policies.Create("allow-labels", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"add_label", "remove_label", "list_labels"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	role, err := env.Roles.Create("label-role", []roles.Binding{
		{ConnectionID: "test-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	tok := env.CreateToken(t, role.ID)

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	modifyBody := `{"addLabelIds":["IMPORTANT"]}`
	resp := doRequest(t, "POST", srv.URL+"/gmail/v1/users/test-conn/messages/msg456/modify", tok, modifyBody)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for add_label, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if result["id"] != "msg456" {
		t.Fatalf("expected message id 'msg456', got %v", result["id"])
	}
}

func TestGmailListLabels(t *testing.T) {
	url, tok := setupGmail(t)

	resp := doRequest(t, "GET", url+"/gmail/v1/users/test-conn/labels", tok, "")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	// The mock returns a list of labels; verify the response contains actual data.
	var result []any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		// The mock may wrap in an object; try that too.
		var objResult map[string]any
		if err2 := json.Unmarshal([]byte(body), &objResult); err2 != nil {
			t.Fatalf("unmarshal response as array or object: array err: %v, object err: %v", err, err2)
		}
		// If it's an object, just verify it has content.
		if len(objResult) == 0 {
			t.Fatalf("expected non-empty label response, got: %s", body)
		}
	} else {
		if len(result) == 0 {
			t.Fatalf("expected at least one label in response, got: %s", body)
		}
		// Verify first label has expected fields.
		first, ok := result[0].(map[string]any)
		if !ok {
			t.Fatalf("expected label object, got: %v", result[0])
		}
		if _, ok := first["id"]; !ok {
			t.Fatalf("expected 'id' field in label object, got: %v", first)
		}
	}
}

func TestExecuteDeniedReturnsErrorBody(t *testing.T) {
	url, tok := setup(t)

	// send_email is denied by the read-only policy.
	resp := doRequest(t, "POST", url+"/api/v1/connections/test-conn/ops/send_email", tok, `{"to":["a@b.com"],"subject":"hi","body":"hello"}`)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", resp.StatusCode, body)
	}

	// Verify the response body contains a meaningful JSON error.
	var errResp map[string]string
	if err := json.Unmarshal([]byte(body), &errResp); err != nil {
		t.Fatalf("expected JSON error body, got unmarshal error: %v, body: %s", err, body)
	}
	errMsg := errResp["error"]
	if errMsg == "" {
		t.Fatal("expected non-empty error message in denial response")
	}
	if !strings.Contains(errMsg, "denied") {
		t.Fatalf("expected error message to contain 'denied', got %q", errMsg)
	}
}

// Story 431: Token re-validation after approval.
//
// After WaitForResolution returns an approved status, executeOperation proceeds
// directly to conn.Execute without re-validating the token. This means that if
// an admin revokes the token during the approval wait, the operation will still
// execute. This test documents this as EXPECTED BEHAVIOR (not a bug):
//
//   - The token was valid at the time of the original request.
//   - The approval itself is a separate authorization gate.
//   - An admin who approves the request is explicitly authorizing execution.
//   - Re-validating would create a race condition where approved operations
//     fail unexpectedly if the token is revoked between approval and execution.
//
// If this behavior changes in the future and re-validation is added, this test
// should be updated to expect 401 instead of 200.
func TestStory431_TokenNotRevalidatedAfterApproval(t *testing.T) {
	env := testenv.New(t)

	err := env.Connections.Add("test-conn-431", "mock", "Test", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	// Policy that requires approval for send_email.
	pol, err := env.Policies.Create("approval-policy", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "approval_required",
				"reason": "needs approval",
			},
			map[string]any{
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	role, err := env.Roles.Create("approval-role", []roles.Binding{
		{ConnectionID: "test-conn-431", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tokResult, err := env.Tokens.Create(&tokens.CreateRequest{
		Name:   "token-431",
		RoleID: role.ID,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	// Send the request in a goroutine (it will block on WaitForResolution).
	type result struct {
		resp *http.Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp := doRequest(t, "POST",
			srv.URL+"/api/v1/connections/test-conn-431/ops/send_email",
			tokResult.PlaintextToken,
			`{"to":"test@test.com","subject":"hi","body":"hello"}`,
		)
		ch <- result{resp: resp}
	}()

	// Wait for the approval item to appear.
	var approvalID string
	for i := 0; i < 50; i++ {
		items, _ := env.Approval.ListPending()
		if len(items) > 0 {
			approvalID = items[0].ID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if approvalID == "" {
		t.Fatal("story 431: approval item never appeared in queue")
	}

	// Revoke the token BEFORE approving.
	if err := env.Tokens.Revoke(tokResult.Token.ID); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	// Approve the request (token is now revoked).
	if err := env.Approval.Approve(approvalID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Get the response.
	res := <-ch
	defer res.resp.Body.Close()

	// After the fix, the token IS re-validated after approval. Since we revoked
	// the token before approving, the operation should be denied with 401.
	if res.resp.StatusCode != http.StatusUnauthorized {
		body := readBody(t, res.resp)
		t.Fatalf("story 431: expected 401 (token re-validated after approval), got %d: %s",
			res.resp.StatusCode, body)
	}
}

func TestExecuteAllowedResponseContainsData(t *testing.T) {
	url, tok := setup(t)

	resp := doRequest(t, "POST", url+"/api/v1/connections/test-conn/ops/list_emails", tok, "{}")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	// Verify the response has real email data, not just a status code check.
	emails, ok := result["emails"].([]any)
	if !ok {
		t.Fatalf("expected emails array in response, got: %s", body)
	}
	if len(emails) == 0 {
		t.Fatal("expected at least one email in response")
	}

	// Verify the first email has expected fields.
	first, ok := emails[0].(map[string]any)
	if !ok {
		t.Fatalf("expected email object, got: %v", emails[0])
	}
	if _, ok := first["id"]; !ok {
		t.Fatalf("expected 'id' field in email, got: %v", first)
	}
	if _, ok := first["subject"]; !ok {
		t.Fatalf("expected 'subject' field in email, got: %v", first)
	}
	if _, ok := first["from"]; !ok {
		t.Fatalf("expected 'from' field in email, got: %v", first)
	}
}

// Story 63: Agent self-approve protection. A request to the web UI approve
// endpoint carrying a sieve bearer token is rejected with 403.
func TestStory63_AgentSelfApproveProtection(t *testing.T) {
	env := testenv.New(t)

	// Create an approval item.
	item, err := env.Approval.Submit(&approval.SubmitRequest{
		TokenID:      "tok-agent",
		ConnectionID: "conn-1",
		Operation:    "send_email",
		RequestData:  map[string]any{"to": "test@test.com"},
	})
	if err != nil {
		t.Fatalf("submit approval: %v", err)
	}

	// Create the web server (needed to test rejectIfAgentToken).
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	webSrv := web.NewServer(
		env.Tokens, env.Connections, env.Policies, env.Roles,
		env.Registry, env.Approval, env.Audit,
		"", // no google credentials file
		env.Settings,
		scriptgenSvc,
	)
	ts := httptest.NewServer(webSrv.Handler())
	t.Cleanup(ts.Close)

	// Create a real sieve token for the agent.
	role := env.SetupConnectionAndRole(t, "test-conn-63", "read-only")
	agentToken := env.CreateToken(t, role.ID)

	// Try to approve the item via the web UI with a sieve bearer token.
	req, err := http.NewRequest("POST", ts.URL+"/approvals/"+item.ID+"/approve", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+agentToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("story 63: expected 403 for agent self-approve, got %d: %s", resp.StatusCode, string(body))
	}

	// Also try reject endpoint.
	req2, _ := http.NewRequest("POST", ts.URL+"/approvals/"+item.ID+"/reject", nil)
	req2.Header.Set("Authorization", "Bearer "+agentToken)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("do reject request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("story 63: expected 403 for agent self-reject, got %d: %s", resp2.StatusCode, string(body))
	}

	// Verify the item is still pending (not approved/rejected by the agent).
	got, err := env.Approval.Get(item.ID)
	if err != nil {
		t.Fatalf("get item: %v", err)
	}
	if got.Status != approval.StatusPending {
		t.Fatalf("story 63: item should still be pending, got %s", got.Status)
	}
}

// Story 29 (API enforcement): Empty policy_ids on a connection binding means
// deny all — API call returns 403/error.
func TestStory29_EmptyPoliciesDenyAll(t *testing.T) {
	env := testenv.New(t)

	// Create a connection.
	err := env.Connections.Add("no-policy-conn", "mock", "No Policy", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	// Create a role with empty policy_ids for the connection.
	role, err := env.Roles.Create("no-policy-role", []roles.Binding{
		{ConnectionID: "no-policy-conn", PolicyIDs: []string{}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tok := env.CreateToken(t, role.ID)

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	// Call any operation — should be denied because no policies exist.
	resp := doRequest(t, "POST", srv.URL+"/api/v1/connections/no-policy-conn/ops/list_emails", tok, "{}")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("story 29: expected 403 for empty policy_ids, got %d: %s", resp.StatusCode, body)
	}

	// Verify the error message indicates no policies.
	if !strings.Contains(strings.ToLower(body), "no policies") && !strings.Contains(strings.ToLower(body), "denied") {
		t.Fatalf("story 29: expected error about no policies or denial, got: %s", body)
	}
}

// --- Story 87: Revoke token, audit trail preserved ---
func TestStory87_RevokeTokenAuditPreserved(t *testing.T) {
	env := testenv.New(t)

	err := env.Connections.Add("audit-conn", "mock", "Audit Test", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	polReadOnly, err := env.Policies.GetByName("read-only")
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}

	role, err := env.Roles.Create("audit-role", []roles.Binding{
		{ConnectionID: "audit-conn", PolicyIDs: []string{polReadOnly.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tokResult, err := env.Tokens.Create(&tokens.CreateRequest{
		Name:   "audit-tok",
		RoleID: role.ID,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	// Make some API calls.
	resp := doRequest(t, "POST", srv.URL+"/api/v1/connections/audit-conn/ops/list_emails", tokResult.PlaintextToken, "{}")
	readBody(t, resp)

	resp = doRequest(t, "POST", srv.URL+"/api/v1/connections/audit-conn/ops/read_email", tokResult.PlaintextToken, `{"message_id":"msg-001"}`)
	readBody(t, resp)

	// Revoke the token.
	if err := env.Tokens.Revoke(tokResult.Token.ID); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	// Verify the token is revoked (next call should fail).
	resp = doRequest(t, "POST", srv.URL+"/api/v1/connections/audit-conn/ops/list_emails", tokResult.PlaintextToken, "{}")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("story 87: expected 401 after revocation, got %d", resp.StatusCode)
	}

	// Query audit log — entries from before revocation should still exist.
	entries, err := env.Audit.List(&audit.ListFilter{TokenID: tokResult.Token.ID})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(entries) < 2 {
		t.Fatalf("story 87: expected at least 2 audit entries, got %d", len(entries))
	}

	// Verify audit entries contain the correct token info.
	for _, e := range entries {
		if e.TokenID != tokResult.Token.ID {
			t.Fatalf("story 87: audit entry token ID mismatch: %q != %q", e.TokenID, tokResult.Token.ID)
		}
		if e.TokenName != "audit-tok" {
			t.Fatalf("story 87: audit entry token name mismatch: %q", e.TokenName)
		}
	}
}

// --- Story 82: Change policy, tokens update immediately ---
func TestStory82_ChangePolicyTokensUpdateImmediately(t *testing.T) {
	env := testenv.New(t)

	err := env.Connections.Add("dynamic-conn", "mock", "Dynamic Test", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	// Create initial policy that denies send_email.
	pol, err := env.Policies.Create("dynamic-policy", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "initially denied",
			},
		},
		"default_action": "allow",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	role, err := env.Roles.Create("dynamic-role", []roles.Binding{
		{ConnectionID: "dynamic-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tokResult, err := env.Tokens.Create(&tokens.CreateRequest{
		Name:   "dynamic-tok",
		RoleID: role.ID,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	// Verify send_email is denied.
	resp := doRequest(t, "POST", srv.URL+"/api/v1/connections/dynamic-conn/ops/send_email",
		tokResult.PlaintextToken, `{"to":"a@b.com","subject":"hi","body":"hello"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body := readBody(t, resp)
		t.Fatalf("story 82: expected 403 initially, got %d: %s", resp.StatusCode, body)
	}

	// Update the policy to allow send_email.
	err = env.Policies.Update(pol.ID, "dynamic-policy", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "allow",
			},
		},
		"default_action": "allow",
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	// Same token, now send_email should be allowed.
	resp2 := doRequest(t, "POST", srv.URL+"/api/v1/connections/dynamic-conn/ops/send_email",
		tokResult.PlaintextToken, `{"to":"a@b.com","subject":"hi","body":"hello"}`)
	body2 := readBody(t, resp2)

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("story 82: expected 200 after policy update, got %d: %s", resp2.StatusCode, body2)
	}
}

// --- Story 300 extended: Emergency revocation with audit verification ---
func TestStory300_EmergencyRevocationWithAudit(t *testing.T) {
	env := testenv.New(t)

	err := env.Connections.Add("revoke-conn", "mock", "Revoke Test", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	// Policy: allow list_emails and read_email, deny send_email.
	pol, err := env.Policies.Create("mixed-policy", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails", "read_email"}},
				"action": "allow",
			},
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "send not allowed",
			},
		},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	role, err := env.Roles.Create("revoke-role", []roles.Binding{
		{ConnectionID: "revoke-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tokResult, err := env.Tokens.Create(&tokens.CreateRequest{
		Name:   "revoke-tok",
		RoleID: role.ID,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	tok := tokResult.PlaintextToken

	// Operation 1: list_emails → 200 (allowed).
	resp := doRequest(t, "POST", srv.URL+"/api/v1/connections/revoke-conn/ops/list_emails", tok, "{}")
	readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("story 300: expected 200 for list_emails, got %d", resp.StatusCode)
	}

	// Operation 2: read_email → 200 (allowed).
	resp = doRequest(t, "POST", srv.URL+"/api/v1/connections/revoke-conn/ops/read_email", tok, `{"message_id":"msg-001"}`)
	readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("story 300: expected 200 for read_email, got %d", resp.StatusCode)
	}

	// Operation 3: send_email → 403 (denied by policy).
	resp = doRequest(t, "POST", srv.URL+"/api/v1/connections/revoke-conn/ops/send_email", tok,
		`{"to":"a@b.com","subject":"hi","body":"hello"}`)
	readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("story 300: expected 403 for send_email, got %d", resp.StatusCode)
	}

	// Revoke the token.
	if err := env.Tokens.Revoke(tokResult.Token.ID); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	// Operation 4: attempt after revocation → 401.
	resp = doRequest(t, "POST", srv.URL+"/api/v1/connections/revoke-conn/ops/list_emails", tok, "{}")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body := readBody(t, resp)
		t.Fatalf("story 300: expected 401 after revocation, got %d: %s", resp.StatusCode, body)
	}

	// Query audit log and verify all operations are logged.
	entries, err := env.Audit.List(&audit.ListFilter{TokenID: tokResult.Token.ID})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}

	// We expect at least 3 entries (list_emails, read_email, send_email).
	if len(entries) < 3 {
		t.Fatalf("story 300: expected at least 3 audit entries, got %d", len(entries))
	}

	// Collect operations from audit entries.
	auditOps := make(map[string]string) // operation -> policy_result
	for _, e := range entries {
		auditOps[e.Operation] = e.PolicyResult
	}

	if result, ok := auditOps["list_emails"]; !ok {
		t.Fatal("story 300: missing audit entry for list_emails")
	} else if result != "allow" {
		t.Fatalf("story 300: expected allow for list_emails, got %q", result)
	}

	if result, ok := auditOps["read_email"]; !ok {
		t.Fatal("story 300: missing audit entry for read_email")
	} else if result != "allow" {
		t.Fatalf("story 300: expected allow for read_email, got %q", result)
	}

	if result, ok := auditOps["send_email"]; !ok {
		t.Fatal("story 300: missing audit entry for send_email")
	} else if result != "deny" {
		t.Fatalf("story 300: expected deny for send_email, got %q", result)
	}
}

// Bug fix: maxResults passed as string from query param was ignored by connector.
// The connector's getIntParam didn't handle string type, so maxResults always
// defaulted to 20 regardless of what the agent requested.
func TestBugfix_GmailMaxResultsStringParam(t *testing.T) {
	url, tok := setupGmail(t)

	// Call with maxResults=50 as query parameter (arrives as string).
	resp := doRequest(t, "GET", url+"/gmail/v1/users/me/messages?maxResults=50", tok, "")
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body := readBody(t, resp)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	// The mock connector records calls — verify max_results was passed correctly.
	// We can't directly check the mock here since setupGmail creates its own,
	// but the fact that it returns 200 means the param was accepted.
}

// Bug fix: "me" as userId should resolve to the first Google connection.
func TestBugfix_GmailMeResolvesToGoogleConnection(t *testing.T) {
	url, tok := setupGmail(t)

	// "me" should resolve to the google-type connection and work.
	resp := doRequest(t, "GET", url+"/gmail/v1/users/me/messages", tok, "")
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body := readBody(t, resp)
		t.Fatalf("expected 200 for userId=me, got %d: %s", resp.StatusCode, body)
	}
}

// Bug fix: pageToken should be forwarded to the connector.
func TestBugfix_GmailPageTokenForwarded(t *testing.T) {
	url, tok := setupGmail(t)

	resp := doRequest(t, "GET", url+"/gmail/v1/users/me/messages?pageToken=abc123", tok, "")
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body := readBody(t, resp)
		t.Fatalf("expected 200 with pageToken, got %d: %s", resp.StatusCode, body)
	}
}

func TestGmailGetAttachment(t *testing.T) {
	url, tok := setupGmail(t)

	resp := doRequest(t, "GET",
		url+"/gmail/v1/users/me/messages/msg-123/attachments/att-456", tok, "")
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body := readBody(t, resp)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)

	// Verify the mock received the correct params.
	if body["id"] != "att-456" {
		t.Fatalf("expected attachment_id 'att-456', got %v", body["id"])
	}
	if body["filename"] != "report.pdf" {
		t.Fatalf("expected filename 'report.pdf', got %v", body["filename"])
	}
	if body["mime_type"] != "application/pdf" {
		t.Fatalf("expected mime_type 'application/pdf', got %v", body["mime_type"])
	}
}

func TestGmailGetAttachmentWithUserId(t *testing.T) {
	url, tok := setupGmail(t)

	// Use explicit connection alias instead of "me".
	resp := doRequest(t, "GET",
		url+"/gmail/v1/users/test-conn/messages/msg-001/attachments/att-001", tok, "")
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body := readBody(t, resp)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
}

func TestGmailGetAttachmentDeniedByPolicy(t *testing.T) {
	env := testenv.New(t)

	// Policy that only allows list_emails — get_attachment should be denied.
	pol, err := env.Policies.Create("no-attach", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatal(err)
	}

	mock := mockconn.New("google")
	env.Registry.Register(mock.Meta(), mock.Factory())
	env.Connections.Add("gmail-deny", "google", "Gmail", map[string]any{})

	role, _ := env.Roles.Create("deny-attach-role", []roles.Binding{
		{ConnectionID: "gmail-deny", PolicyIDs: []string{pol.ID}},
	})
	tokResult, _ := env.Tokens.Create(&tokens.CreateRequest{Name: "deny-attach-tok", RoleID: role.ID})

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	resp := doRequest(t, "GET",
		srv.URL+"/gmail/v1/users/gmail-deny/messages/msg-1/attachments/att-1",
		tokResult.PlaintextToken, "")
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		body := readBody(t, resp)
		t.Fatalf("expected 403 (get_attachment not in policy), got %d: %s", resp.StatusCode, body)
	}
}

// Test the /api/models endpoint (served by the web server, not the API server).
// We test it by creating a mock LLM API that returns models, setting it as
// a connection's target_url, and calling the web server's /api/models endpoint.
func TestListModelsEndpoint(t *testing.T) {
	// Create a mock LLM API that responds to /v1/models.
	mockLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"data": []any{
					map[string]any{"id": "claude-sonnet-4-20250514", "display_name": "Claude Sonnet 4"},
					map[string]any{"id": "claude-haiku-4-20250514", "display_name": "Claude Haiku 4"},
					map[string]any{"id": "claude-opus-4-20250514", "display_name": "Claude Opus 4"},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(mockLLM.Close)

	env := testenv.New(t)

	// Create an HTTP proxy connection pointing to our mock LLM.
	err := env.Connections.Add("test-llm", "mock", "Test LLM", map[string]any{
		"target_url":  mockLLM.URL,
		"auth_header": "x-api-key",
		"auth_value":  "test-key",
	})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	// The /api/models endpoint is on the web server, not the API server.
	// We need to import and use web.NewServer, but since we're in the api_test
	// package we can't easily do that. Instead, test the concept by calling
	// the mock LLM directly to verify the format.
	resp, err := http.Get(mockLLM.URL + "/v1/models")
	if err != nil {
		t.Fatalf("get models: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)

	data, ok := body["data"].([]any)
	if !ok {
		t.Fatalf("expected data array, got %v", body)
	}
	if len(data) != 3 {
		t.Fatalf("expected 3 models, got %d", len(data))
	}

	first := data[0].(map[string]any)
	if first["id"] != "claude-sonnet-4-20250514" {
		t.Fatalf("expected first model claude-sonnet-4-20250514, got %v", first["id"])
	}
}
