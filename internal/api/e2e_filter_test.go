package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/approval"
	"github.com/trilitech/Sieve/internal/roles"
	mockconn "github.com/trilitech/Sieve/internal/testing/mockconnector"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/tokens"
)

// setupWithFixtures creates a test environment with realistic Gmail fixture data
// loaded into the mock connector. Returns the server URL and a valid token.
func setupWithFixtures(t *testing.T, policyConfig map[string]any) (string, string) {
	t.Helper()
	env := testenv.New(t)

	// Load realistic Gmail fixtures.
	env.Mock.SetResponse("list_emails", mockconn.GmailListEmails())
	env.Mock.SetResponse("read_email", mockconn.GmailReadEmail("msg-001"))

	// Create the policy.
	pol, err := env.Policies.Create("test-filter-policy", "rules", policyConfig)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	err = env.Connections.Add("gmail-conn", "mock", "Test Gmail", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	role, err := env.Roles.Create("filter-role", []roles.Binding{
		{ConnectionID: "gmail-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tokResult, err := env.Tokens.Create(&tokens.CreateRequest{Name: "filter-tok", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	return srv.URL, tokResult.PlaintextToken
}

func apiGet(t *testing.T, url, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func apiPost(t *testing.T, url, token, bodyJSON string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// --- Story 42: Content filtering excludes emails containing "CONFIDENTIAL" ---
func TestE2E_Story42_ExcludeConfidentialEmails(t *testing.T) {
	url, tok := setupWithFixtures(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":          map[string]any{"operations": []any{"list_emails"}},
				"action":         "filter",
				"filter_exclude": "CONFIDENTIAL",
			},
		},
		"default_action": "deny",
	})

	status, body := apiPost(t, url+"/api/v1/connections/gmail-conn/ops/list_emails", tok, `{}`)
	if status != 200 {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	emails, ok := body["emails"].([]any)
	if !ok {
		t.Fatalf("expected emails array, got %v", body)
	}

	// Original had 5 emails, one containing "CONFIDENTIAL" (msg-002).
	// After filtering, should have 4.
	if len(emails) != 4 {
		t.Fatalf("expected 4 emails after excluding CONFIDENTIAL, got %d", len(emails))
	}

	// Verify msg-002 (the CONFIDENTIAL one) is gone.
	for _, e := range emails {
		em := e.(map[string]any)
		if em["id"] == "msg-002" {
			t.Fatal("msg-002 (CONFIDENTIAL) should have been excluded")
		}
	}

	// Verify total was updated.
	total, _ := body["total"].(float64)
	if total != 4 {
		t.Fatalf("expected total=4 after filtering, got %v", total)
	}
}

// --- Story 225: Exclude emails containing specific keywords ---
func TestE2E_Story225_ExcludeByKeyword(t *testing.T) {
	url, tok := setupWithFixtures(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":          map[string]any{"operations": []any{"list_emails"}},
				"action":         "filter",
				"filter_exclude": "PRIVATE",
			},
		},
		"default_action": "deny",
	})

	status, body := apiPost(t, url+"/api/v1/connections/gmail-conn/ops/list_emails", tok, `{}`)
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	emails := body["emails"].([]any)
	// msg-004 contains "PRIVATE" in body. Should be excluded.
	if len(emails) != 4 {
		t.Fatalf("expected 4 emails after PRIVATE exclusion, got %d", len(emails))
	}
	for _, e := range emails {
		em := e.(map[string]any)
		if em["id"] == "msg-004" {
			t.Fatal("msg-004 (PRIVATE) should have been excluded")
		}
	}
}

// --- Story 226: Redact SSN patterns from email content ---
func TestE2E_Story226_RedactSSN(t *testing.T) {
	url, tok := setupWithFixtures(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":          map[string]any{"operations": []any{"list_emails"}},
				"action":         "filter",
				"redact_patterns": []any{`\d{3}-\d{2}-\d{4}`},
			},
		},
		"default_action": "deny",
	})

	status, body := apiPost(t, url+"/api/v1/connections/gmail-conn/ops/list_emails", tok, `{}`)
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	// The response JSON should have SSNs redacted.
	respJSON, _ := json.Marshal(body)
	respStr := string(respJSON)

	if strings.Contains(respStr, "123-45-6789") {
		t.Fatal("SSN 123-45-6789 should have been redacted")
	}
	if strings.Contains(respStr, "987-65-4321") {
		t.Fatal("SSN 987-65-4321 should have been redacted")
	}
	if !strings.Contains(respStr, "[REDACTED]") {
		t.Fatal("expected [REDACTED] placeholder in response")
	}

	// All 5 emails should still be present (redaction doesn't remove items).
	emails := body["emails"].([]any)
	if len(emails) != 5 {
		t.Fatalf("expected 5 emails (redaction not exclusion), got %d", len(emails))
	}
}

// --- Story 228: Both exclude and redact on the same rule ---
func TestE2E_Story228_ExcludeAndRedact(t *testing.T) {
	url, tok := setupWithFixtures(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":           map[string]any{"operations": []any{"list_emails"}},
				"action":          "filter",
				"filter_exclude":  "PRIVATE",
				"redact_patterns": []any{`\d{3}-\d{2}-\d{4}`},
			},
		},
		"default_action": "deny",
	})

	status, body := apiPost(t, url+"/api/v1/connections/gmail-conn/ops/list_emails", tok, `{}`)
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	emails := body["emails"].([]any)
	// msg-004 excluded (contains "PRIVATE"), remaining 4 emails have SSNs redacted.
	if len(emails) != 4 {
		t.Fatalf("expected 4 emails, got %d", len(emails))
	}

	respJSON, _ := json.Marshal(body)
	respStr := string(respJSON)
	if strings.Contains(respStr, "123-45-6789") {
		t.Fatal("SSN should have been redacted in remaining emails")
	}
}

// --- Story 43: Label-based filtering (policy denies emails without label) ---
// This test verifies that a policy rule with label filter only allows access
// when the email has the specified label. The rule matches list_emails with
// label="project-x", and the agent's metadata would need labels set.
// Since the mock returns all emails and label filtering happens at the
// connector query level (not response filtering), this test verifies
// that the policy engine correctly matches based on label params.
func TestE2E_Story43_LabelFilterDeniesUnlabeled(t *testing.T) {
	env := testenv.New(t)

	pol, err := env.Policies.Create("label-policy", "rules", map[string]any{
		"rules": []any{
			// Only allow read_email if labels include "project-x".
			map[string]any{
				"match": map[string]any{
					"operations": []any{"read_email"},
					"labels":     []any{"project-x"},
				},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	err = env.Connections.Add("label-conn", "mock", "Label Test", map[string]any{})
	if err != nil {
		t.Fatalf("add conn: %v", err)
	}

	role, err := env.Roles.Create("label-role", []roles.Binding{
		{ConnectionID: "label-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tokResult, err := env.Tokens.Create(&tokens.CreateRequest{Name: "label-tok", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	// Request with labels metadata containing "project-x" — should be allowed.
	status, _ := apiPost(t, srv.URL+"/api/v1/connections/label-conn/ops/read_email",
		tokResult.PlaintextToken,
		`{"message_id":"msg-001","labels":["project-x","INBOX"]}`)
	if status != 200 {
		t.Fatalf("expected 200 for email with project-x label, got %d", status)
	}

	// Request without the required label — should be denied.
	status, body := apiPost(t, srv.URL+"/api/v1/connections/label-conn/ops/read_email",
		tokResult.PlaintextToken,
		`{"message_id":"msg-002","labels":["INBOX"]}`)
	if status != 403 {
		t.Fatalf("expected 403 for email without project-x label, got %d: %v", status, body)
	}
}

// --- Story 44: From filter restricts by sender ---
func TestE2E_Story44_FromFilter(t *testing.T) {
	env := testenv.New(t)

	pol, err := env.Policies.Create("from-policy", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match": map[string]any{
					"operations": []any{"read_email"},
					"from":       []any{"*@company.com"},
				},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	err = env.Connections.Add("from-conn", "mock", "From Test", map[string]any{})
	if err != nil {
		t.Fatalf("add conn: %v", err)
	}

	role, err := env.Roles.Create("from-role", []roles.Binding{
		{ConnectionID: "from-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tokResult, err := env.Tokens.Create(&tokens.CreateRequest{Name: "from-tok", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	// From company.com — allowed.
	status, _ := apiPost(t, srv.URL+"/api/v1/connections/from-conn/ops/read_email",
		tokResult.PlaintextToken,
		`{"message_id":"msg-001","from":"alice@company.com"}`)
	if status != 200 {
		t.Fatalf("expected 200 for company sender, got %d", status)
	}

	// From external — denied.
	status, _ = apiPost(t, srv.URL+"/api/v1/connections/from-conn/ops/read_email",
		tokResult.PlaintextToken,
		`{"message_id":"msg-002","from":"hacker@evil.com"}`)
	if status != 403 {
		t.Fatalf("expected 403 for external sender, got %d", status)
	}
}

// --- Story 368: To filter restricts who agents can email ---
func TestE2E_Story368_ToFilter(t *testing.T) {
	env := testenv.New(t)

	pol, err := env.Policies.Create("to-policy", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match": map[string]any{
					"operations": []any{"send_email"},
					"to":         []any{"*@company.com"},
				},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	err = env.Connections.Add("to-conn", "mock", "To Test", map[string]any{})
	if err != nil {
		t.Fatalf("add conn: %v", err)
	}

	role, err := env.Roles.Create("to-role", []roles.Binding{
		{ConnectionID: "to-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tokResult, err := env.Tokens.Create(&tokens.CreateRequest{Name: "to-tok", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	// To company.com — allowed.
	status, _ := apiPost(t, srv.URL+"/api/v1/connections/to-conn/ops/send_email",
		tokResult.PlaintextToken,
		`{"to":"bob@company.com","subject":"Hi","body":"Hello"}`)
	if status != 200 {
		t.Fatalf("expected 200 for company recipient, got %d", status)
	}

	// To external — denied.
	status, _ = apiPost(t, srv.URL+"/api/v1/connections/to-conn/ops/send_email",
		tokResult.PlaintextToken,
		`{"to":"attacker@evil.com","subject":"Secrets","body":"Here are the secrets"}`)
	if status != 403 {
		t.Fatalf("expected 403 for external recipient, got %d", status)
	}
}

// --- Story 227: Redact credit card numbers ---
func TestE2E_Story227_RedactCreditCards(t *testing.T) {
	url, tok := setupWithFixtures(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":           map[string]any{"operations": []any{"list_emails"}},
				"action":          "filter",
				"redact_patterns": []any{`\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}`},
			},
		},
		"default_action": "deny",
	})

	status, body := apiPost(t, url+"/api/v1/connections/gmail-conn/ops/list_emails", tok, `{}`)
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	respJSON, _ := json.Marshal(body)
	respStr := string(respJSON)

	if strings.Contains(respStr, "4111-1111-1111-1111") {
		t.Fatal("credit card number should have been redacted")
	}
	if strings.Contains(respStr, "4532-1234-5678-9012") {
		t.Fatal("second credit card should have been redacted from read_email fixture")
	}
}

// --- Story 55: First-match-wins with deny before allow (full pipeline) ---
func TestE2E_Story55_FirstMatchDenyThenAllow(t *testing.T) {
	url, tok := setupWithFixtures(t, map[string]any{
		"rules": []any{
			// Rule 1: deny send_email.
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "sending is blocked",
			},
			// Rule 2: allow everything.
			map[string]any{
				"action": "allow",
			},
		},
		"default_action": "deny",
	})

	// list_emails skips rule 1, hits rule 2 (allow).
	status, _ := apiPost(t, url+"/api/v1/connections/gmail-conn/ops/list_emails", tok, `{}`)
	if status != 200 {
		t.Fatalf("expected 200 for list_emails, got %d", status)
	}

	// send_email hits rule 1 (deny).
	status, body := apiPost(t, url+"/api/v1/connections/gmail-conn/ops/send_email", tok,
		`{"to":"x@x.com","subject":"x","body":"x"}`)
	if status != 403 {
		t.Fatalf("expected 403 for send_email, got %d", status)
	}
	// Verify the denial reason is in the response.
	errMsg, _ := body["error"].(string)
	if !strings.Contains(errMsg, "sending is blocked") {
		t.Fatalf("expected denial reason in error, got %q", errMsg)
	}
}

// --- Story 169: Allow list+read, deny send — full pipeline with fixture data ---
func TestE2E_Story169_AllowListReadDenySend(t *testing.T) {
	url, tok := setupWithFixtures(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails", "read_email"}},
				"action": "allow",
			},
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "sending is forbidden",
			},
		},
		"default_action": "deny",
	})

	// list_emails → 200, verify 5 realistic emails.
	status, body := apiPost(t, url+"/api/v1/connections/gmail-conn/ops/list_emails", tok, `{}`)
	if status != 200 {
		t.Fatalf("expected 200 for list_emails, got %d: %v", status, body)
	}
	emails, ok := body["emails"].([]any)
	if !ok {
		t.Fatalf("expected emails array, got %v", body)
	}
	if len(emails) != 5 {
		t.Fatalf("expected 5 emails, got %d", len(emails))
	}
	// Verify realistic fields on first email.
	first := emails[0].(map[string]any)
	if first["from"] == nil || first["from"] == "" {
		t.Fatal("expected 'from' field on email")
	}
	if first["to"] == nil {
		t.Fatal("expected 'to' field on email")
	}
	if first["subject"] == nil || first["subject"] == "" {
		t.Fatal("expected 'subject' field on email")
	}
	if first["body"] == nil || first["body"] == "" {
		t.Fatal("expected 'body' field on email")
	}

	// read_email → 200, verify single email fields.
	status, body = apiPost(t, url+"/api/v1/connections/gmail-conn/ops/read_email", tok, `{"message_id":"msg-001"}`)
	if status != 200 {
		t.Fatalf("expected 200 for read_email, got %d: %v", status, body)
	}
	if body["id"] != "msg-001" {
		t.Fatalf("expected id=msg-001, got %v", body["id"])
	}
	if body["subject"] != "Q3 Revenue Report" {
		t.Fatalf("expected subject 'Q3 Revenue Report', got %v", body["subject"])
	}
	if body["from"] != "alice@company.com" {
		t.Fatalf("expected from 'alice@company.com', got %v", body["from"])
	}

	// send_email → 403.
	status, body = apiPost(t, url+"/api/v1/connections/gmail-conn/ops/send_email", tok,
		`{"to":"x@x.com","subject":"Hi","body":"Hello"}`)
	if status != 403 {
		t.Fatalf("expected 403 for send_email, got %d: %v", status, body)
	}
	errMsg, _ := body["error"].(string)
	if !strings.Contains(errMsg, "sending is forbidden") {
		t.Fatalf("expected denial reason, got %q", errMsg)
	}
}

// --- Story 172: Require approval for send, allow everything else ---
func TestE2E_Story172_RequireApprovalForSend(t *testing.T) {
	env := testenv.New(t)

	env.Mock.SetResponse("list_emails", mockconn.GmailListEmails())

	pol, err := env.Policies.Create("approval-send", "rules", map[string]any{
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

	err = env.Connections.Add("gmail-conn", "mock", "Test Gmail", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	role, err := env.Roles.Create("approval-role", []roles.Binding{
		{ConnectionID: "gmail-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tokResult, err := env.Tokens.Create(&tokens.CreateRequest{Name: "approval-tok", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	// list_emails → 200 (allowed).
	status, body := apiPost(t, srv.URL+"/api/v1/connections/gmail-conn/ops/list_emails", tokResult.PlaintextToken, `{}`)
	if status != 200 {
		t.Fatalf("expected 200 for list_emails, got %d: %v", status, body)
	}
	emails := body["emails"].([]any)
	if len(emails) != 5 {
		t.Fatalf("expected 5 emails, got %d", len(emails))
	}

	// send_email → blocks on approval (send in goroutine, then check queue).
	done := make(chan int, 1)
	go func() {
		st, _ := apiPost(t, srv.URL+"/api/v1/connections/gmail-conn/ops/send_email", tokResult.PlaintextToken,
			`{"to":"bob@company.com","subject":"Report","body":"Here is the report"}`)
		done <- st
	}()

	// Wait for approval item to appear in queue.
	var items []approval.Item
	for i := 0; i < 50; i++ {
		items, _ = env.Approval.ListPending()
		if len(items) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(items) == 0 {
		t.Fatal("expected approval item in queue")
	}

	// Verify the approval item details.
	item := items[0]
	if item.Operation != "send_email" {
		t.Fatalf("expected operation 'send_email', got %q", item.Operation)
	}
	if item.ConnectionID != "gmail-conn" {
		t.Fatalf("expected connection 'gmail-conn', got %q", item.ConnectionID)
	}
	reqData := item.RequestData
	if reqData["to"] != "bob@company.com" {
		t.Fatalf("expected to='bob@company.com' in request data, got %v", reqData["to"])
	}
	if reqData["subject"] != "Report" {
		t.Fatalf("expected subject='Report' in request data, got %v", reqData["subject"])
	}

	// Approve so the goroutine can finish.
	_ = env.Approval.Approve(item.ID)
	<-done
}

// --- Story 229: Content filter on deny rule has no effect ---
func TestE2E_Story229_DenyRuleIgnoresFilter(t *testing.T) {
	url, tok := setupWithFixtures(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":          map[string]any{"operations": []any{"list_emails"}},
				"action":         "deny",
				"reason":         "blocked",
				"filter_exclude": "test",
			},
		},
		"default_action": "deny",
	})

	// Deny rule should deny, not filter.
	status, body := apiPost(t, url+"/api/v1/connections/gmail-conn/ops/list_emails", tok, `{}`)
	if status != 403 {
		t.Fatalf("expected 403 (deny overrides filter), got %d: %v", status, body)
	}
	errMsg, _ := body["error"].(string)
	if !strings.Contains(errMsg, "blocked") {
		t.Fatalf("expected denial reason 'blocked', got %q", errMsg)
	}
}

// --- Story 88/230: Composite policy — one allows with redaction, one denies ---
func TestE2E_Story88_230_CompositePolicyRedactAndDeny(t *testing.T) {
	env := testenv.New(t)

	env.Mock.SetResponse("list_emails", mockconn.GmailListEmails())

	// Policy A: allows list_emails with SSN redaction.
	polA, err := env.Policies.Create("allow-list-redact", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":           map[string]any{"operations": []any{"list_emails"}},
				"action":          "filter",
				"redact_patterns": []any{`\d{3}-\d{2}-\d{4}`},
			},
		},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy A: %v", err)
	}

	// Policy B: denies send_email, allows everything else.
	polB, err := env.Policies.Create("deny-send", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "send is blocked by policy B",
			},
		},
		"default_action": "allow",
	})
	if err != nil {
		t.Fatalf("create policy B: %v", err)
	}

	err = env.Connections.Add("gmail-conn", "mock", "Test Gmail", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	// Both policies on the same connection.
	role, err := env.Roles.Create("composite-role", []roles.Binding{
		{ConnectionID: "gmail-conn", PolicyIDs: []string{polA.ID, polB.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tokResult, err := env.Tokens.Create(&tokens.CreateRequest{Name: "composite-tok", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	// list_emails → 200 with SSNs redacted.
	status, body := apiPost(t, srv.URL+"/api/v1/connections/gmail-conn/ops/list_emails", tokResult.PlaintextToken, `{}`)
	if status != 200 {
		t.Fatalf("expected 200 for list_emails, got %d: %v", status, body)
	}

	respJSON, _ := json.Marshal(body)
	respStr := string(respJSON)
	if strings.Contains(respStr, "123-45-6789") {
		t.Fatal("SSN 123-45-6789 should have been redacted")
	}
	if strings.Contains(respStr, "987-65-4321") {
		t.Fatal("SSN 987-65-4321 should have been redacted")
	}
	if !strings.Contains(respStr, "[REDACTED]") {
		t.Fatal("expected [REDACTED] placeholder in response")
	}

	// send_email → 403.
	status, body = apiPost(t, srv.URL+"/api/v1/connections/gmail-conn/ops/send_email", tokResult.PlaintextToken,
		`{"to":"x@x.com","subject":"x","body":"x"}`)
	if status != 403 {
		t.Fatalf("expected 403 for send_email, got %d: %v", status, body)
	}
}

// --- Story 348: Response filter excludes matching items from list ---
func TestE2E_Story348_ExcludeSpamFromList(t *testing.T) {
	url, tok := setupWithFixtures(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":          map[string]any{"operations": []any{"list_emails"}},
				"action":         "filter",
				"filter_exclude": "spam",
			},
		},
		"default_action": "deny",
	})

	status, body := apiPost(t, url+"/api/v1/connections/gmail-conn/ops/list_emails", tok, `{}`)
	if status != 200 {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	emails := body["emails"].([]any)
	// msg-003 has "not spam" in body and newsletter@spam.com as sender.
	// The filter_exclude matches "spam" anywhere in the serialized item.
	for _, e := range emails {
		em := e.(map[string]any)
		emailJSON, _ := json.Marshal(em)
		if strings.Contains(strings.ToLower(string(emailJSON)), "spam") {
			t.Fatalf("email %v should have been excluded (contains 'spam')", em["id"])
		}
	}

	// Total should be updated.
	total, _ := body["total"].(float64)
	if int(total) != len(emails) {
		t.Fatalf("expected total=%d to match emails length, got %v", len(emails), total)
	}
}

// --- Story 349: Response filter redacts patterns in individual email ---
func TestE2E_Story349_RedactSSNInReadEmail(t *testing.T) {
	url, tok := setupWithFixtures(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":           map[string]any{"operations": []any{"read_email"}},
				"action":          "filter",
				"redact_patterns": []any{`\d{3}-\d{2}-\d{4}`},
			},
		},
		"default_action": "deny",
	})

	status, body := apiPost(t, url+"/api/v1/connections/gmail-conn/ops/read_email", tok, `{"message_id":"msg-001"}`)
	if status != 200 {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	// Verify the email is otherwise intact.
	if body["id"] != "msg-001" {
		t.Fatalf("expected id=msg-001, got %v", body["id"])
	}
	if body["subject"] != "Q3 Revenue Report" {
		t.Fatalf("expected subject preserved, got %v", body["subject"])
	}
	if body["from"] != "alice@company.com" {
		t.Fatalf("expected from preserved, got %v", body["from"])
	}

	// Verify SSNs are redacted in the body.
	emailBody, _ := body["body"].(string)
	if strings.Contains(emailBody, "123-45-6789") {
		t.Fatal("SSN 123-45-6789 should have been redacted in email body")
	}
	if strings.Contains(emailBody, "4532-1234-5678-9012") {
		// This is a credit card but matches the SSN-like pattern partially.
		// The fixture has it as "4532-1234-5678-9012", which should not match \d{3}-\d{2}-\d{4}.
	}
	if !strings.Contains(emailBody, "[REDACTED]") {
		t.Fatal("expected [REDACTED] placeholder in email body")
	}

	// Verify other fields are not corrupted.
	if body["thread_id"] != "thread-001" {
		t.Fatalf("expected thread_id preserved, got %v", body["thread_id"])
	}
}

// --- Story 298: Principle of least privilege (full pipeline with fixtures) ---
func TestE2E_Story298_LeastPrivilege(t *testing.T) {
	url, tok := setupWithFixtures(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails", "list_labels"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})

	// list_emails — allowed, returns realistic data.
	status, body := apiPost(t, url+"/api/v1/connections/gmail-conn/ops/list_emails", tok, `{}`)
	if status != 200 {
		t.Fatalf("expected 200 for list_emails, got %d", status)
	}
	emails := body["emails"].([]any)
	if len(emails) != 5 {
		t.Fatalf("expected 5 emails, got %d", len(emails))
	}

	// read_email — denied.
	status, _ = apiPost(t, url+"/api/v1/connections/gmail-conn/ops/read_email", tok,
		`{"message_id":"msg-001"}`)
	if status != 403 {
		t.Fatalf("expected 403 for read_email (not in allowed list), got %d", status)
	}

	// send_email — denied.
	status, _ = apiPost(t, url+"/api/v1/connections/gmail-conn/ops/send_email", tok,
		`{"to":"x@x.com","subject":"x","body":"x"}`)
	if status != 403 {
		t.Fatalf("expected 403 for send_email, got %d", status)
	}
}
