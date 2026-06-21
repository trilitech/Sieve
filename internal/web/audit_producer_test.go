package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/tokens"
)

// Admin mutation handlers MUST emit an audit row identifying the
// operator. This file covers the headline mutation paths; per-handler
// coverage can grow as additional flows land.

func newAuditTestServer(t *testing.T) (*httptest.Server, *testenv.Env) {
	t.Helper()
	env := testenv.New(t).WithOperator("test-pass", "test-op")
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := NewServer(
		env.Tokens, env.Connections, env.Roles,
		env.Registry, env.Approval, env.Audit,
		"", env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "127.0.0.1:0",
	)
	srv.SetAuth(env.Operator, env.Session)
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, env
}

func adminOpAudit(t *testing.T, env *testenv.Env, op string) []audit.Entry {
	t.Helper()
	rows, err := env.Audit.List(&audit.ListFilter{Operation: op})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestAuditProducer_TokenCreate(t *testing.T) {
	ts, env := newAuditTestServer(t)
	role, err := env.Roles.Create("r1", nil)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("name", "audit-token")
	form.Set("role_id", role.ID)
	req, _ := http.NewRequest("POST", ts.URL+"/tokens/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}

	rows := adminOpAudit(t, env, "token.create")
	if len(rows) != 1 {
		t.Fatalf("token.create audit rows=%d, want 1", len(rows))
	}
	r := rows[0]
	if r.ActorKind != "operator" {
		t.Errorf("actor_kind=%q, want operator", r.ActorKind)
	}
	if r.OperatorDisplayName != "test-op" {
		t.Errorf("operator_display_name=%q, want test-op", r.OperatorDisplayName)
	}
	if r.PolicyResult != "success" {
		t.Errorf("policy_result=%q", r.PolicyResult)
	}
	// Plaintext bearer must NOT appear in the audit row.
	if strings.Contains(r.Params, "sieve_tok_") {
		t.Errorf("audit row leaks plaintext token: %s", r.Params)
	}
}

func TestAuditProducer_SettingsSave(t *testing.T) {
	ts, env := newAuditTestServer(t)
	form := url.Values{}
	form.Set("llm_connection", "")
	form.Set("llm_model", "")
	form.Set("llm_max_tokens", "")
	form.Set("public_base_url", "")
	req, _ := http.NewRequest("POST", ts.URL+"/settings",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusOK {
		body := readAll(t, resp.Body)
		t.Fatalf("settings/save status=%d body=%s", resp.StatusCode, body)
	}
	rows := adminOpAudit(t, env, "settings.save")
	if len(rows) != 1 {
		t.Fatalf("settings.save audit rows=%d", len(rows))
	}
	if rows[0].OperatorDisplayName != "test-op" {
		t.Errorf("operator_display_name=%q", rows[0].OperatorDisplayName)
	}
	if !strings.Contains(rows[0].Params, "submitted_keys") {
		t.Errorf("settings.save audit row should contain submitted_keys, got: %s", rows[0].Params)
	}
	// Sanity: shouldn't contain the old field name `"keys"` as a
	// stand-alone JSON key (the rename was deliberate).
	if strings.Contains(rows[0].Params, `"keys":`) {
		t.Errorf("settings.save audit row still uses old field name `keys`: %s", rows[0].Params)
	}
}

// TestApprovalApproveProposal_RejectsMissingName proves that a policy-
// proposal approval with no name field returns 400 — round-4 fix moved
// validation BEFORE s.approval.Approve so the proposal row is not
// flipped to approved on a malformed payload.
func TestAuditProducer_TokenRevoke(t *testing.T) {
	ts, env := newAuditTestServer(t)
	role, _ := env.Roles.Create("r", nil)
	tokenInfo, err := env.Tokens.Create(&tokens.CreateRequest{Name: "rev-target", RoleID: role.ID})
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("POST", ts.URL+"/tokens/"+tokenInfo.Token.ID+"/revoke", nil)
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	rows := adminOpAudit(t, env, "token.revoke")
	if len(rows) != 1 {
		t.Fatalf("token.revoke audit rows=%d", len(rows))
	}
}
