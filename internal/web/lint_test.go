package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// Spec 001-fix-security-vulns US6 (Shannon AUTHZ-VULN-10): the deny +
// numeric-ceiling + non-deny-default composition surfaces a sticky lint
// warning at the policy save endpoint. Operators must explicitly
// acknowledge to proceed; a re-save with the same composition reuses
// the prior ack; changing the deny shape re-fires.

func newLintTestServer(t *testing.T) (*httptest.Server, *testenv.Env) {
	t.Helper()
	env := testenv.New(t)
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := NewServer(
		env.Tokens, env.Connections, env.Policies, env.Roles,
		env.Registry, env.Approval, env.Audit,
		"", env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "127.0.0.1:0",
	)
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, env
}

func postPolicyCreateForm(t *testing.T, ts *httptest.Server, form url.Values) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+"/policies/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestPolicyCreate_LintBlocksWithoutAck — the documented Shannon attack
// path: a deny rule with a numeric ceiling + a non-deny default. The
// save endpoint MUST return 400 and a structured lint payload.
func TestPolicyCreate_LintBlocksWithoutAck(t *testing.T) {
	ts, _ := newLintTestServer(t)
	form := url.Values{}
	form.Set("name", "ceiling-bad")
	form.Set("policy_type", "rules")
	form.Set("policy_config",
		`{"default_action":"allow","rules":[{"action":"deny","match":{"max_tokens":500}}]}`)
	resp := postPolicyCreateForm(t, ts, form)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "lint_acknowledgement_required" {
		t.Errorf("error=%v, want lint_acknowledgement_required", body["error"])
	}
	lints, _ := body["lints"].([]any)
	if len(lints) != 1 {
		t.Fatalf("lints=%v, want 1 entry", lints)
	}
}

// TestPolicyCreate_LintAccepted — same composition but with
// acknowledge_lint=true: the policy persists, sticky ack stored.
func TestPolicyCreate_LintAccepted(t *testing.T) {
	ts, env := newLintTestServer(t)
	form := url.Values{}
	form.Set("name", "ceiling-acked")
	form.Set("policy_type", "rules")
	form.Set("policy_config",
		`{"default_action":"allow","rules":[{"action":"deny","match":{"max_tokens":500}}]}`)
	form.Set("acknowledge_lint", "true")
	resp := postPolicyCreateForm(t, ts, form)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body := readAll(t, resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	pol, err := env.Policies.GetByName("ceiling-acked")
	if err != nil {
		t.Fatalf("policy missing: %v", err)
	}
	if pol.LintAck == nil {
		t.Fatal("sticky lint ack was not persisted")
	}
	ack, _ := pol.LintAck["deny_ceiling_v1"].(map[string]any)
	if ack == nil || ack["fingerprint"] == "" {
		t.Errorf("ack[deny_ceiling_v1].fingerprint missing: %v", pol.LintAck)
	}
}

// TestPolicyUpdate_StickyAckSilencesCosmeticEdit — the operator has
// already acknowledged a deny-ceiling composition. Renaming the
// policy (no shape change) does not re-fire the warning even without
// acknowledge_lint=true.
func TestPolicyUpdate_StickyAckSilencesCosmeticEdit(t *testing.T) {
	ts, env := newLintTestServer(t)
	// Seed an acknowledged policy.
	form := url.Values{}
	form.Set("name", "sticky-ack")
	form.Set("policy_type", "rules")
	form.Set("policy_config",
		`{"default_action":"allow","rules":[{"action":"deny","match":{"max_tokens":500}}]}`)
	form.Set("acknowledge_lint", "true")
	resp := postPolicyCreateForm(t, ts, form)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("setup create failed status=%d", resp.StatusCode)
	}
	pol, err := env.Policies.GetByName("sticky-ack")
	if err != nil {
		t.Fatal(err)
	}

	// Update with NO ack flag, but identical composition (just a rename).
	uForm := url.Values{}
	uForm.Set("name", "sticky-ack-renamed")
	uForm.Set("policy_type", "rules")
	uForm.Set("policy_config",
		`{"default_action":"allow","rules":[{"action":"deny","match":{"max_tokens":500}}]}`)
	req, _ := http.NewRequest("POST", ts.URL+"/policies/"+pol.ID+"/update",
		strings.NewReader(uForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body := readAll(t, resp.Body)
		t.Fatalf("status=%d (want 303 — sticky ack should silence); body=%s",
			resp.StatusCode, body)
	}
}

// TestPolicyUpdate_LintRefiresOnCompositionChange — same starting state,
// but the operator changes the ceiling value. Sticky ack fingerprint
// no longer matches; warning re-fires.
func TestPolicyUpdate_LintRefiresOnCompositionChange(t *testing.T) {
	ts, env := newLintTestServer(t)
	// Seed an acknowledged policy at max_tokens=500.
	form := url.Values{}
	form.Set("name", "refire-test")
	form.Set("policy_type", "rules")
	form.Set("policy_config",
		`{"default_action":"allow","rules":[{"action":"deny","match":{"max_tokens":500}}]}`)
	form.Set("acknowledge_lint", "true")
	resp := postPolicyCreateForm(t, ts, form)
	resp.Body.Close()
	pol, err := env.Policies.GetByName("refire-test")
	if err != nil {
		t.Fatal(err)
	}

	// Change ceiling from 500 → 1000. No ack flag.
	uForm := url.Values{}
	uForm.Set("name", "refire-test")
	uForm.Set("policy_type", "rules")
	uForm.Set("policy_config",
		`{"default_action":"allow","rules":[{"action":"deny","match":{"max_tokens":1000}}]}`)
	req, _ := http.NewRequest("POST", ts.URL+"/policies/"+pol.ID+"/update",
		strings.NewReader(uForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status=%d (want 400 — fingerprint changed, ack invalid)", resp.StatusCode)
	}
}

// TestPolicyUpdate_ClearsAckOnCompositionRemoval — removing the
// offending composition (no more deny+ceiling) clears the stored ack
// so a future re-introduction re-warns.
func TestPolicyUpdate_ClearsAckOnCompositionRemoval(t *testing.T) {
	ts, env := newLintTestServer(t)
	form := url.Values{}
	form.Set("name", "clear-ack")
	form.Set("policy_type", "rules")
	form.Set("policy_config",
		`{"default_action":"allow","rules":[{"action":"deny","match":{"max_tokens":500}}]}`)
	form.Set("acknowledge_lint", "true")
	resp := postPolicyCreateForm(t, ts, form)
	resp.Body.Close()
	pol, err := env.Policies.GetByName("clear-ack")
	if err != nil {
		t.Fatal(err)
	}
	if pol.LintAck == nil {
		t.Fatal("setup: ack should exist after create")
	}

	// Update to remove the offending composition.
	uForm := url.Values{}
	uForm.Set("name", "clear-ack")
	uForm.Set("policy_type", "rules")
	uForm.Set("policy_config",
		`{"default_action":"deny","rules":[]}`)
	req, _ := http.NewRequest("POST", ts.URL+"/policies/"+pol.ID+"/update",
		strings.NewReader(uForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("update status=%d", resp.StatusCode)
	}
	after, _ := env.Policies.Get(pol.ID)
	if len(after.LintAck) != 0 {
		t.Errorf("ack should be cleared after composition removal; got %v", after.LintAck)
	}
}
