package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/policy"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// Spec 001-fix-security-vulns US4 (Shannon INJ-VULN-01/02/03): the
// `command` field on script-type policies and on rules-type nested
// `script.command` MUST be rejected by the policy CREATE / UPDATE
// handlers when it isn't on the operator-configured allowlist.

func newPolicyAllowlistTestServer(t *testing.T) (*httptest.Server, *testenv.Env) {
	t.Helper()
	env := testenv.New(t).WithOperator("test-pass", "test-op")
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := NewServer(
		env.Tokens, env.Connections, env.Policies, env.Roles,
		env.Registry, env.Approval, env.Audit,
		"", env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "127.0.0.1:0",
	)
	srv.SetAuth(env.Operator, env.Session)
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	// Reset the package-level allowlist so each test starts from the
	// documented default (bundled Python interpreter).
	policy.SetCommandAllowlist(nil)
	return ts, env
}

func postPolicyCreate(t *testing.T, ts *httptest.Server, env *testenv.Env, name, policyType, configJSON string) *http.Response {
	t.Helper()
	form := url.Values{}
	form.Set("name", name)
	form.Set("policy_type", policyType)
	form.Set("policy_config", configJSON)
	req, _ := http.NewRequest("POST", ts.URL+"/policies/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestPolicyCreate_RejectsBashCommand(t *testing.T) {
	ts, env := newPolicyAllowlistTestServer(t)
	resp := postPolicyCreate(t, ts, env, "bash-attempt", "script",
		`{"command":"bash","script":"/dev/stdin"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", resp.StatusCode)
	}
	body := readAll(t, resp.Body)
	if !strings.Contains(body, "not in allowlist") {
		t.Errorf("response body should name the allowlist failure: %q", body)
	}
}

func TestPolicyCreate_RejectsBinShCommand(t *testing.T) {
	ts, env := newPolicyAllowlistTestServer(t)
	resp := postPolicyCreate(t, ts, env, "sh-attempt", "script",
		`{"command":"/bin/sh","script":"/dev/stdin"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", resp.StatusCode)
	}
}

func TestPolicyCreate_RejectsPerlCommand(t *testing.T) {
	ts, env := newPolicyAllowlistTestServer(t)
	resp := postPolicyCreate(t, ts, env, "perl-attempt", "script",
		`{"command":"/usr/bin/perl","script":"/dev/stdin"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", resp.StatusCode)
	}
}

func TestPolicyCreate_RejectsRelativePath(t *testing.T) {
	ts, env := newPolicyAllowlistTestServer(t)
	resp := postPolicyCreate(t, ts, env, "rel-attempt", "script",
		`{"command":"../../bin/bash","script":"/dev/stdin"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", resp.StatusCode)
	}
}

func TestPolicyCreate_AcceptsBundledPython(t *testing.T) {
	ts, env := newPolicyAllowlistTestServer(t)
	// The default allowlist contains exactly the bundled Python path,
	// which may not exist on disk in the test container; the policy
	// validates by literal-string match, so this should succeed.
	// We also point script at a known-existing file so the constructor's
	// os.Stat doesn't intercept the success path here — note: policy
	// CREATE itself doesn't construct an evaluator (that happens at
	// evaluation time), so /dev/null is fine for this test.
	resp := postPolicyCreate(t, ts, env, "python-ok", "script",
		`{"command":"/opt/sieve-py/bin/python3","script":"/dev/null"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body := readAll(t, resp.Body)
		t.Fatalf("got status %d (want 303 See Other); body=%q",
			resp.StatusCode, body)
	}
}

func TestPolicyCreate_RejectsRulesNestedScriptCommand(t *testing.T) {
	ts, env := newPolicyAllowlistTestServer(t)
	// Rules-type policy with action=script and bash as the nested
	// command — the path Shannon INJ-VULN-03 exercised.
	cfg := `{"rules":[{"action":"script","script":{"command":"bash","path":"/dev/stdin"}}],"default_action":"deny"}`
	resp := postPolicyCreate(t, ts, env, "rules-nested-bash", "rules", cfg)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400 (rules-nested bash should be rejected)", resp.StatusCode)
	}
	body := readAll(t, resp.Body)
	if !strings.Contains(body, "rule 1") {
		t.Errorf("response should name the offending rule index: %q", body)
	}
}

func TestPolicyUpdate_RejectsFlippingToBash(t *testing.T) {
	ts, env := newPolicyAllowlistTestServer(t)
	// Seed a benign script policy directly via the storage layer to
	// bypass the CREATE handler's check, then attempt to flip it via
	// the UPDATE handler.
	pol, err := env.Policies.Create("benign-python", "script", map[string]any{
		"command": "/opt/sieve-py/bin/python3",
		"script":  "/dev/null",
	})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	form.Set("name", "benign-python")
	form.Set("policy_type", "script")
	form.Set("policy_config", `{"command":"bash","script":"/dev/stdin"}`)
	req, _ := http.NewRequest("POST",
		ts.URL+"/policies/"+pol.ID+"/update",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("UPDATE should reject command=bash, got %d", resp.StatusCode)
	}
}

func TestPolicyCreate_OperatorExtendsAllowlist(t *testing.T) {
	ts, env := newPolicyAllowlistTestServer(t)
	// Operator added /usr/bin/node to the allowlist before creating.
	policy.SetCommandAllowlist([]string{"/opt/sieve-py/bin/python3", "/usr/bin/node"})
	t.Cleanup(func() { policy.SetCommandAllowlist(nil) })
	resp := postPolicyCreate(t, ts, env, "node-ok", "script",
		`{"command":"/usr/bin/node","script":"/dev/null"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body := readAll(t, resp.Body)
		t.Fatalf("got %d, want 303 (node should be allowed via operator override); body=%q",
			resp.StatusCode, body)
	}
}
