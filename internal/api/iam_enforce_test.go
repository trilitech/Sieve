package api_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/policy"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/tokens"
)

const apiGuardScript = `import sys, json
req = json.load(sys.stdin)
body = ((req.get("params") or {}).get("body")) or ""
print(json.dumps({"action": "deny", "reason": "blocked"} if "secret" in body.lower() else {"action": "allow"}))
`

// TestIAMEnforce_ScriptConditionOverGateway proves a rule's script-mode CONDITION
// (spec §5.4) enforces THROUGH THE REAL HTTP GATEWAY: a send rule whose condition
// is a script returns 403 for a body the script denies and 200 for one it allows.
// The script gates the grant per-grant — no filter, no guardrail involved.
func TestIAMEnforce_ScriptConditionOverGateway(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	policy.SetCommandAllowlist([]string{py})
	defer policy.SetCommandAllowlist(nil)

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "block_secret.py")
	if err := os.WriteFile(scriptPath, []byte(apiGuardScript), 0o600); err != nil {
		t.Fatal(err)
	}
	policy.SetScriptDirs([]string{dir})
	defer policy.SetScriptDirs(nil)

	// Self-contained env so the SCRIPT-CONDITION grant is the sole authorizer of the
	// send (the shared setupIAMRouter seeds a broad plain allow that would survive
	// the veto — that's correct per-grant behavior, but not what we're testing here).
	env := testenv.New(t)
	env.Mock.SetResponse("send_email", map[string]any{"id": "1"})
	if err := env.Connections.Add("mc", "mock", "Mock", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	role, err := env.Roles.Create("scripted", []roles.Binding{{ConnectionID: "mc"}})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := env.Tokens.Create(&tokens.CreateRequest{Name: "t", RoleID: role.ID})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: role.ID, Effect: "allow", ConnectorType: "mock", OpScope: "write",
		ConnectionIDs:   []string{"mc"},
		ConditionMode:   "script",
		ConditionScript: iampolicies.ScriptCondSpec{Command: py, Path: scriptPath},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreatePolicy("send-scripted", "", grant, true); err != nil {
		t.Fatal(err)
	}
	if err := env.Settings.Set("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	router := api.NewRouter(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	url := srv.URL + "/api/v1/connections/mc/ops/send_email"
	if status, _ := apiPost(t, url, tok.PlaintextToken, `{"to":"a@b.com","subject":"s","body":"weekly status"}`); status != 200 {
		t.Errorf("clean send should be allowed, got %d", status)
	}
	if status, body := apiPost(t, url, tok.PlaintextToken, `{"to":"a@b.com","subject":"s","body":"the secret plan"}`); status != 403 {
		t.Errorf("send with 'secret' should be denied by the script condition, got %d (%v)", status, body)
	}
}

// TestIAMEnforce_ConditionOverGateway proves a numeric cap enforces through the
// real gateway in the SAFE form the builder produces: "allow write WHEN amount
// <= 100" with default-deny (no broad allow). A value that exceeds the cap, is
// absent, or is non-integral (no Cedar representation) all fail closed — the
// permit's condition errors/false, the permit is skipped, default-deny applies.
func TestIAMEnforce_ConditionOverGateway(t *testing.T) {
	env := testenv.New(t)
	env.Mock.SetResponse("send_email", map[string]any{"id": "1"})
	if err := env.Connections.Add("mc", "mock", "Mock", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	role, err := env.Roles.Create("capped", []roles.Binding{{ConnectionID: "mc"}})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := env.Tokens.Create(&tokens.CreateRequest{Name: "t", RoleID: role.ID})
	if err != nil {
		t.Fatal(err)
	}

	cedar, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: role.ID, Effect: "allow", ConnectorType: "mock", OpScope: "write",
		ConnectionIDs: []string{"mc"},
		Conditions:    []iampolicies.ConditionInput{{Kind: "number", CtxPath: "context.param.amount", Op: "lte", Value: "100"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreatePolicy("amount-cap", "", cedar, true); err != nil {
		t.Fatal(err)
	}
	if err := env.Settings.Set("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	router := api.NewRouter(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	url := srv.URL + "/api/v1/connections/mc/ops/send_email"
	send := func(body string) int { s, _ := apiPost(t, url, tok.PlaintextToken, body); return s }

	if s := send(`{"to":"a@b.com","subject":"s","body":"x","amount":50}`); s != 200 {
		t.Errorf("amount 50 (<=100) should pass, got %d", s)
	}
	if s := send(`{"to":"a@b.com","subject":"s","body":"x","amount":500}`); s != 403 {
		t.Errorf("amount 500 (>100) should be denied, got %d", s)
	}
	// Adversarial: a non-integral amount has no Cedar representation — it must
	// fail closed (skipped permit → default deny), never bypass the cap.
	if s := send(`{"to":"a@b.com","subject":"s","body":"x","amount":500.5}`); s == 200 {
		t.Errorf("non-integral amount 500.5 must NOT bypass the cap, got 200")
	}
}

// TestIAMEnforce_BenignDecimalParam proves a request carrying a decimal param
// (no Cedar float representation) does NOT error the whole decision — the value
// is omitted from context, the request proceeds normally.
func TestIAMEnforce_BenignDecimalParam(t *testing.T) {
	env := setupIAMRouter(t)
	if err := env.settingsSet("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if s, _ := apiPost(t, env.url+"/api/v1/connections/mock-conn/ops/list_emails", env.tok, `{"ratio":1.5}`); s != 200 {
		t.Errorf("benign decimal param must not break the decision, got %d", s)
	}
}

// TestIAMEnforce_RedactOverGateway proves a redact filter actually masks
// sensitive data in the HTTP response — response filtering enforced end to end.
func TestIAMEnforce_RedactOverGateway(t *testing.T) {
	env := setupIAMRouter(t)
	if err := env.settingsSet("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	env.mock.SetResponse("list_emails", map[string]any{
		"emails": []any{map[string]any{"id": "1", "note": "ssn 123-45-6789 on file"}},
	})
	if _, err := env.iam.CreateFilter("redact-ssn", "mask US SSNs", iam.KindRedact, 0,
		map[string]any{"patterns": []any{`\d{3}-\d{2}-\d{4}`}, "match": "regex"}); err != nil {
		t.Fatal(err)
	}
	spec := iampolicies.RuleSpec{
		RoleID: env.roleID, Effect: "allow", ConnectorType: "mock", OpScope: "read",
		ConnectionIDs: []string{"mock-conn"}, Filters: []string{"redact-ssn"},
	}
	grant, err := iampolicies.BuildRuleCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.iam.CreatePolicy("read-redact", "", grant, true); err != nil {
		t.Fatal(err)
	}
	guard, err := iampolicies.BuildGuardrailCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.iam.CreateGuardrail("read-redact-g", "", guard, true); err != nil {
		t.Fatal(err)
	}

	status, body := apiPost(t, env.url+"/api/v1/connections/mock-conn/ops/list_emails", env.tok, "{}")
	if status != 200 {
		t.Fatalf("read should be allowed, got %d", status)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "123-45-6789") {
		t.Errorf("SSN was NOT redacted from the response: %s", raw)
	}
}

// TestIAMEnforce_GuardrailRedactOverGateway proves a redact transform carried by
// a guardrail masks the response end to end. Transforms are guardrail-only — a
// rule is a pure decision and carries none.
func TestIAMEnforce_GuardrailRedactOverGateway(t *testing.T) {
	env := testenv.New(t)
	env.Mock.SetResponse("list_emails", map[string]any{
		"emails": []any{map[string]any{"id": "1", "body": "ssn 123-45-6789 on file"}},
	})
	if err := env.Connections.Add("mc", "mock", "Mock", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	role, err := env.Roles.Create("reader", []roles.Binding{{ConnectionID: "mc"}})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := env.Tokens.Create(&tokens.CreateRequest{Name: "t", RoleID: role.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreateFilter("redact-ssn", "mask SSNs", iam.KindRedact, 0,
		map[string]any{"patterns": []any{`\d{3}-\d{2}-\d{4}`}, "match": "regex"}); err != nil {
		t.Fatal(err)
	}
	// Transforms are guardrail-only: the rule grants the read, a (role-bound)
	// guardrail carries the redact transform.
	grant, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: role.ID, Effect: "allow", ConnectorType: "mock", OpScope: "read",
		ConnectionIDs: []string{"mc"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreatePolicy("read", "", grant, true); err != nil {
		t.Fatal(err)
	}
	guard, err := iampolicies.BuildGuardrailCedar(iampolicies.RuleSpec{
		RoleID: role.ID, ConnectorType: "mock", OpScope: "read",
		ConnectionIDs: []string{"mc"}, Filters: []string{"redact-ssn"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreateGuardrail("read-redact-g", "", guard, true); err != nil {
		t.Fatal(err)
	}
	if err := env.Settings.Set("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	router := api.NewRouter(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	status, body := apiPost(t, srv.URL+"/api/v1/connections/mc/ops/list_emails", tok.PlaintextToken, "{}")
	if status != 200 {
		t.Fatalf("read should be allowed, got %d", status)
	}
	if strings.Contains(body, "123-45-6789") {
		t.Errorf("guardrail redact transform did not mask the SSN: %s", body)
	}
}

// TestIAMEnforce_GuardrailSurvivesComposition proves a role-bound guardrail's
// redact cannot be bypassed by composing a second role that grants the same read
// without it. The guardrail is unconditional for any token in its role, so the
// redact still applies — read_with_pii_removed composed with read_everything.
func TestIAMEnforce_GuardrailSurvivesComposition(t *testing.T) {
	env := testenv.New(t)
	env.Mock.SetResponse("list_emails", map[string]any{
		"emails": []any{map[string]any{"id": "1", "body": "ssn 123-45-6789"}},
	})
	if err := env.Connections.Add("mc", "mock", "Mock", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	roleA, err := env.Roles.Create("redacted-reader", []roles.Binding{{ConnectionID: "mc"}})
	if err != nil {
		t.Fatal(err)
	}
	roleB, err := env.Roles.Create("plain-reader", []roles.Binding{{ConnectionID: "mc"}})
	if err != nil {
		t.Fatal(err)
	}
	// The token holds BOTH roles (composition).
	tok, err := env.Tokens.Create(&tokens.CreateRequest{Name: "t", RoleIDs: []string{roleA.ID, roleB.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreateFilter("redact-ssn", "", iam.KindRedact, 0,
		map[string]any{"patterns": []any{`\d{3}-\d{2}-\d{4}`}, "match": "regex"}); err != nil {
		t.Fatal(err)
	}
	grantA, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: roleA.ID, Effect: "allow", ConnectorType: "mock", OpScope: "read",
		ConnectionIDs: []string{"mc"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreatePolicy("a-read", "", grantA, true); err != nil {
		t.Fatal(err)
	}
	// roleA's redact is a role-bound GUARDRAIL — unconditional for any token in
	// roleA, so a sibling plain grant can't route around it.
	guardA, err := iampolicies.BuildGuardrailCedar(iampolicies.RuleSpec{
		RoleID: roleA.ID, ConnectorType: "mock", OpScope: "read",
		ConnectionIDs: []string{"mc"}, Filters: []string{"redact-ssn"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreateGuardrail("a-redact-g", "", guardA, true); err != nil {
		t.Fatal(err)
	}
	// Role B grants the same read with NO transform — the bypass attempt.
	grantB, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: roleB.ID, Effect: "allow", ConnectorType: "mock", OpScope: "read",
		ConnectionIDs: []string{"mc"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreatePolicy("b-plain", "", grantB, true); err != nil {
		t.Fatal(err)
	}
	if err := env.Settings.Set("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	router := api.NewRouter(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	status, body := apiPost(t, srv.URL+"/api/v1/connections/mc/ops/list_emails", tok.PlaintextToken, "{}")
	if status != 200 {
		t.Fatalf("read should be allowed, got %d", status)
	}
	if strings.Contains(body, "123-45-6789") {
		t.Errorf("COMPOSITION BYPASS: role B (no filter) stripped role A's redact — SSN leaked: %s", body)
	}
}

// apiFilterScript is a post-execution script_filter: it reads the response from
// metadata.response, walks the JSON, blanks any `ssn` field, and returns the
// rewritten response. Proves a script TRANSFORM (not just a guard) runs e2e.
const apiFilterScript = `import sys, json
req = json.load(sys.stdin)
resp = (req.get("metadata") or {}).get("response", "")
data = json.loads(resp)
def walk(v):
    if isinstance(v, dict):
        return {k: ("[redacted-by-script]" if k == "ssn" else walk(x)) for k, x in v.items()}
    if isinstance(v, list):
        return [walk(x) for x in v]
    return v
print(json.dumps({"rewrite": json.dumps(walk(data))}))
`

// TestIAMEnforce_ScriptFilterRewritesResponse proves a script_filter (post-exec
// transform) actually REWRITES the response through the real gateway — not a
// guard (allow/deny) but a content transform, the case the UI now exposes.
func TestIAMEnforce_ScriptFilterRewritesResponse(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	policy.SetCommandAllowlist([]string{py})
	defer policy.SetCommandAllowlist(nil)

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "scrub.py")
	if err := os.WriteFile(scriptPath, []byte(apiFilterScript), 0o600); err != nil {
		t.Fatal(err)
	}
	policy.SetScriptDirs([]string{dir})
	defer policy.SetScriptDirs(nil)

	env := setupIAMRouter(t)
	if err := env.settingsSet("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	env.mock.SetResponse("list_emails", map[string]any{
		"emails": []any{map[string]any{"id": "1", "ssn": "123-45-6789"}},
	})
	if _, err := env.iam.CreateFilter("scrub-script", "rewrite: redact ssn",
		iam.KindScriptFilter, 0, map[string]any{"command": py, "path": scriptPath}); err != nil {
		t.Fatal(err)
	}
	spec := iampolicies.RuleSpec{
		RoleID: env.roleID, Effect: "allow", ConnectorType: "mock", OpScope: "read",
		ConnectionIDs: []string{"mock-conn"}, Filters: []string{"scrub-script"},
	}
	grant, err := iampolicies.BuildRuleCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.iam.CreatePolicy("read-scrub", "", grant, true); err != nil {
		t.Fatal(err)
	}
	guard, err := iampolicies.BuildGuardrailCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.iam.CreateGuardrail("read-scrub-g", "", guard, true); err != nil {
		t.Fatal(err)
	}

	status, body := apiPost(t, env.url+"/api/v1/connections/mock-conn/ops/list_emails", env.tok, "{}")
	if status != 200 {
		t.Fatalf("read should be allowed, got %d", status)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "123-45-6789") {
		t.Errorf("script_filter should have rewritten the SSN out of the response: %s", raw)
	}
	if !strings.Contains(string(raw), "[redacted-by-script]") {
		t.Errorf("expected the script's redaction marker in the response: %s", raw)
	}
}
