package api_test

import (
	"encoding/json"
	"net/http/httptest"
	"os/exec"
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

// TestIAMEnforce_ScriptGuardOverGateway proves authored ⇒ enforced THROUGH THE
// REAL HTTP GATEWAY: an operator-authored script_guard attached to a send rule
// causes the agent API to return 403 for a forbidden send and 200 for an allowed
// one. This is the end-to-end dogfood for "custom logic that decides what can be
// sent" — not a decision-layer unit test, an actual request through api.Router.
func TestIAMEnforce_ScriptGuardOverGateway(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	policy.SetCommandAllowlist([]string{py})
	defer policy.SetCommandAllowlist(nil)

	env := setupIAMRouter(t)
	if err := env.settingsSet("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}

	if _, err := env.iam.CreateFilter("block-secret", "block sends containing 'secret'",
		iam.KindScriptGuard, 0, map[string]any{"command": py, "inline": apiGuardScript}); err != nil {
		t.Fatal(err)
	}
	spec := iampolicies.RuleSpec{
		RoleID: env.roleID, Effect: "allow", ConnectorType: "mock", OpScope: "write",
		ConnectionIDs: []string{"mock-conn"}, Filters: []string{"block-secret"},
	}
	grant, err := iampolicies.BuildRuleCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.iam.CreatePolicy("send-guarded", "", grant, true); err != nil {
		t.Fatal(err)
	}
	guard, err := iampolicies.BuildGuardrailCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.iam.CreateGuardrail("send-guarded-g", "", guard, true); err != nil {
		t.Fatal(err)
	}

	url := env.url + "/api/v1/connections/mock-conn/ops/send_email"
	if status, _ := apiPost(t, url, env.tok, `{"to":"a@b.com","subject":"s","body":"weekly status"}`); status != 200 {
		t.Errorf("clean send should be allowed by the guard, got %d", status)
	}
	if status, body := apiPost(t, url, env.tok, `{"to":"a@b.com","subject":"s","body":"the secret plan"}`); status != 403 {
		t.Errorf("send with 'secret' should be blocked by the guard, got %d (%v)", status, body)
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
		map[string]any{"patterns": []any{`\d{3}-\d{2}-\d{4}`}}); err != nil {
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
