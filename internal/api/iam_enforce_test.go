package api_test

import (
	"os/exec"
	"testing"

	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/policy"
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
	cedar, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: env.roleID, Effect: "allow", ConnectorType: "mock", OpScope: "write",
		ConnectionIDs: []string{"mock-conn"}, Filters: []string{"block-secret"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.iam.CreatePolicy("send-guarded", "", cedar, true); err != nil {
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

// TestIAMEnforce_ConditionOverGateway proves a numeric condition (amount cap)
// enforces through the real gateway, incl. JSON numbers (which decode as float64
// and must round-trip as Cedar Long).
func TestIAMEnforce_ConditionOverGateway(t *testing.T) {
	env := setupIAMRouter(t)
	if err := env.settingsSet("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	// A cap is naturally a DENY rule (it overrides the role's broader allow):
	// "deny writes whose amount exceeds 100". forbid-overrides-permit.
	cedar, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: env.roleID, Effect: "deny", ConnectorType: "mock", OpScope: "write",
		ConnectionIDs: []string{"mock-conn"},
		Conditions:    []iampolicies.ConditionInput{{Kind: "number", CtxPath: "context.param.amount", Op: "gt", Value: "100"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.iam.CreatePolicy("amount-cap", "", cedar, true); err != nil {
		t.Fatal(err)
	}
	url := env.url + "/api/v1/connections/mock-conn/ops/send_email"
	if status, _ := apiPost(t, url, env.tok, `{"to":"a@b.com","subject":"s","body":"x","amount":50}`); status != 200 {
		t.Errorf("amount 50 (<=100) should pass, got %d", status)
	}
	if status, _ := apiPost(t, url, env.tok, `{"to":"a@b.com","subject":"s","body":"x","amount":500}`); status != 403 {
		t.Errorf("amount 500 (>100) should be denied, got %d", status)
	}
}
