package iampolicies_test

import (
	"context"
	"os/exec"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/connectors/gmail"
	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/policy"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// A custom operator script: deny the send if the body contains "secret".
const guardScript = `import sys, json
req = json.load(sys.stdin)
body = ((req.get("params") or {}).get("body")) or ""
print(json.dumps({"action": "deny", "reason": "blocked: contains 'secret'"} if "secret" in body.lower() else {"action": "allow"}))
`

// TestDecide_ScriptGuardBlocksSend proves the answer to "where do I set up a
// custom script to filter what can/cannot be sent": a script_guard filter
// attached to a send rule is EXECUTED by the live PDP and actually blocks the
// send. This is the "arbitrary operator logic, authored ⇒ enforced" capability.
func TestDecide_ScriptGuardBlocksSend(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	policy.SetCommandAllowlist([]string{py})
	defer policy.SetCommandAllowlist(nil)

	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)

	if _, err := svc.CreateFilter("block-secret", "block sends containing 'secret'",
		iam.KindScriptGuard, 0, map[string]any{"command": py, "inline": guardScript}); err != nil {
		t.Fatal(err)
	}

	spec := iampolicies.RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "google", OpScope: "write",
		Filters: []string{"block-secret"},
	}
	// Grant (allow the write) + the companion guardrail carrying the script_guard
	// obligation (spec §7.2). The guard runs in pass 2 and can deny.
	grant, err := iampolicies.BuildRuleCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy("send-with-guard", "", grant, true); err != nil {
		t.Fatal(err)
	}
	guard, err := iampolicies.BuildGuardrailCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateGuardrail("send-with-guard-g", "", guard, true); err != nil {
		t.Fatal(err)
	}

	reg := connector.NewRegistry()
	reg.Register(gmail.Meta, gmail.Factory)

	send := func(body string) *policy.PolicyDecision {
		d, err := svc.Decide(context.Background(), reg, "tok", []string{"R"}, "google", "work", "active", "send_email",
			map[string]any{"to": []string{"a@b.com"}, "subject": "s", "body": body})
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
		return d
	}

	if d := send("hello team, status update"); d.Action != "allow" {
		t.Errorf("clean send: got %q (reason %q), want allow", d.Action, d.Reason)
	}
	if d := send("here is the secret launch plan"); d.Action != "deny" {
		t.Errorf("send with 'secret': got %q, want deny", d.Action)
	}
}
