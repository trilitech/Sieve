package iampolicies_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/connectors/gmail"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/policy"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// A custom operator script (a rule's script-mode CONDITION): deny the send if the
// body contains "secret", else allow.
const guardScript = `import sys, json
req = json.load(sys.stdin)
body = ((req.get("params") or {}).get("body")) or ""
print(json.dumps({"action": "deny", "reason": "blocked: contains 'secret'"} if "secret" in body.lower() else {"action": "allow"}))
`

// scriptCondEnv writes the guard script to an allowlisted dir and returns the
// interpreter path. Skips if python3 isn't available.
func scriptCondEnv(t *testing.T) (py, scriptPath string) {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	policy.SetCommandAllowlist([]string{py})
	t.Cleanup(func() { policy.SetCommandAllowlist(nil) })
	dir := t.TempDir()
	scriptPath = filepath.Join(dir, "block_secret.py")
	if err := os.WriteFile(scriptPath, []byte(guardScript), 0o600); err != nil {
		t.Fatal(err)
	}
	policy.SetScriptDirs([]string{dir})
	t.Cleanup(func() { policy.SetScriptDirs(nil) })
	return py, scriptPath
}

func gmailRegistry() *connector.Registry {
	reg := connector.NewRegistry()
	reg.Register(gmail.Meta, gmail.Factory)
	return reg
}

// TestDecide_ScriptConditionGatesGrant proves a rule's script-mode CONDITION
// (spec §5.4) is executed by the live PDP and gates the grant: a script that
// returns deny makes the rule not apply, so the request is denied; a clean body
// is allowed. This is "arbitrary operator logic as a rule condition,
// authored ⇒ enforced".
func TestDecide_ScriptConditionGatesGrant(t *testing.T) {
	py, scriptPath := scriptCondEnv(t)
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)

	spec := iampolicies.RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "google", OpScope: "write",
		ConditionMode:   "script",
		ConditionScript: iampolicies.ScriptCondSpec{Command: py, Path: scriptPath},
	}
	grant, err := iampolicies.BuildRuleCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy("send-scripted", "", grant, true); err != nil {
		t.Fatal(err)
	}

	reg := gmailRegistry()
	send := func(role, body string) *policy.PolicyDecision {
		d, err := svc.Decide(context.Background(), reg, "tok", []string{role}, "google", "work", "active", "send_email",
			map[string]any{"to": []string{"a@b.com"}, "subject": "s", "body": body})
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
		return d
	}

	if d := send("R", "hello team, status update"); d.Action != "allow" {
		t.Errorf("clean send: got %q (reason %q), want allow", d.Action, d.Reason)
	}
	if d := send("R", "here is the secret launch plan"); d.Action != "deny" {
		t.Errorf("send with 'secret': got %q, want deny", d.Action)
	}
}

// TestDecide_ScriptConditionPerGrant proves the per-grant semantic: a script
// condition vetoes ONLY ITS grant, not the whole request. A token holding both a
// scripted rule (denies "secret") and a plain rule (no condition) for the same
// send is ALLOWED even on a secret body — the plain grant survives. A token with
// only the scripted rule is denied. (spec §5.4 / §7.3 union-of-grants.)
func TestDecide_ScriptConditionPerGrant(t *testing.T) {
	py, scriptPath := scriptCondEnv(t)
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)

	// Scripted rule on role "both" + a plain allow-write rule on role "both".
	scripted, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: "both", Effect: "allow", ConnectorType: "google", OpScope: "write",
		ConditionMode:   "script",
		ConditionScript: iampolicies.ScriptCondSpec{Command: py, Path: scriptPath},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: "both", Effect: "allow", ConnectorType: "google", OpScope: "write",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// And a role that has ONLY the scripted rule.
	scriptedOnly, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: "scripted", Effect: "allow", ConnectorType: "google", OpScope: "write",
		ConditionMode:   "script",
		ConditionScript: iampolicies.ScriptCondSpec{Command: py, Path: scriptPath},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]string{"both-scripted": scripted, "both-plain": plain, "scripted-only": scriptedOnly} {
		if _, err := svc.CreatePolicy(name, "", c, true); err != nil {
			t.Fatal(err)
		}
	}

	reg := gmailRegistry()
	send := func(role, body string) string {
		d, err := svc.Decide(context.Background(), reg, "tok", []string{role}, "google", "work", "active", "send_email",
			map[string]any{"to": []string{"a@b.com"}, "subject": "s", "body": body})
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
		return d.Action
	}

	// role "both": the plain grant survives the script veto → allowed even on secret.
	if a := send("both", "the secret plan"); a != "allow" {
		t.Errorf("per-grant: a plain co-grant must keep the request allowed; got %q", a)
	}
	// role "scripted": only the scripted grant matches → vetoed → deny.
	if a := send("scripted", "the secret plan"); a != "deny" {
		t.Errorf("script-only role with a secret body must be denied; got %q", a)
	}
	if a := send("scripted", "clean status"); a != "allow" {
		t.Errorf("script-only role with a clean body must be allowed; got %q", a)
	}
}

// approvalScript: a script-mode condition that asks for human approval.
const approvalScript = `import sys, json
json.load(sys.stdin)
print(json.dumps({"action": "approval_required"}))
`

// TestDecide_ScriptConditionApproval proves a script condition that returns
// "approval_required" surfaces as an approval-gated decision (spec §5.4).
func TestDecide_ScriptConditionApproval(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	policy.SetCommandAllowlist([]string{py})
	t.Cleanup(func() { policy.SetCommandAllowlist(nil) })
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "ask.py")
	if err := os.WriteFile(scriptPath, []byte(approvalScript), 0o600); err != nil {
		t.Fatal(err)
	}
	policy.SetScriptDirs([]string{dir})
	t.Cleanup(func() { policy.SetScriptDirs(nil) })

	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)
	grant, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "google", OpScope: "write",
		ConditionMode:   "script",
		ConditionScript: iampolicies.ScriptCondSpec{Command: py, Path: scriptPath},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy("send-ask", "", grant, true); err != nil {
		t.Fatal(err)
	}
	d, err := svc.Decide(context.Background(), gmailRegistry(), "tok", []string{"R"}, "google", "work", "active", "send_email",
		map[string]any{"to": []string{"a@b.com"}, "subject": "s", "body": "x"})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if d.Action != "approval_required" {
		t.Errorf("script returning approval_required → got %q, want approval_required", d.Action)
	}
}
