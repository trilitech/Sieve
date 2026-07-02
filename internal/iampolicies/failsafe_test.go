package iampolicies

import (
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iam"
)

// These tests pin the B2 fix (review): a conditional approval/deny OVERLAY layered
// on a broad allow must not fail OPEN when an agent-controlled param forces the
// condition to error (wrong type or a missing attribute). Cedar skips an errored
// policy; the engine's fail-safe (spec §7.6) then forces the restriction to apply.

func mustCedar(t *testing.T, spec RuleSpec) string {
	t.Helper()
	c, err := BuildRuleCedar(spec, nil)
	if err != nil {
		t.Fatalf("build cedar: %v", err)
	}
	return c
}

func amountReq(params map[string]any) iam.Request {
	return iam.BuildRequest("tok", []string{"R"}, "anthropic", "ap", "active",
		connector.OperationDef{Name: "messages_create"}, params)
}

// TestEngineFailSafe_ApprovalOverlay: "allow all" + "require approval when
// amount>1000". An over-cap integer requires approval normally; a decimal (can't
// compare to the Long threshold → error) and a missing attribute must STILL
// require approval (fail-safe), never slip through as a plain allow.
func TestEngineFailSafe_ApprovalOverlay(t *testing.T) {
	broad := mustCedar(t, RuleSpec{RoleID: "R", Effect: "allow", ConnectorType: "anthropic", OpScope: "all"})
	overlay := mustCedar(t, RuleSpec{RoleID: "R", Effect: "require_approval", ConnectorType: "anthropic", OpScope: "all",
		Conditions: []ConditionInput{{Kind: "number", CtxPath: "context.param.amount", Op: "gt", Value: "1000"}}})
	eng := decideEngine(t, broad+"\n"+overlay)

	decide := func(params map[string]any) (allow, approval bool) {
		d, err := eng.Decide(amountReq(params))
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
		return d.Allow, d.Obligations.Approval
	}

	if a, ap := decide(map[string]any{"amount": 2000}); !a || !ap {
		t.Errorf("amount 2000 > 1000 should require approval; allow=%v approval=%v", a, ap)
	}
	if a, ap := decide(map[string]any{"amount": 1000.01}); !a || !ap {
		t.Errorf("decimal 1000.01 must still require approval (fail-safe on type error); allow=%v approval=%v", a, ap)
	}
	if a, ap := decide(map[string]any{}); !a || !ap {
		t.Errorf("missing amount must still require approval (fail-safe); allow=%v approval=%v", a, ap)
	}
	if a, ap := decide(map[string]any{"amount": 500}); !a || ap {
		t.Errorf("amount 500 <= 1000 should be a plain allow; allow=%v approval=%v", a, ap)
	}
}

// TestEngineFailSafe_ForbidOverlay: "allow all" + a raw-Cedar "forbid when
// amount>1000". A decimal / missing amount errors the forbid; the engine must
// fail-safe to DENY rather than skipping the forbid and allowing.
func TestEngineFailSafe_ForbidOverlay(t *testing.T) {
	broad := mustCedar(t, RuleSpec{RoleID: "R", Effect: "allow", ConnectorType: "anthropic", OpScope: "all"})
	forbid := `forbid(principal in Sieve::Role::"R", action, resource) when { context.param.amount > 1000 };`
	eng := decideEngine(t, broad+"\n"+forbid)

	allowed := func(params map[string]any) bool {
		d, err := eng.Decide(amountReq(params))
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
		return d.Allow
	}

	if allowed(map[string]any{"amount": 2000}) {
		t.Error("amount 2000 > 1000 must be denied by the forbid")
	}
	if allowed(map[string]any{"amount": 1000.01}) {
		t.Error("decimal 1000.01 must be denied — errored forbid fails safe to deny, not open")
	}
	if allowed(map[string]any{}) {
		t.Error("missing amount must be denied — errored forbid fails safe to deny")
	}
	if !allowed(map[string]any{"amount": 500}) {
		t.Error("amount 500 <= 1000 should be allowed (forbid does not match)")
	}
}

// TestBuildRuleCedar_RejectsApprovalInScriptMode pins M6: a script-condition rule
// decides allow/deny/approval itself, so require_approval + script mode (whose
// @approval the engine would silently drop) is rejected at build time.
func TestBuildRuleCedar_RejectsApprovalInScriptMode(t *testing.T) {
	_, err := BuildRuleCedar(RuleSpec{
		RoleID: "R", Effect: "require_approval", ConnectorType: "mock", OpScope: "all",
		ConditionMode: "script", ConditionScript: ScriptCondSpec{Command: "python3", Path: "/opt/sieve-py/x.py"},
	}, nil)
	if err == nil {
		t.Fatal("require_approval + script mode must be rejected at build time")
	}
}
