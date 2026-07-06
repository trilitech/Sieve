package web

import (
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iampolicies"
)

// metaFixture is a small connector meta with two ops (one read-only) and one
// op-scoped condition, used to exercise authoring-time validation.
func metaFixture() connector.ConnectorMeta {
	return connector.ConnectorMeta{
		Type: "mock",
		Operations: []connector.OperationDef{
			{Name: "list_things", ReadOnly: true},
			{Name: "send_thing"},
		},
		RuleConditions: []connector.RuleCondition{
			{Key: "recipient_count", Label: "Recipient count", Kind: "number",
				CtxPath: "context.param.recipient_count", Ops: []string{"send_thing"}},
		},
	}
}

func TestValidateRuleSpec_UnknownOperationRejected(t *testing.T) {
	spec := iampolicies.RuleSpec{
		ConnectorType: "mock", Effect: "allow", OpScope: "specific",
		Operations: []string{"send_thing", "not_a_real_op"},
	}
	perr := validateRuleSpec(spec, metaFixture())
	if perr == nil {
		t.Fatal("expected an unknown-operation rejection, got nil")
	}
	if !strings.Contains(perr.msg, "not_a_real_op") {
		t.Fatalf("error should name the bad op; got %q", perr.msg)
	}
}

func TestValidateRuleSpec_UndeclaredConditionRejected(t *testing.T) {
	spec := iampolicies.RuleSpec{
		ConnectorType: "mock", Effect: "allow", OpScope: "all",
		Conditions: []iampolicies.ConditionInput{
			{Kind: "number", CtxPath: "context.param.nonexistent", Op: "lte", Value: "5"},
		},
	}
	perr := validateRuleSpec(spec, metaFixture())
	if perr == nil {
		t.Fatal("expected an undeclared-condition rejection, got nil")
	}
	if !strings.Contains(perr.msg, "context.param.nonexistent") {
		t.Fatalf("error should name the undeclared condition; got %q", perr.msg)
	}
}

func TestValidateRuleSpec_OpScopedConditionOnWrongOpsRejected(t *testing.T) {
	// The condition only applies to send_thing, but the rule is scoped to
	// list_things — the compiled guard would make it vacuous, so reject.
	spec := iampolicies.RuleSpec{
		ConnectorType: "mock", Effect: "allow", OpScope: "specific",
		Operations: []string{"list_things"},
		Conditions: []iampolicies.ConditionInput{
			{Kind: "number", CtxPath: "context.param.recipient_count", Op: "lte", Value: "5",
				Ops: []string{"send_thing"}},
		},
	}
	perr := validateRuleSpec(spec, metaFixture())
	if perr == nil {
		t.Fatal("expected an inapplicable-condition rejection, got nil")
	}
	if !strings.Contains(perr.msg, "never take effect") {
		t.Fatalf("error should explain it never fires; got %q", perr.msg)
	}
}

func TestValidateRuleSpec_ValidSpecsAccepted(t *testing.T) {
	// (i) specific op that exists, no conditions.
	if perr := validateRuleSpec(iampolicies.RuleSpec{
		ConnectorType: "mock", Effect: "allow", OpScope: "specific",
		Operations: []string{"send_thing"},
	}, metaFixture()); perr != nil {
		t.Fatalf("valid specific-op spec rejected: %q", perr.msg)
	}
	// (ii) op-scoped condition on a rule scoped to the matching op.
	if perr := validateRuleSpec(iampolicies.RuleSpec{
		ConnectorType: "mock", Effect: "allow", OpScope: "specific",
		Operations: []string{"send_thing"},
		Conditions: []iampolicies.ConditionInput{
			{Kind: "number", CtxPath: "context.param.recipient_count", Op: "lte", Value: "5",
				Ops: []string{"send_thing"}},
		},
	}, metaFixture()); perr != nil {
		t.Fatalf("valid op-scoped-condition spec rejected: %q", perr.msg)
	}
	// (iii) op-scoped condition on an all-ops rule (guard handles applicability).
	if perr := validateRuleSpec(iampolicies.RuleSpec{
		ConnectorType: "mock", Effect: "allow", OpScope: "all",
		Conditions: []iampolicies.ConditionInput{
			{Kind: "number", CtxPath: "context.param.recipient_count", Op: "lte", Value: "5",
				Ops: []string{"send_thing"}},
		},
	}, metaFixture()); perr != nil {
		t.Fatalf("valid all-ops spec rejected: %q", perr.msg)
	}
}
