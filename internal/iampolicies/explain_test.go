package iampolicies_test

import (
	"context"
	"testing"

	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// explain is a thin wrapper around the decision explorer's Explain for a mock
// read with the given roles + request params.
func explain(t *testing.T, svc *iampolicies.Service, roles []string, params map[string]any) *iampolicies.ExplainResult {
	t.Helper()
	res, err := svc.Explain(context.Background(), approvalMockReg(), "explorer", roles,
		"mock", "c", "active", "list_emails", params)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestExplain_ParamsDriveConditions proves the explorer evaluates request PARAMS:
// an allow-read rule conditioned on context.param.model in {allowed} lets a
// matching model through and reports the determining rule by name, while a
// non-matching model falls through to default-deny.
func TestExplain_ParamsDriveConditions(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)

	cedar, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "mock", OpScope: "read",
		Conditions: []iampolicies.ConditionInput{
			{Kind: "one_of", CtxPath: "context.param.model", Value: "allowed"},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy("model-allow", "only the allowed model", cedar, true); err != nil {
		t.Fatal(err)
	}

	// model=allowed → allow, and the determining rule is named.
	res := explain(t, svc, []string{"R"}, map[string]any{"model": "allowed"})
	if res.Action != "allow" {
		t.Fatalf("model=allowed should allow, got %q (%s)", res.Action, res.Reason)
	}
	named := false
	for _, d := range res.Determining {
		if d.Name == "model-allow" {
			named = true
		}
	}
	if !named {
		t.Errorf("determining should name the rule model-allow, got %+v", res.Determining)
	}

	// model=other → the conditioned permit doesn't match → default deny.
	res2 := explain(t, svc, []string{"R"}, map[string]any{"model": "other"})
	if res2.Action == "allow" {
		t.Errorf("model=other must not allow, got %q", res2.Action)
	}
	if !res2.DefaultDeny {
		t.Errorf("model=other should be default-deny (no matching grant), got %+v", res2)
	}
}

// TestExplain_ReportsWouldRunTransforms proves the explorer lists the transforms
// that would run: a role-attached redact transform is reported by name + kind for
// a request that matches it.
func TestExplain_ReportsWouldRunTransforms(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)
	allowRead(t, svc, "R")
	defineRedactSSN(t, svc, "redact-ssn") // reusable definition
	attachRedact(t, svc, "redact-ssn", "R")

	res := explain(t, svc, []string{"R"}, map[string]any{})
	if res.Action != "allow" {
		t.Fatalf("expected allow, got %q (%s)", res.Action, res.Reason)
	}
	found := false
	for _, tr := range res.Transforms {
		if tr.Name == "redact-ssn" && tr.Kind == string(iam.KindRedact) {
			found = true
		}
	}
	if !found {
		t.Errorf("explorer should report redact-ssn (redact) as a would-run transform, got %+v", res.Transforms)
	}
}
