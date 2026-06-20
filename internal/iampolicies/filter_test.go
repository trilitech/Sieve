package iampolicies_test

import (
	"testing"

	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

func TestFilterInUse(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)

	if _, err := svc.CreateFilter("used", "", iam.KindRedact, 0, map[string]any{"patterns": []any{"x"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateFilter("unused", "", iam.KindRedact, 0, map[string]any{"patterns": []any{"y"}}); err != nil {
		t.Fatal(err)
	}
	cedar, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "mock", OpScope: "read",
		Filters: []string{"used"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy("p", "", cedar, true); err != nil {
		t.Fatal(err)
	}

	if inUse, _ := svc.FilterInUse("used"); !inUse {
		t.Error("an attached filter should report in-use")
	}
	if inUse, _ := svc.FilterInUse("unused"); inUse {
		t.Error("an unattached filter should not report in-use")
	}
}
