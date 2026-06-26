package iampolicies_test

import (
	"context"
	"testing"

	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/policy"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// allowRead stores an allow-read rule for a role so reads are permitted and a
// transform's effect on the response can be observed.
func allowRead(t *testing.T, svc *iampolicies.Service, role string) {
	t.Helper()
	cedar, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: role, Effect: "allow", ConnectorType: "mock", OpScope: "read",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy("allow-read-"+role, "", cedar, true); err != nil {
		t.Fatal(err)
	}
}

// redactTransform stores a scoped redact transform (roleID "" ⇒ global) on read
// ops, with an SSN pattern.
func redactTransform(t *testing.T, svc *iampolicies.Service, name, roleID string) {
	t.Helper()
	cedar, err := iampolicies.BuildTransformCedar(iampolicies.TransformSpec{
		RoleID: roleID, ConnectorType: "mock", OpScope: "read", Kind: iam.KindRedact,
		Config: map[string]any{"patterns": []string{`\d{3}-\d{2}-\d{4}`}, "match": "regex"}, Rank: 20,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateTransform(name, "", cedar, "", true); err != nil {
		t.Fatal(err)
	}
}

func decideRead(t *testing.T, svc *iampolicies.Service, roles []string) *policy.PolicyDecision {
	t.Helper()
	d, err := svc.Decide(context.Background(), approvalMockReg(), "tok", roles,
		"mock", "c", "active", "list_emails", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func hasRedact(d *policy.PolicyDecision) bool {
	for _, f := range d.Filters {
		if len(f.RedactPatterns) > 0 {
			return true
		}
	}
	return false
}

// TestDecide_ScopedTransform_Applies proves a role-scoped transform reaches the
// decision as a response filter (the inline @transform_* path, no filter library).
func TestDecide_ScopedTransform_Applies(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)
	allowRead(t, svc, "R")
	redactTransform(t, svc, "redact-ssn", "R")
	d := decideRead(t, svc, []string{"R"})
	if d.Action != "allow" {
		t.Fatalf("read should be allowed, got %q", d.Action)
	}
	if !hasRedact(d) {
		t.Errorf("a role-scoped redact transform should attach to the decision: %+v", d.Filters)
	}
}

// TestDecide_TransformRoleScoped_ReadWithPiiRemoved is the read_with_pii_removed
// pattern as a role-scoped transform: a token holding the redacting role reads
// redacted even when it ALSO holds an unredacted-read role; a token without the
// redacting role reads raw. (Transform unconditional ⇒ composition-safe.)
func TestDecide_TransformRoleScoped_ReadWithPiiRemoved(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)
	allowRead(t, svc, "full") // read_everything
	allowRead(t, svc, "pii")  // read_with_pii_removed also grants the read
	redactTransform(t, svc, "redact-ssn", "pii")

	if d := decideRead(t, svc, []string{"full", "pii"}); !hasRedact(d) {
		t.Errorf("token in {full, pii} should read redacted (the redacting role's transform applies)")
	}
	if d := decideRead(t, svc, []string{"full"}); hasRedact(d) {
		t.Errorf("token in {full} only must read raw (no redacting role held)")
	}
}

// TestDecide_GlobalTransform proves a global transform (no role) applies to any
// token — the floor the old global guardrail provided.
func TestDecide_GlobalTransform(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)
	allowRead(t, svc, "R")
	redactTransform(t, svc, "redact-ssn-global", "") // global
	if d := decideRead(t, svc, []string{"R"}); !hasRedact(d) {
		t.Errorf("a global transform should apply to any token's matching read")
	}
}
