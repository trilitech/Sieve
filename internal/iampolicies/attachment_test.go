package iampolicies_test

import (
	"testing"

	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/policy"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// defineRedactSSN stores a REUSABLE transform definition (a filter-library entry)
// that masks US SSNs. It carries no scope — scope comes from each attachment.
func defineRedactSSN(t *testing.T, svc *iampolicies.Service, name string) {
	t.Helper()
	if _, err := svc.CreateFilter(name, "redact SSNs", iam.KindRedact, 20,
		map[string]any{"patterns": []string{`\d{3}-\d{2}-\d{4}`}, "match": "regex"}); err != nil {
		t.Fatal(err)
	}
}

// attachRedact binds a definition to a scope (roleID "" ⇒ global) on read ops via
// @filters — the by-reference attachment that restores reuse across roles.
func attachRedact(t *testing.T, svc *iampolicies.Service, defName, roleID string) {
	t.Helper()
	cedar, err := iampolicies.BuildAttachmentCedar(iampolicies.AttachmentSpec{
		TransformName: defName, RoleID: roleID, ConnectorType: "mock", OpScope: "read",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateTransform(defName, "", cedar, "", true); err != nil {
		t.Fatal(err)
	}
}

// TestAttachment_ReadWithPiiRemoved is read_with_pii_removed as an ATTACHMENT: one
// reusable definition attached to the "pii" role. A token holding "pii" reads
// redacted even alongside an unredacted-read role; without "pii" it reads raw.
func TestAttachment_ReadWithPiiRemoved(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)
	allowRead(t, svc, "full") // read_everything
	allowRead(t, svc, "pii")  // read_with_pii_removed also grants the read
	defineRedactSSN(t, svc, "redact-ssn")
	attachRedact(t, svc, "redact-ssn", "pii")

	if d := decideRead(t, svc, []string{"full", "pii"}); !hasRedact(d) {
		t.Errorf("token in {full, pii} should read redacted (the attached transform applies)")
	}
	if d := decideRead(t, svc, []string{"full"}); hasRedact(d) {
		t.Errorf("token in {full} only must read raw (the redacting role isn't held)")
	}
}

// TestAttachment_ReuseAcrossRoles is the reuse proof: ONE definition attached to
// two different roles applies for a token in either — without copying the
// definition. (Standalone scoped transforms couldn't do this.)
func TestAttachment_ReuseAcrossRoles(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)
	allowRead(t, svc, "A")
	allowRead(t, svc, "B")
	allowRead(t, svc, "C")
	defineRedactSSN(t, svc, "redact-ssn") // defined ONCE
	attachRedact(t, svc, "redact-ssn", "A")
	attachRedact(t, svc, "redact-ssn", "B") // same definition, second role

	if d := decideRead(t, svc, []string{"A"}); !hasRedact(d) {
		t.Errorf("role A's attachment should apply")
	}
	if d := decideRead(t, svc, []string{"B"}); !hasRedact(d) {
		t.Errorf("role B's attachment (same definition) should apply")
	}
	if d := decideRead(t, svc, []string{"C"}); hasRedact(d) {
		t.Errorf("role C has no attachment — should read raw")
	}
}

// TestAttachment_Global proves a global attachment (no role) applies to any token
// — the floor the old global guardrail provided.
func TestAttachment_Global(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)
	allowRead(t, svc, "R")
	defineRedactSSN(t, svc, "redact-ssn")
	attachRedact(t, svc, "redact-ssn", "") // global
	if d := decideRead(t, svc, []string{"R"}); !hasRedact(d) {
		t.Errorf("a global attachment should apply to any token's matching read")
	}
}

// redactPatternSet flattens the redact patterns carried by a decision's filters.
func redactPatternSet(d *policy.PolicyDecision) map[string]bool {
	out := map[string]bool{}
	for _, f := range d.Filters {
		for _, p := range f.RedactPatterns {
			out[p] = true
		}
	}
	return out
}

// TestAttachment_EditDefinitionAffectsAllAttachments proves the reuse value:
// editing the ONE definition changes what every attachment resolves to. Both
// roles reference the same definition, so editing its pattern flows to both.
func TestAttachment_EditDefinitionAffectsAllAttachments(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)
	allowRead(t, svc, "A")
	allowRead(t, svc, "B")
	defineRedactSSN(t, svc, "redact-ssn")
	attachRedact(t, svc, "redact-ssn", "A")
	attachRedact(t, svc, "redact-ssn", "B")
	if !redactPatternSet(decideRead(t, svc, []string{"A"}))[`\d{3}-\d{2}-\d{4}`] {
		t.Fatal("precondition: A should resolve the SSN pattern before the edit")
	}
	// Edit the ONE definition; both attachments must reflect the new pattern.
	if err := svc.UpdateFilter("redact-ssn", "new pattern", iam.KindRedact, 20,
		map[string]any{"patterns": []string{`CARD-\d+`}, "match": "regex"}); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"A", "B"} {
		set := redactPatternSet(decideRead(t, svc, []string{role}))
		if set[`\d{3}-\d{2}-\d{4}`] {
			t.Errorf("role %s still resolves the OLD pattern after the definition edit", role)
		}
		if !set[`CARD-\d+`] {
			t.Errorf("role %s should resolve the NEW pattern (edit flowed through the shared definition)", role)
		}
	}
}
