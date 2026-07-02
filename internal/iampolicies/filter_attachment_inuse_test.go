package iampolicies_test

import (
	"testing"

	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// TestFilterInUse_Attachment is the regression test for the P2 dangling-reference
// bug: a reusable transform DEFINITION attached by reference (an @filters entry in
// iam_transforms, produced by BuildAttachmentCedar) must report in-use, so the
// admin UI won't delete it and leave an enabled attachment whose @filters can't be
// resolved (which would then fail-close matching requests). FilterInUse previously
// scanned only guardrails + policies, not attachments.
func TestFilterInUse_Attachment(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)

	if _, err := svc.CreateFilter("redact-ssn", "", iam.KindRedact, 20,
		map[string]any{"patterns": []string{`\d{3}-\d{2}-\d{4}`}, "match": "regex"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateFilter("unused", "", iam.KindRedact, 20,
		map[string]any{"patterns": []string{"x"}}); err != nil {
		t.Fatal(err)
	}

	// Attach "redact-ssn" via a by-reference ATTACHMENT (iam_transforms), not a guardrail.
	cedar, err := iampolicies.BuildAttachmentCedar(iampolicies.AttachmentSpec{
		TransformName: "redact-ssn", RoleID: "R", ConnectorType: "mock", OpScope: "read",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateTransform("redact-ssn", "", cedar, "", true); err != nil {
		t.Fatal(err)
	}

	if inUse, err := svc.FilterInUse("redact-ssn"); err != nil || !inUse {
		t.Errorf("a definition attached via an attachment should report in-use (got %v, err %v)", inUse, err)
	}
	if inUse, _ := svc.FilterInUse("unused"); inUse {
		t.Error("an unattached definition should not report in-use")
	}
}
