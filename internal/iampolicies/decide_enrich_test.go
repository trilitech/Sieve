package iampolicies_test

import (
	"context"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/connectors/gmail"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// TestDecide_GmailRecipientDomain proves the connector-tailored condition works
// END TO END through the live PDP: a domain_allowlist rule built in the UI →
// stored Cedar → Decide() → the Gmail Meta.EnrichContext derives
// recipient_domains from the send params → the rule's containsAll matches.
// This is the "tailored to the particularities of each connector" claim, tested.
func TestDecide_GmailRecipientDomain(t *testing.T) {
	env := testenv.New(t)
	svc := iampolicies.NewService(env.DB)

	cedar, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "google", OpScope: "write",
		Conditions: []iampolicies.ConditionInput{
			{Kind: "domain_allowlist", CtxPath: "context.recipient_domains", Value: "example.com"},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy("gmail-domains", "", cedar, true); err != nil {
		t.Fatal(err)
	}

	reg := connector.NewRegistry()
	reg.Register(gmail.Meta, gmail.Factory)

	decide := func(to string) string {
		d, err := svc.Decide(context.Background(), reg, "tok", "R", "google", "work", "active", "send_email",
			map[string]any{"to": []string{to}, "subject": "s", "body": "b"})
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
		return d.Action
	}

	if a := decide("alice@example.com"); a != "allow" {
		t.Errorf("send to allowed domain: got %q, want allow", a)
	}
	if a := decide("bob@evil.com"); a != "deny" {
		t.Errorf("send to disallowed domain: got %q, want deny", a)
	}
}
