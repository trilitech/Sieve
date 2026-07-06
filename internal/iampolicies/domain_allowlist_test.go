package iampolicies

import "testing"

// TestConditionExpr_DomainAllowlistLowercased pins (reviewer a): domain allowlist
// literals must be folded to lower case, because they compare against
// connector-enriched domains that are already lowercased and Cedar string
// equality is case-sensitive. Otherwise `Example.COM` never matches `example.com`
// — an allowlist silently denies and a blocklist silently lets everything by.
func TestConditionExpr_DomainAllowlistLowercased(t *testing.T) {
	got, err := conditionExpr(ConditionInput{
		Kind:    "domain_allowlist",
		CtxPath: "context.recipient_domains",
		Value:   "Example.COM, Foo.ORG",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `["example.com", "foo.org"].containsAll(context.recipient_domains)`
	if got != want {
		t.Errorf("domain allowlist not lowercased:\n got %s\nwant %s", got, want)
	}
}
