package iam

import "testing"

// TestValidateRawCedarInvariants pins the raw-Cedar authoring guards (reviewer
// b, c): the escape hatch must not author a permit that grants to every token,
// nor an @approval value that silently drops the approval gate.
func TestValidateRawCedarInvariants(t *testing.T) {
	cases := []struct {
		name  string
		cedar string
		ok    bool
	}{
		{"role-scoped permit", `permit(principal in Sieve::Role::"r1", action, resource);`, true},
		{"broad forbid is fine (fail-safe)", `forbid(principal, action, resource);`, true},
		{"approval required (lower)", "@approval(\"required\")\npermit(principal in Sieve::Role::\"r1\", action, resource);", true},
		{"approval Required (mixed case accepted)", "@approval(\"Required\")\npermit(principal in Sieve::Role::\"r1\", action, resource);", true},
		{"unconstrained principal permit rejected", `permit(principal, action, resource);`, false},
		{"principal==Token rejected (not role-scoped)", `permit(principal == Sieve::Token::"t", action, resource);`, false},
		{"bad @approval value rejected", "@approval(\"sometime\")\npermit(principal in Sieve::Role::\"r1\", action, resource);", false},
	}
	for _, c := range cases {
		err := ValidateRawCedarInvariants(c.cedar)
		if c.ok && err != nil {
			t.Errorf("%s: unexpected rejection: %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: expected rejection, got nil", c.name)
		}
	}
}

// TestCollectObligations_ApprovalCaseInsensitive pins (b): a raw-Cedar
// @approval("Required") (any casing) must still set the approval obligation —
// an exact-string match would silently drop the human gate.
func TestCollectObligations_ApprovalCaseInsensitive(t *testing.T) {
	for _, v := range []string{"required", "Required", "REQUIRED"} {
		obl, err := collectObligations([]map[string]string{{"approval": v}}, MapFilterLibrary{})
		if err != nil {
			t.Fatalf("collectObligations(%q): %v", v, err)
		}
		if !obl.Approval {
			t.Errorf("@approval(%q) must set Approval (case-insensitive)", v)
		}
	}
}
