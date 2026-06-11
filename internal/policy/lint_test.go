package policy

import (
	"testing"
)

// with numeric-ceiling match fields combined with a non-deny default
// action are an operator footgun; the lint flags them.

func TestDenyCeilingLint_FiresOnMaxTokensCeiling(t *testing.T) {
	cfg := map[string]any{
		"default_action": "allow",
		"rules": []any{
			map[string]any{"action": "deny", "match": map[string]any{"max_tokens": 500}},
		},
	}
	w := DenyCeilingLint("rules", cfg)
	if w == nil {
		t.Fatal("lint should fire on deny+max_tokens+default=allow")
	}
	if w.Rule != LintRuleName {
		t.Errorf("Rule = %q, want %q", w.Rule, LintRuleName)
	}
	if len(w.Offending) != 1 || w.Offending[0].MatchField != "max_tokens" {
		t.Errorf("offending = %v", w.Offending)
	}
}

func TestDenyCeilingLint_FiresOnEachCeilingField(t *testing.T) {
	// Every numeric-ceiling match field defined in rules.go's matchRule
	// must appear here. max_cost was missed in the first cut and slipped
	// through as the same footgun under a different name — keep this
	// list in sync with ceilingFields.
	for _, field := range []string{"max_tokens", "max_count", "max_vms", "max_temperature", "max_cost"} {
		t.Run(field, func(t *testing.T) {
			cfg := map[string]any{
				"default_action": "allow",
				"rules": []any{
					map[string]any{"action": "deny", "match": map[string]any{field: 1}},
				},
			}
			if DenyCeilingLint("rules", cfg) == nil {
				t.Errorf("expected fire on %s", field)
			}
		})
	}
}

func TestDenyCeilingLint_FiresOnMaxCostCeiling(t *testing.T) {
	// Direct regression for the deny+max_cost+default=allow trap. An
	// operator writing this composition intends "deny anything over $1.00"
	// but actually gets "deny calls ≤ $1.00, allow the $1000 call".
	cfg := map[string]any{
		"default_action": "allow",
		"rules": []any{
			map[string]any{"action": "deny", "match": map[string]any{"max_cost": 1.00}},
		},
	}
	w := DenyCeilingLint("rules", cfg)
	if w == nil {
		t.Fatal("lint should fire on deny+max_cost+default=allow")
	}
	if len(w.Offending) != 1 || w.Offending[0].MatchField != "max_cost" {
		t.Errorf("offending = %v, want one entry for max_cost", w.Offending)
	}
}

func TestDenyCeilingLint_NoFireOnDenyDefault(t *testing.T) {
	// The CORRECT composition — default=deny means the deny-rule's
	// only effect is documented; no ceiling-inversion trap.
	cfg := map[string]any{
		"default_action": "deny",
		"rules": []any{
			map[string]any{"action": "deny", "match": map[string]any{"max_tokens": 500}},
		},
	}
	if w := DenyCeilingLint("rules", cfg); w != nil {
		t.Errorf("lint should NOT fire when default_action=deny; got %v", w)
	}
}

func TestDenyCeilingLint_NoFireOnAllowWithCeiling(t *testing.T) {
	// The safe pattern: allow + ceiling + default=deny.
	cfg := map[string]any{
		"default_action": "deny",
		"rules": []any{
			map[string]any{"action": "allow", "match": map[string]any{"max_tokens": 500}},
		},
	}
	if w := DenyCeilingLint("rules", cfg); w != nil {
		t.Errorf("lint should NOT fire on allow+ceiling+default=deny; got %v", w)
	}
}

func TestDenyCeilingLint_NoFireOnDenyWithoutCeiling(t *testing.T) {
	// Deny rule that doesn't touch any ceiling field — no trap.
	cfg := map[string]any{
		"default_action": "allow",
		"rules": []any{
			map[string]any{"action": "deny", "match": map[string]any{"operations": []any{"sensitive_op"}}},
		},
	}
	if w := DenyCeilingLint("rules", cfg); w != nil {
		t.Errorf("lint should NOT fire on deny w/o ceiling; got %v", w)
	}
}

func TestDenyCeilingLint_NoFireOnNonRulesType(t *testing.T) {
	if w := DenyCeilingLint("script", map[string]any{"command": "/opt/sieve-py/bin/python3"}); w != nil {
		t.Errorf("script policy should not lint")
	}
}

func TestDenyCeilingLint_FingerprintStable_AcrossSameComposition(t *testing.T) {
	base := map[string]any{
		"default_action": "allow",
		"rules": []any{
			map[string]any{"action": "deny", "match": map[string]any{"max_tokens": 500}},
		},
	}
	w1 := DenyCeilingLint("rules", base)
	w2 := DenyCeilingLint("rules", base)
	if w1 == nil || w2 == nil {
		t.Fatal("setup: both lints should fire")
	}
	if w1.Fingerprint != w2.Fingerprint {
		t.Errorf("fingerprints diverge for identical configs: %q vs %q", w1.Fingerprint, w2.Fingerprint)
	}
}

func TestDenyCeilingLint_FingerprintChanges_OnCeilingChange(t *testing.T) {
	a := map[string]any{
		"default_action": "allow",
		"rules":          []any{map[string]any{"action": "deny", "match": map[string]any{"max_tokens": 500}}},
	}
	b := map[string]any{
		"default_action": "allow",
		"rules":          []any{map[string]any{"action": "deny", "match": map[string]any{"max_tokens": 1000}}},
	}
	if DenyCeilingLint("rules", a).Fingerprint == DenyCeilingLint("rules", b).Fingerprint {
		t.Error("changing the ceiling value MUST change the fingerprint")
	}
}

func TestDenyCeilingLint_FingerprintChanges_OnDefaultActionChange(t *testing.T) {
	a := map[string]any{
		"default_action": "allow",
		"rules":          []any{map[string]any{"action": "deny", "match": map[string]any{"max_tokens": 500}}},
	}
	wA := DenyCeilingLint("rules", a)
	// Flip default to "approval_required" — still a non-deny default
	// so the lint still fires; the fingerprint MUST change.
	a["default_action"] = "approval_required"
	wB := DenyCeilingLint("rules", a)
	if wA == nil || wB == nil {
		t.Fatal("setup: both lints should fire")
	}
	if wA.Fingerprint == wB.Fingerprint {
		t.Error("changing default_action MUST change the fingerprint")
	}
}

func TestDenyCeilingLint_FingerprintStable_OnUnrelatedRuleReorder(t *testing.T) {
	// Two configs with the same deny+ceiling rule but different
	// ordering of unrelated rules. Fingerprint must match.
	a := map[string]any{
		"default_action": "allow",
		"rules": []any{
			map[string]any{"action": "allow", "match": map[string]any{"operations": []any{"a"}}},
			map[string]any{"action": "deny", "match": map[string]any{"max_tokens": 500}},
			map[string]any{"action": "allow", "match": map[string]any{"operations": []any{"b"}}},
		},
	}
	b := map[string]any{
		"default_action": "allow",
		"rules": []any{
			map[string]any{"action": "deny", "match": map[string]any{"max_tokens": 500}},
			map[string]any{"action": "allow", "match": map[string]any{"operations": []any{"b"}}},
			map[string]any{"action": "allow", "match": map[string]any{"operations": []any{"a"}}},
		},
	}
	if DenyCeilingLint("rules", a).Fingerprint != DenyCeilingLint("rules", b).Fingerprint {
		t.Error("reordering unrelated rules must NOT change the fingerprint")
	}
}

func TestStickyAcknowledgmentMatches(t *testing.T) {
	ack := map[string]any{
		LintRuleName: map[string]any{
			"acknowledged_at": "2026-05-26T00:00:00Z",
			"by":              "alice",
			"fingerprint":     "sha256:abc",
		},
	}
	if !StickyAcknowledgmentMatches(ack, LintRuleName, "sha256:abc") {
		t.Error("matching fingerprint should be sticky")
	}
	if StickyAcknowledgmentMatches(ack, LintRuleName, "sha256:different") {
		t.Error("differing fingerprint MUST NOT match sticky ack")
	}
	if StickyAcknowledgmentMatches(nil, LintRuleName, "sha256:abc") {
		t.Error("nil ack MUST NOT match")
	}
	if StickyAcknowledgmentMatches(ack, "other_rule_v1", "sha256:abc") {
		t.Error("ack for different rule MUST NOT match")
	}
}

func TestDenyCeilingLint_FiresOnChainSubPolicy(t *testing.T) {
	// chain wraps two sub-policies; the second has the offending shape.
	cfg := map[string]any{
		"policies": []any{
			map[string]any{
				"type":   "rules",
				"config": map[string]any{"default_action": "deny", "rules": []any{}},
			},
			map[string]any{
				"type": "rules",
				"config": map[string]any{
					"default_action": "allow",
					"rules":          []any{map[string]any{"action": "deny", "match": map[string]any{"max_tokens": 500}}},
				},
			},
		},
	}
	if w := DenyCeilingLint("chain", cfg); w == nil {
		t.Error("lint should walk into chain sub-policies")
	}
}
