package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Spec 001-fix-security-vulns US6 (was AUTHZ-VULN-10): the numeric
// match fields max_tokens / max_count / max_vms / max_temperature are
// CEILINGS — a rule fires when the request value is at-or-below the
// configured value. The evaluator implements this correctly. The
// operator footgun is composition: writing
//   {action: deny, match: {max_tokens: 500}}, default_action: allow
// reads like "deny anything over 500" but means "deny anything <= 500,
// fall through for > 500" — the inverse of intent.
//
// DenyCeilingLint flags that composition so the save flow can surface
// a warning + the safer composition + require explicit acknowledgement.
// FR-022..FR-024b. The acknowledgement is sticky per policy via a
// fingerprint of the offending shape (FR-024a) — re-fires only when
// the deny rules / ceiling values / default action change.

// LintRuleName identifies the deny-ceiling lint in stored acks.
const LintRuleName = "deny_ceiling_v1"

// ceilingFields names the numeric match fields that exhibit the
// ceiling-not-threshold semantics described above.
var ceilingFields = []string{"max_tokens", "max_count", "max_vms", "max_temperature"}

// LintOffender describes a single offending rule found by the lint.
type LintOffender struct {
	RuleIndex  int            `json:"rule_index"`  // 1-based; matches operator-facing "rule 1, rule 2..."
	MatchField string         `json:"match_field"` // e.g., "max_tokens"
	Ceiling    any            `json:"ceiling"`     // operator-supplied limit value
}

// LintWarning is the structured payload returned to the save endpoint
// and (via JSON) to the API caller. Matches contracts/lint-api.md.
type LintWarning struct {
	Rule                    string         `json:"rule"`
	Severity                string         `json:"severity"`
	Title                   string         `json:"title"`
	Detail                  string         `json:"detail"`
	Offending               []LintOffender `json:"offending"`
	SaferComposition        map[string]any `json:"safer_composition"`
	AcknowledgementRequired bool           `json:"acknowledgement_required"`
	Fingerprint             string         `json:"fingerprint"`
}

// DenyCeilingLint inspects `config` for the deny-with-ceiling composition.
// Returns nil if the lint does not fire (no warning needed), or a
// populated *LintWarning otherwise. policyType ("rules", "chain",
// "composite") drives nested traversal.
func DenyCeilingLint(policyType string, config map[string]any) *LintWarning {
	switch policyType {
	case "rules":
		return lintRulesConfig(config)
	case "chain", "composite":
		// chain / composite policies hold sub-policies under "policies"
		// (the chain.NewChainEvaluator convention) or "evaluators".
		// We walk both shapes; lints fire independently per sub-policy.
		return lintNestedConfig(config)
	default:
		return nil
	}
}

// lintRulesConfig fires on a top-level rules-type config when the
// deny + ceiling + non-deny-default composition is present.
func lintRulesConfig(config map[string]any) *LintWarning {
	defAction, _ := config["default_action"].(string)
	// If default_action is "deny", the composition is the correct one
	// (allow-only-up-to-ceiling pattern); no lint.
	if defAction == "deny" {
		return nil
	}
	rulesRaw, _ := config["rules"].([]any)
	var offenders []LintOffender
	for i, ri := range rulesRaw {
		rm, ok := ri.(map[string]any)
		if !ok {
			continue
		}
		action, _ := rm["action"].(string)
		if action != "deny" {
			continue
		}
		match, _ := rm["match"].(map[string]any)
		for _, field := range ceilingFields {
			if val, present := match[field]; present {
				offenders = append(offenders, LintOffender{
					RuleIndex:  i + 1,
					MatchField: field,
					Ceiling:    val,
				})
			}
		}
	}
	if len(offenders) == 0 {
		return nil
	}
	fp := fingerprintRulesConfig(rulesRaw, defAction)
	return &LintWarning{
		Rule:     LintRuleName,
		Severity: "warning",
		Title:    "Deny rule with numeric ceiling has ceiling semantics, not threshold semantics",
		Detail: "The deny rule matches requests where the named field is at or below the configured value. " +
			"Requests above the value fall through to default_action. " +
			"To deny requests above the ceiling, use {action: allow, match: {field: N}} with default_action=deny.",
		Offending:               offenders,
		SaferComposition:        saferCompositionFor(offenders),
		AcknowledgementRequired: true,
		Fingerprint:             fp,
	}
}

// lintNestedConfig walks chain/composite sub-policy lists. Returns the
// first warning encountered (operators address one at a time; multiple
// would clutter the save flow).
func lintNestedConfig(config map[string]any) *LintWarning {
	for _, key := range []string{"policies", "evaluators"} {
		subs, ok := config[key].([]any)
		if !ok {
			continue
		}
		for _, si := range subs {
			sm, ok := si.(map[string]any)
			if !ok {
				continue
			}
			subType, _ := sm["type"].(string)
			subCfg, _ := sm["config"].(map[string]any)
			if w := DenyCeilingLint(subType, subCfg); w != nil {
				return w
			}
		}
	}
	return nil
}

// fingerprintRulesConfig returns a canonical SHA-256 of the shape that
// drives FR-024a's sticky-acknowledgement semantics. Two policies that
// differ only in cosmetic ways (name, comments, unrelated rules) produce
// the SAME fingerprint, so a re-save with no real change doesn't re-warn.
// Two policies that change the deny rules / ceiling values / default
// action produce a DIFFERENT fingerprint, so the warning re-fires.
func fingerprintRulesConfig(rules []any, defAction string) string {
	// Project each rule to just the fields that influence the lint:
	//   - action (only "deny" matters here, but kept for clarity)
	//   - the ceiling match fields and their values
	type denyShape struct {
		Action  string         `json:"action"`
		Ceiling map[string]any `json:"ceiling"`
	}
	var projected []denyShape
	for _, ri := range rules {
		rm, ok := ri.(map[string]any)
		if !ok {
			continue
		}
		action, _ := rm["action"].(string)
		if action != "deny" {
			continue
		}
		match, _ := rm["match"].(map[string]any)
		ceiling := make(map[string]any)
		for _, f := range ceilingFields {
			if v, ok := match[f]; ok {
				ceiling[f] = v
			}
		}
		if len(ceiling) == 0 {
			continue
		}
		projected = append(projected, denyShape{Action: action, Ceiling: ceiling})
	}
	// Canonical sort: by serialized ceiling map (stable across rule
	// reordering when the same ceilings appear).
	sort.Slice(projected, func(i, j int) bool {
		a, _ := json.Marshal(projected[i].Ceiling)
		b, _ := json.Marshal(projected[j].Ceiling)
		return string(a) < string(b)
	})
	payload := map[string]any{
		"deny":           projected,
		"default_action": defAction,
	}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// saferCompositionFor renders the documented "right way" for each
// offending field — a small UI hint, not a programmatic rewrite.
func saferCompositionFor(offenders []LintOffender) map[string]any {
	rules := make([]any, 0, len(offenders))
	for _, o := range offenders {
		rules = append(rules, map[string]any{
			"action": "allow",
			"match":  map[string]any{o.MatchField: o.Ceiling},
		})
	}
	return map[string]any{
		"default_action": "deny",
		"rules":          rules,
	}
}

// AckPayload is the value stored in policies.lint_ack[<rule_name>]
// when an operator acknowledges a lint warning. The fingerprint enables
// the sticky behavior — a future save that produces the same fingerprint
// is silently allowed; a save that produces a different fingerprint
// re-fires the warning.
type AckPayload struct {
	AcknowledgedAt string `json:"acknowledged_at"`
	By             string `json:"by"`
	Fingerprint    string `json:"fingerprint"`
}

// StickyAcknowledgmentMatches returns true if the stored lint_ack
// payload for the given rule covers the current fingerprint. When true,
// the save should proceed without requiring a fresh ack.
func StickyAcknowledgmentMatches(storedAck map[string]any, ruleName, currentFingerprint string) bool {
	if storedAck == nil {
		return false
	}
	raw, ok := storedAck[ruleName].(map[string]any)
	if !ok {
		return false
	}
	fp, _ := raw["fingerprint"].(string)
	return fp != "" && fp == currentFingerprint
}

// String makes LintWarning printable in error contexts.
func (w *LintWarning) String() string {
	if w == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", w.Title, w.Detail)
}
