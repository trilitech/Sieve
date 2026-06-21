// Package iammigrate translates legacy internal/policy "rules" policies into
// Cedar policies + filter-library entries for the IAM engine (internal/iam).
//
// Scope (validated against the real legacy types): only the CLEAN, common case
// translates automatically — Operations-based allow/deny/approval rules and
// their ResponseFilters. The legacy RuleMatch has ~50 ad-hoc fields (globs,
// substring, response-content, per-service matchers); anything beyond
// Operations is reported as a manual-port item rather than mis-translated
// (fail-closed: the rule is omitted → narrows access, never widens). This is
// the migration mapping the spec's docs/architecture/iam/03-migration-plan.md
// §3 describes, with the H1 catch-all-deny guard.
package iammigrate

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/policy"
)

// Result is the output of migrating one legacy policy as bound to (role, conn).
type Result struct {
	Cedar      string       // the GRANT document (permit/forbid; may be empty if all default-deny)
	Guardrails string       // the GUARDRAIL document (permit-only @approval/@filters overlays); spec §7.2
	Filters    []iam.Filter // filter-library entries referenced by @filters
	Manual     []ManualItem // rules that need a human port (rich match, scripts, llm)
}

// ManualItem flags a rule/policy the migrator refused to auto-translate.
type ManualItem struct {
	PolicyID string
	Rule     int // -1 for whole-policy items
	Reason   string
}

// MigrateRulesBinding migrates a legacy "rules" policy as applied to one
// (role, connection) pair. connType is the connection's connector type (e.g.
// "google"), needed to derive action ids. Statements are scoped to
// `principal in Sieve::Role::"role"` and `resource in Sieve::Connection::"conn"`.
func MigrateRulesBinding(connType, role, conn string, p PolicyInput) (Result, error) {
	var cfg policy.RulesConfig
	buf, err := json.Marshal(p.Config)
	if err != nil {
		return Result{}, fmt.Errorf("iammigrate: marshal config for %q: %w", p.ID, err)
	}
	if err := json.Unmarshal(buf, &cfg); err != nil {
		return Result{}, fmt.Errorf("iammigrate: %q is not a rules policy: %w", p.ID, err)
	}

	var grants, guardrails []string
	var filters []iam.Filter
	var manual []ManualItem

	for i, r := range cfg.Rules {
		grant, guard, fs, man := translateRule(connType, role, conn, p.ID, i, r)
		if man != nil {
			manual = append(manual, *man)
			continue
		}
		if grant != "" {
			grants = append(grants, grant)
		}
		if guard != "" {
			guardrails = append(guardrails, guard)
		}
		filters = append(filters, fs...)
	}

	// DefaultAction: "deny" (or empty) → nothing (Cedar default-deny). "allow"
	// → a trailing broad permit on this connection.
	if cfg.DefaultAction == "allow" {
		grants = append(grants, fmt.Sprintf(
			`@id(%q) permit(principal in Sieve::Role::%q, action, resource in Sieve::Connection::%q);`,
			fmt.Sprintf("mig:%s:%s:default-allow", p.ID, conn), role, conn))
	}

	return Result{
		Cedar:      strings.Join(grants, "\n\n"),
		Guardrails: strings.Join(guardrails, "\n\n"),
		Filters:    dedupeFilters(filters),
		Manual:     manual,
	}, nil
}

// PolicyInput is the subset of a stored policy the migrator needs (decoupled
// from internal/policies to avoid importing storage here).
type PolicyInput struct {
	ID     string
	Config map[string]any // the rules evaluator config (RulesConfig shape)
}

// translateRule returns (grant, guardrail, filters, manual). The grant is the
// plain permit/forbid (no obligations); the guardrail (when the rule carries an
// approval/filter obligation) is a permit-only overlay carrying @approval/@filters
// over the same scope (spec §7.2 — obligations live in the guardrail set so
// composition can't strip them, §7.0).
func translateRule(connType, role, conn, polID string, idx int, r policy.Rule) (grant, guardrail string, fs []iam.Filter, man *ManualItem) {
	// Only Operations-based matches translate cleanly. Anything richer → manual.
	if richMatch(r.Match) {
		return "", "", nil, &ManualItem{PolicyID: polID, Rule: idx,
			Reason: "rule match uses fields beyond `operations` (glob/substring/content/service-specific) — port by hand or as a script_guard"}
	}
	ops := matchedOps(r.Match)
	id := fmt.Sprintf("mig:%s:%s:r%d", polID, conn, idx)

	switch r.Action {
	case "allow", "filter":
		fs, ann := ruleFilters(polID, idx, r)
		grant = permit(id, nil, role, conn, connType, ops)
		if len(ann) > 0 {
			guardrail = permit(id+":g", ann, role, conn, connType, ops)
		}
		return grant, guardrail, fs, nil

	case "deny":
		// H1: an unconditional catch-all deny is legacy "default deny" — Cedar
		// gives that for free. Emitting a catch-all forbid would override ALL
		// permits. So a catch-all deny emits NOTHING.
		if len(ops) == 0 {
			return "", "", nil, nil
		}
		msg := r.Reason
		if msg == "" {
			msg = fmt.Sprintf("denied by rule %d", idx+1)
		}
		return forbid(id, msg, role, conn, connType, ops), "", nil, nil

	case "approval_required":
		fs, ann := ruleFilters(polID, idx, r)
		grant = permit(id, nil, role, conn, connType, ops)
		gann := append([]string{`@approval("required")`}, ann...)
		guardrail = permit(id+":g", gann, role, conn, connType, ops)
		return grant, guardrail, fs, nil

	case "script":
		return "", "", nil, &ManualItem{PolicyID: polID, Rule: idx,
			Reason: "rule action=script — port to a script_guard filter-library entry"}

	default:
		return "", "", nil, &ManualItem{PolicyID: polID, Rule: idx,
			Reason: "unknown rule action " + r.Action}
	}
}

// richMatch reports whether the match uses anything beyond Operations (which we
// can't faithfully render as Cedar scope/condition in v1).
func richMatch(m *policy.RuleMatch) bool {
	if m == nil {
		return false
	}
	// Compare against a match that has ONLY Operations set: marshal both with
	// Operations zeroed and see if anything remains.
	clone := *m
	clone.Operations = nil
	b, _ := json.Marshal(clone)
	return string(b) != "{}"
}

func matchedOps(m *policy.RuleMatch) []string {
	if m == nil {
		return nil
	}
	out := make([]string, 0, len(m.Operations))
	for _, op := range m.Operations {
		if op != "*" {
			out = append(out, op)
		}
	}
	return out
}

// actionClause renders the `action` scope: unconstrained for catch-all, else a
// set of derived leaf action ids.
func actionClause(connType string, ops []string) string {
	if len(ops) == 0 {
		return "action"
	}
	ids := make([]string, len(ops))
	for i, op := range ops {
		ids[i] = fmt.Sprintf(`Sieve::Action::%q`, connType+"/"+op)
	}
	sort.Strings(ids)
	if len(ids) == 1 {
		return "action == " + ids[0]
	}
	return "action in [" + strings.Join(ids, ", ") + "]"
}

func permit(id string, annotations []string, role, conn, connType string, ops []string) string {
	ann := ""
	if len(annotations) > 0 {
		ann = strings.Join(annotations, " ") + " "
	}
	return fmt.Sprintf("@id(%q) %spermit(principal in Sieve::Role::%q, %s, resource in Sieve::Connection::%q);",
		id, ann, role, actionClause(connType, ops), conn)
}

func forbid(id, denyMsg, role, conn, connType string, ops []string) string {
	return fmt.Sprintf("@id(%q) @deny_message(%q) forbid(principal in Sieve::Role::%q, %s, resource in Sieve::Connection::%q);",
		id, denyMsg, role, actionClause(connType, ops), conn)
}

// ruleFilters turns a rule's ResponseFilter/FilterExclude/RedactPatterns into
// filter-library entries and the @filters annotation referencing them.
func ruleFilters(polID string, idx int, r policy.Rule) ([]iam.Filter, []string) {
	var fs []iam.Filter
	add := func(suffix string, f iam.Filter) {
		f.Name = fmt.Sprintf("mig-%s-r%d-%s", polID, idx, suffix)
		fs = append(fs, f)
	}
	if r.ResponseFilter != nil {
		applyRF(*r.ResponseFilter, add)
	}
	if r.FilterExclude != "" {
		add("exclude", iam.Filter{Kind: iam.KindExcludeItems, Config: map[string]any{"text": r.FilterExclude}})
	}
	if len(r.RedactPatterns) > 0 {
		add("redact", iam.Filter{Kind: iam.KindRedact, Config: map[string]any{"patterns": r.RedactPatterns}})
	}
	names := make([]string, 0, len(fs))
	for _, f := range fs {
		names = append(names, f.Name)
	}
	var ann []string
	if len(names) > 0 {
		ann = append(ann, fmt.Sprintf("@filters(%q)", strings.Join(names, " ")))
	}
	return fs, ann
}

func applyRF(rf policy.ResponseFilter, add func(string, iam.Filter)) {
	if rf.ExcludeContaining != "" {
		add("exclude", iam.Filter{Kind: iam.KindExcludeItems, Config: map[string]any{"text": rf.ExcludeContaining}})
	}
	if len(rf.RedactPatterns) > 0 {
		add("redact", iam.Filter{Kind: iam.KindRedact, Config: map[string]any{"patterns": rf.RedactPatterns}})
	}
	if rf.ScriptCommand != "" || rf.ScriptPath != "" {
		add("script", iam.Filter{Kind: iam.KindScriptFilter, Config: map[string]any{"command": rf.ScriptCommand, "path": rf.ScriptPath}})
	}
}

func dedupeFilters(fs []iam.Filter) []iam.Filter {
	seen := map[string]bool{}
	var out []iam.Filter
	for _, f := range fs {
		if seen[f.Name] {
			continue
		}
		seen[f.Name] = true
		out = append(out, f)
	}
	return out
}
