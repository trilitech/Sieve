package iam

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Annotation keys Sieve recognizes on a policy (spec §7.2). Unknown annotations
// (e.g. @id) are ignored. These are the only obligation-bearing keys.
const (
	annApproval   = "approval"     // @approval("required")
	annFilters    = "filters"      // @filters("name1 name2 …")
	annAuditLabel = "audit_label"  // @audit_label("…")
	annDenyMsg    = "deny_message" // @deny_message("…")  (read on deny, not here)
	// A grant whose CONDITION is a script (spec §5.4) carries the interpreter +
	// path as annotations; the engine surfaces them per-grant and the PEP runs the
	// script (deny ⇒ that grant is vetoed). These are NOT obligations.
	annCondScriptCmd  = "condition_script_command"
	annCondScriptPath = "condition_script_path"
	// A scoped TRANSFORM (spec §7) carries its action INLINE — a kind, a JSON
	// config, and a rank — so the engine builds the Filter directly, with no
	// filter-library lookup. The self-contained successor to @filters("name").
	annTransformKind   = "transform_kind"
	annTransformConfig = "transform_config"
	annTransformRank   = "transform_rank"
)

// inlineTransform builds a Filter from a statement's inline @transform_*
// annotations, or (Filter{}, false, nil) when it carries none. Config is a JSON
// object; rank is an integer string. The complement of the @filters→library path.
func inlineTransform(anns map[string]string) (Filter, bool, error) {
	kind := strings.TrimSpace(anns[annTransformKind])
	if kind == "" {
		return Filter{}, false, nil
	}
	f := Filter{Kind: FilterKind(kind)}
	if r := strings.TrimSpace(anns[annTransformRank]); r != "" {
		n, err := strconv.Atoi(r)
		if err != nil {
			return Filter{}, false, fmt.Errorf("iam: bad transform rank %q: %w", r, err)
		}
		f.Order = n
	}
	if cfg := strings.TrimSpace(anns[annTransformConfig]); cfg != "" {
		if err := json.Unmarshal([]byte(cfg), &f.Config); err != nil {
			return Filter{}, false, fmt.Errorf("iam: bad transform config: %w", err)
		}
	}
	return f, true, nil
}

// scriptCondFromAnns returns the per-grant script condition a permit carries, or
// nil if it has none (a declarative / unconditional grant).
func scriptCondFromAnns(anns map[string]string) *ScriptCond {
	cmd := strings.TrimSpace(anns[annCondScriptCmd])
	path := strings.TrimSpace(anns[annCondScriptPath])
	if cmd == "" || path == "" {
		return nil
	}
	return &ScriptCond{Command: cmd, Path: path}
}

// collectObligations builds the Obligations for an ALLOW from the annotations of
// the determining permits (spec §7.3). It is pure and cedar-free: engine.go
// reads annotations off the PolicySet and passes them here.
//
// Semantics:
//   - @approval: logical OR across determining permits.
//   - @filters:  union of referenced filter names, then DEDUPED by name (two
//     permits naming the same filter ⇒ applied once). Each name is resolved
//     against the library; a missing name is a fail-closed error.
//   - @audit_label: collected and joined.
//   - Guards (pre) and Post (transforms) are split by kind; Post is sorted by
//     (Order, Name) so application is deterministic and idempotent (spec §7.1).
//
// It can only ever produce obligations that deny or transform — there is no path
// by which it grants. That is the monotonicity invariant (spec §7).
func collectObligations(perPermit []map[string]string, lib FilterLibrary) (Obligations, error) {
	var obl Obligations
	seen := map[string]Filter{} // filter name → resolved Filter (dedupe)
	var inline []Filter         // inline scoped transforms (no library name)
	var labels []string

	for _, anns := range perPermit {
		if strings.TrimSpace(anns[annApproval]) == "required" {
			obl.Approval = true
		}
		if lbl := strings.TrimSpace(anns[annAuditLabel]); lbl != "" {
			labels = append(labels, lbl)
		}
		for _, name := range strings.Fields(anns[annFilters]) {
			if _, dup := seen[name]; dup {
				continue
			}
			f, ok := lib.Get(name)
			if !ok {
				// Fail closed: a policy referencing an unknown filter must not
				// silently proceed un-filtered. (Save-time validation prevents
				// this normally; this is the runtime backstop.)
				return Obligations{}, fmt.Errorf("iam: policy references unknown filter %q", name)
			}
			seen[name] = f
		}
		// A scoped transform carries its action inline — no library lookup. Each
		// statement contributes at most one; annotationMapsByID already deduped by
		// policy id, so the same transform statement isn't double-counted.
		if f, ok, err := inlineTransform(anns); err != nil {
			return Obligations{}, err
		} else if ok {
			inline = append(inline, f)
		}
	}

	split := func(f Filter) {
		if f.Kind.isPre() {
			obl.Guards = append(obl.Guards, f)
		} else {
			obl.Post = append(obl.Post, f)
		}
	}
	for _, f := range seen {
		split(f)
	}
	for _, f := range inline {
		split(f)
	}
	// Deterministic ordering. Guards are order-independent (any deny denies) but
	// we still sort for stable output; Post ordering is semantically meaningful.
	// SliceStable on Post so inline transforms sharing a rank (no library name to
	// tiebreak) keep their collection order — still deterministic.
	sort.Slice(obl.Guards, func(i, j int) bool { return obl.Guards[i].Name < obl.Guards[j].Name })
	sort.SliceStable(obl.Post, func(i, j int) bool {
		if obl.Post[i].Order != obl.Post[j].Order {
			return obl.Post[i].Order < obl.Post[j].Order
		}
		return obl.Post[i].Name < obl.Post[j].Name
	})
	obl.AuditLabel = strings.Join(labels, ",")
	return obl, nil
}
