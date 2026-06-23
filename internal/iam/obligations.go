package iam

import (
	"fmt"
	"sort"
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
)

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
	}

	for _, f := range seen {
		if f.Kind.isPre() {
			obl.Guards = append(obl.Guards, f)
		} else {
			obl.Post = append(obl.Post, f)
		}
	}
	// Deterministic ordering. Guards are order-independent (any deny denies) but
	// we still sort for stable output; Post ordering is semantically meaningful.
	sort.Slice(obl.Guards, func(i, j int) bool { return obl.Guards[i].Name < obl.Guards[j].Name })
	sort.Slice(obl.Post, func(i, j int) bool {
		if obl.Post[i].Order != obl.Post[j].Order {
			return obl.Post[i].Order < obl.Post[j].Order
		}
		return obl.Post[i].Name < obl.Post[j].Name
	})
	obl.AuditLabel = strings.Join(labels, ",")
	return obl, nil
}
