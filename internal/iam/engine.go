package iam

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// Engine is the PDP. It holds TWO compiled Cedar PolicySets — the GRANTS set
// (the allow/deny decision) and the GUARDRAILS set (global obligation overlays) —
// plus the filter library, and answers Decide. It is the ONLY type that touches
// cedar-go. The two-set / two-pass design is the spec §7 obligation model: an
// obligation binds the OUTCOME, never a particular grant, so composition cannot
// strip it.
type Engine struct {
	grants     *cedar.PolicySet
	guardrails *cedar.PolicySet
	lib        FilterLibrary
}

// buildPolicySet compiles a list of Sieve policies into one Cedar PolicySet,
// each statement under a stable id "<prefix>:<policyID>#<idx>" (spec §9.3) so
// diag.Reasons maps back to a source rule/guardrail + statement.
func buildPolicySet(prefix string, policies []Policy) (*cedar.PolicySet, error) {
	set := cedar.NewPolicySet()
	for _, p := range policies {
		list, err := cedar.NewPolicyListFromBytes(p.ID, []byte(p.Cedar))
		if err != nil {
			return nil, fmt.Errorf("iam: %s %q: %w", prefix, p.ID, err)
		}
		for i, stmt := range list {
			pid := types.PolicyID(prefix + ":" + p.ID + "#" + strconv.Itoa(i))
			if set.Get(pid) != nil {
				return nil, fmt.Errorf("iam: duplicate %s id %q", prefix, p.ID)
			}
			set.Add(pid, stmt)
		}
	}
	return set, nil
}

// NewEngine compiles the grant rules and the guardrails into their two PolicySets.
// Grant ids keep the legacy "pol:" prefix (back-compat with audit/explorer);
// guardrails use "guard:". A policy whose Cedar fails to parse is an error (the
// caller surfaces it as broken rather than silently dropping it).
func NewEngine(grants []Policy, guardrails []Policy, lib FilterLibrary) (*Engine, error) {
	g, err := buildPolicySet("pol", grants)
	if err != nil {
		return nil, err
	}
	h, err := buildPolicySet("guard", guardrails)
	if err != nil {
		return nil, err
	}
	if lib == nil {
		lib = MapFilterLibrary{}
	}
	return &Engine{grants: g, guardrails: h, lib: lib}, nil
}

// ValidateGuardrailCedar enforces the permit-only invariant on guardrail Cedar
// (spec §7.2): every statement must be a `permit`. A `forbid` in the guardrail
// set would flip the guardrail pass's Reasons semantics (on a deny, diag.Reasons
// holds satisfied forbids, not matched permits) and silently drop obligations —
// so it is rejected at save, including via the raw-Cedar escape hatch. Also
// rejects unparseable or empty guardrail text.
func ValidateGuardrailCedar(cedarText string) error {
	list, err := cedar.NewPolicyListFromBytes("_guardrail", []byte(cedarText))
	if err != nil {
		return err
	}
	if len(list) == 0 {
		return fmt.Errorf("a guardrail must contain at least one permit statement")
	}
	for _, stmt := range list {
		if stmt.Effect() != cedar.Permit {
			return fmt.Errorf("a guardrail must be a `permit` — it only ADDS an obligation (approval/filters) to an already-allowed request; `forbid` is not allowed in the guardrail set (spec §7.2)")
		}
	}
	return nil
}

// Decide runs the two-pass evaluation (spec §7.3). Pass 1 (grants) yields the
// allow/deny decision. Pass 2 (guardrails, only on allow) collects obligations
// from EVERY guardrail that matched or errored — independent of which grant
// fired, so composition cannot strip an obligation. Performs no I/O.
func (e *Engine) Decide(r Request) (Decision, error) {
	entities, err := buildEntityMap(r.Entities)
	if err != nil {
		return Decision{}, err
	}
	ctx, err := toRecord(r.Context)
	if err != nil {
		return Decision{}, fmt.Errorf("iam: context: %w", err)
	}
	req := cedar.Request{
		Principal: toUID(r.Principal),
		Action:    toUID(r.Action),
		Resource:  toUID(r.Resource),
		Context:   ctx,
	}

	// Pass 1 — grants: the decision.
	dec, diag := e.grants.IsAuthorized(entities, req)
	out := Decision{Allow: bool(dec)}
	for _, d := range diag.Errors {
		out.EvalErrors = append(out.EvalErrors, EvalError{PolicyID: string(d.PolicyID), Message: d.Message})
	}
	for _, reason := range diag.Reasons {
		out.Determining = append(out.Determining, string(reason.PolicyID))
	}
	if dec != cedar.Allow {
		out.Reason = e.denyReason(diag.Reasons)
		return out, nil
	}

	// Split the matching grant permits (spec §5.4/§7.3). Grants carry NO
	// transforms — those are guardrail-only — so a grant contributes only to the
	// DECISION (and its @approval):
	//   - SCRIPT-CONDITION grants carry a per-grant decision script; surface each
	//     as a candidate so the PEP runs it (deny ⇒ that grant is vetoed, not the
	//     request).
	//   - PLAIN grants (no script) are unconditional; their @approval (if any)
	//     folds into the obligation set. Reasons only — a condition-erroring permit
	//     is skipped by Cedar (no grant), the fail-closed polarity.
	// TRANSFORM obligations come solely from EVERY matching-or-errored GUARDRAIL
	// (global, role-agnostic; Reasons∪Errors, the fail-safe polarity, spec §7.6).
	// Because guardrail obligations UNION over the outcome, composition can only
	// ADD one, never strip it (the monotonicity invariant).
	var plain []map[string]string
	seenPID := make(map[types.PolicyID]bool)
	for _, pid := range reasonIDs(diag.Reasons) {
		if seenPID[pid] {
			continue
		}
		seenPID[pid] = true
		p := e.grants.Get(pid)
		if p == nil {
			continue
		}
		anns := annotationsToMap(p.Annotations())
		if sc := scriptCondFromAnns(anns); sc != nil {
			// A script-condition grant carries no transforms; the script's return
			// (allow/deny/approval) is the decision, run per-grant by the PEP. A
			// plain grant may still carry its decision's @approval (collected below).
			out.ScriptGrants = append(out.ScriptGrants, GrantCandidate{PolicyID: string(pid), Script: *sc})
		} else {
			plain = append(plain, anns)
			out.HasPlainGrant = true
		}
	}
	perPermit := append(plain, e.matchedGuardrails(entities, req)...)
	obl, err := collectObligations(perPermit, e.lib)
	if err != nil {
		// Fail closed: an unresolvable obligation denies rather than allowing
		// without the intended guard/filter.
		return Decision{Allow: false, Reason: err.Error(), Determining: out.Determining, EvalErrors: out.EvalErrors}, nil
	}
	out.Obligations = obl
	return out, nil
}

// matchedGuardrails runs the guardrail pass and returns the annotation maps of
// every guardrail that MATCHED (diag.Reasons — the set is permit-only, spec §7.2,
// so on Allow these are exactly the satisfied guardrails) OR ERRORED
// (diag.Errors). An errored guardrail is treated as matched — fail-SAFE, the
// mirror of the grant fail-closed rule: a guardrail whose condition can't be
// evaluated still imposes its obligation rather than silently dropping it
// (spec §7.3/§7.6 polarity).
func (e *Engine) matchedGuardrails(entities types.EntityMap, req cedar.Request) []map[string]string {
	_, hdiag := e.guardrails.IsAuthorized(entities, req)
	ids := reasonIDs(hdiag.Reasons)
	for _, d := range hdiag.Errors {
		ids = append(ids, d.PolicyID) // fail-safe: an errored guardrail still imposes its obligation
	}
	return annotationMapsByID(e.guardrails, ids)
}

// reasonIDs extracts the policy ids from a diagnostic's Reasons (the satisfied
// permits on an allow).
func reasonIDs(reasons []types.DiagnosticReason) []types.PolicyID {
	ids := make([]types.PolicyID, 0, len(reasons))
	for _, r := range reasons {
		ids = append(ids, r.PolicyID)
	}
	return ids
}

// annotationMapsByID returns the dedup'd annotation maps for the given policy ids
// in set — the obligation-bearing annotations off the determining permits of
// either pass (grants or guardrails). The single reusable annotation reader.
func annotationMapsByID(set *cedar.PolicySet, ids []types.PolicyID) []map[string]string {
	seen := make(map[types.PolicyID]bool)
	var out []map[string]string
	for _, pid := range ids {
		if seen[pid] {
			continue
		}
		seen[pid] = true
		if p := set.Get(pid); p != nil {
			out = append(out, annotationsToMap(p.Annotations()))
		}
	}
	return out
}

// denyReason builds a human-readable reason from the determining forbids'
// @deny_message annotations, falling back to the default-deny message.
func (e *Engine) denyReason(reasons []types.DiagnosticReason) string {
	var msgs []string
	for _, reason := range reasons {
		if p := e.grants.Get(reason.PolicyID); p != nil {
			if m := strings.TrimSpace(string(p.Annotations()[types.Ident(annDenyMsg)])); m != "" {
				msgs = append(msgs, m)
			}
		}
	}
	if len(msgs) > 0 {
		return strings.Join(msgs, "; ")
	}
	if len(reasons) > 0 {
		return "denied by policy"
	}
	return "no matching permit (default deny)"
}

// --- cedar conversions (the seam) ---

func toUID(u EntityUID) types.EntityUID {
	return cedar.NewEntityUID(types.EntityType(u.Type), cedar.String(u.ID))
}

func buildEntityMap(ents []Entity) (types.EntityMap, error) {
	m := make(types.EntityMap, len(ents))
	for _, e := range ents {
		parents := make([]types.EntityUID, 0, len(e.Parents))
		for _, p := range e.Parents {
			parents = append(parents, toUID(p))
		}
		attrs, err := toRecord(e.Attrs)
		if err != nil {
			return nil, fmt.Errorf("iam: entity %s::%q attrs: %w", e.UID.Type, e.UID.ID, err)
		}
		uid := toUID(e.UID)
		m[uid] = types.Entity{
			UID:        uid,
			Parents:    cedar.NewEntityUIDSet(parents...),
			Attributes: attrs,
		}
	}
	return m, nil
}

func toRecord(m map[string]any) (types.Record, error) {
	if len(m) == 0 {
		return types.Record{}, nil
	}
	rm := make(types.RecordMap, len(m))
	for k, v := range m {
		val, err := toValue(v)
		if err != nil {
			return types.Record{}, fmt.Errorf("key %q: %w", k, err)
		}
		rm[types.String(k)] = val
	}
	return cedar.NewRecord(rm), nil
}

// toValue converts a Go value to a Cedar value. Cedar has no float type
// (Long is int64), so a non-integral float64 is rejected rather than silently
// truncated (spec §4.5).
func toValue(v any) (types.Value, error) {
	switch x := v.(type) {
	case nil:
		return nil, fmt.Errorf("nil value (omit the key instead — spec §7.6)")
	case string:
		return cedar.String(x), nil
	case bool:
		return cedar.Boolean(x), nil
	case int:
		return cedar.Long(int64(x)), nil
	case int64:
		return cedar.Long(x), nil
	case float64:
		// Cedar's Long is int64; a fractional number becomes a Cedar decimal
		// (spec §4.5/§5.4) so cost/temperature conditions work. A whole number
		// stays a Long so integer conditions compare against Long thresholds.
		if x == float64(int64(x)) {
			return cedar.Long(int64(x)), nil
		}
		d, err := cedar.NewDecimalFromFloat(x)
		if err != nil {
			return nil, fmt.Errorf("decimal %v: %w", x, err)
		}
		return d, nil
	case types.Decimal:
		return x, nil // an enricher may emit a decimal directly
	case time.Time:
		return cedar.NewDatetime(x), nil
	// ipaddr (context.source_ip) lands with its enricher; until then an
	// unsupported type errors at conversion (fail-loud → the PEP fails closed).
	case []string:
		vals := make([]types.Value, len(x))
		for i, s := range x {
			vals[i] = cedar.String(s)
		}
		return cedar.NewSet(vals...), nil
	case []any:
		vals := make([]types.Value, len(x))
		for i, e := range x {
			ev, err := toValue(e)
			if err != nil {
				return nil, fmt.Errorf("set element %d: %w", i, err)
			}
			vals[i] = ev
		}
		return cedar.NewSet(vals...), nil
	case map[string]any:
		return toRecord(x)
	case EntityUID:
		return toUID(x), nil
	default:
		return nil, fmt.Errorf("unsupported context type %T", v)
	}
}

func annotationsToMap(a types.Annotations) map[string]string {
	m := make(map[string]string, len(a))
	for k, v := range a {
		m[string(k)] = string(v)
	}
	return m
}
