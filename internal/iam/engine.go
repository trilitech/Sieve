package iam

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// Engine is the PDP. It holds the compiled Cedar PolicySet and the filter
// library, and answers Decide. It is the ONLY type that touches cedar-go.
type Engine struct {
	set *cedar.PolicySet
	lib FilterLibrary
}

// NewEngine compiles the given policies into one Cedar PolicySet. Each policy's
// statements are added under a stable id "pol:<policyID>#<idx>" (spec §9.3), so
// diag.Reasons maps back to a source policy + statement. A policy whose Cedar
// fails to parse is returned as an error (the caller — PR-C/PR-D — surfaces it as
// a broken policy rather than silently dropping it).
func NewEngine(policies []Policy, lib FilterLibrary) (*Engine, error) {
	set := cedar.NewPolicySet()
	for _, p := range policies {
		list, err := cedar.NewPolicyListFromBytes(p.ID, []byte(p.Cedar))
		if err != nil {
			return nil, fmt.Errorf("iam: policy %q: %w", p.ID, err)
		}
		for i, stmt := range list {
			pid := types.PolicyID("pol:" + p.ID + "#" + strconv.Itoa(i))
			// Guard against duplicate Sieve policy IDs silently overwriting
			// statements (Add replaces in place). Storage enforces unique ids;
			// this catches a programming/seed error loudly instead.
			if set.Get(pid) != nil {
				return nil, fmt.Errorf("iam: duplicate policy id %q", p.ID)
			}
			set.Add(pid, stmt)
		}
	}
	if lib == nil {
		lib = MapFilterLibrary{}
	}
	return &Engine{set: set, lib: lib}, nil
}

// Decide evaluates the request and resolves obligations. It performs no I/O.
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

	dec, diag := e.set.IsAuthorized(entities, req)

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

	// Allow: collect obligations from the determining permits' annotations.
	perPermit := make([]map[string]string, 0, len(diag.Reasons))
	for _, reason := range diag.Reasons {
		if p := e.set.Get(reason.PolicyID); p != nil {
			perPermit = append(perPermit, annotationsToMap(p.Annotations()))
		}
	}
	obl, err := collectObligations(perPermit, e.lib)
	if err != nil {
		// Fail closed: an unresolvable obligation denies rather than allowing
		// without the intended guard/filter.
		return Decision{Allow: false, Reason: err.Error(), Determining: out.Determining, EvalErrors: out.EvalErrors}, nil
	}
	out.Obligations = obl
	return out, nil
}

// denyReason builds a human-readable reason from the determining forbids'
// @deny_message annotations, falling back to the default-deny message.
func (e *Engine) denyReason(reasons []types.DiagnosticReason) string {
	var msgs []string
	for _, reason := range reasons {
		if p := e.set.Get(reason.PolicyID); p != nil {
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
		if x != float64(int64(x)) {
			return nil, fmt.Errorf("non-integral number %v has no Cedar representation (no float)", x)
		}
		return cedar.Long(int64(x)), nil
	case time.Time:
		return cedar.NewDatetime(x), nil
	// ipaddr (context.source_ip) and decimal land with their enrichers in PR-D;
	// until then an unsupported type errors at conversion (fail-loud), which the
	// PEP maps to fail-closed.
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
