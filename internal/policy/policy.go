// Package policy defines the evaluator interface and types for the Sieve policy
// engine. The policy engine sits between an AI agent's request and the actual
// connector execution, deciding whether to allow, deny, require approval, or
// filter the operation.
// Multiple evaluator backends are supported (rules, script, LLM, chain,
// builtin). CreateEvaluator is the factory that dispatches by type string.
// The most common type is "rules" (see rules.go).
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// PolicyRequest describes the action an AI agent wants to perform.
// The Phase field is retained for backward compatibility with scripts that
// check metadata.phase, but the rules evaluator no longer uses it. All rule
// evaluation happens in a single pre-execution pass; post-execution content
// filtering is handled via ResponseFilter objects on the PolicyDecision.
type PolicyRequest struct {
	Operation  string         `json:"operation"`
	Connection string         `json:"connection"`
	Connector  string         `json:"connector"`
	Params     map[string]any `json:"params"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	Phase      string         `json:"phase,omitempty"` // kept for script compat; rules evaluator ignores it
}

// ResponseFilter describes a post-execution content modification.
// These are collected during pre-phase evaluation and applied to the
// response after the operation executes.
type ResponseFilter struct {
	// Label is an internal sentinel used by the API router to attribute the
	// audit policy_result identifier to a specific filter. It is NOT
	// serialised to policy scripts (json:"-") and has no effect on filtering
	// behaviour. When non-empty, ApplyResponseFilters records the label
	// instead of the generic "redacted" action string so callers can
	// distinguish auto-attached scrub filters from operator-defined redacts.
	Label string `json:"-"`
	// ExcludePatterns drops list items matching ANY pattern; RedactPatterns masks
	// matches of ANY pattern with [REDACTED]. Both interpret their patterns by the
	// same Match mode — a consistent matching model across the two transforms.
	ExcludePatterns []string `json:"exclude_patterns,omitempty"`
	RedactPatterns  []string `json:"redact_patterns,omitempty"`
	// Match is "contains" (default — case-insensitive literal substring) or
	// "regex". It applies to both ExcludePatterns and RedactPatterns, so exclude
	// and redact are equally powerful (no more "exclude is literal, redact is
	// regex" asymmetry).
	Match string `json:"match,omitempty"`
	// Fields optionally narrows redact/exclude to a subset of the connector's
	// content fields (by JSON key name). Empty ⇒ all of the connector's content
	// fields (passed to ApplyResponseFilters). redact/exclude apply ONLY within
	// these fields' string values, never the whole serialized blob — so base64
	// attachments and metadata are untouched.
	Fields        []string `json:"fields,omitempty"`
	ScriptPath    string   `json:"script_path,omitempty"`    // post-filter script
	ScriptCommand string   `json:"script_command,omitempty"` // e.g. "python3" or "node"
}

// fieldSet builds the effective set of content-field keys for a filter: the
// filter's own subset if it set one, else the connector's content fields. An
// empty result means "no field restriction" → whole-response matching (the
// back-compat / auth-scrub path).
func (f ResponseFilter) fieldSet(contentFields []string) map[string]bool {
	keys := f.Fields
	if len(keys) == 0 {
		keys = contentFields
	}
	if len(keys) == 0 {
		return nil
	}
	set := make(map[string]bool, len(keys))
	for _, k := range keys {
		set[k] = true
	}
	return set
}

// --- order-independent redaction (span union) ---
//
// Sequentially replacing matches one filter at a time is NOT commutative:
// overlapping patterns give different output by order ("aXb" with redactors
// "aXb" and "X" yields "[REDACTED]" one way, "a[REDACTED]b" the other), and a
// replacement can even manufacture or destroy a downstream match. So redaction
// must be order-independent BY CONSTRUCTION: compute every match span from every
// applicable redaction filter against the ORIGINAL string, merge overlapping AND
// adjacent spans, and mask each merged span in place with a single "[REDACTED]".
// Same inputs ⇒ same output regardless of filter collection order.

// cRedact is a redaction (or exclusion) filter compiled for one
// ApplyResponseFilters call. fields == nil means the whole-response target (the
// connector-agnostic auth-value scrub / back-compat path).
type cRedact struct {
	f       ResponseFilter
	res     []*regexp.Regexp
	fields  map[string]bool
	matched bool // set when this filter contributed ≥1 span (for label attribution)
}

// redactSpans returns the [start,end) byte ranges in s matched by any of res.
func redactSpans(s string, res []*regexp.Regexp) [][2]int {
	var spans [][2]int
	for _, re := range res {
		for _, m := range re.FindAllStringIndex(s, -1) {
			spans = append(spans, [2]int{m[0], m[1]})
		}
	}
	return spans
}

// mergeSpans sorts and coalesces overlapping AND adjacent (touching) ranges.
func mergeSpans(spans [][2]int) [][2]int {
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i][0] != spans[j][0] {
			return spans[i][0] < spans[j][0]
		}
		return spans[i][1] < spans[j][1]
	})
	merged := [][2]int{spans[0]}
	for _, sp := range spans[1:] {
		last := &merged[len(merged)-1]
		if sp[0] <= last[1] { // overlapping or adjacent
			if sp[1] > last[1] {
				last[1] = sp[1]
			}
		} else {
			merged = append(merged, sp)
		}
	}
	return merged
}

// maskSpans replaces each merged span in s with a single "[REDACTED]". Spans are
// computed on the original s; replacement runs right-to-left so earlier byte
// offsets stay valid. Returns the masked string and whether anything changed.
func maskSpans(s string, spans [][2]int) (string, bool) {
	merged := mergeSpans(spans)
	if len(merged) == 0 {
		return s, false
	}
	out := s
	for i := len(merged) - 1; i >= 0; i-- {
		out = out[:merged[i][0]] + "[REDACTED]" + out[merged[i][1]:]
	}
	return out, true
}

// redactFieldsSpanUnion walks decoded JSON and masks, in each content-field
// string value, the UNION of spans from every filter whose field set includes
// that key — computed on the original value, so order-independent. Non-content
// fields (ids, base64 attachment data, metadata) are never touched.
func redactFieldsSpanUnion(v any, filters []*cRedact) bool {
	changed := false
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok {
				var spans [][2]int
				for _, cf := range filters {
					if cf.fields == nil || !cf.fields[k] {
						continue
					}
					if sp := redactSpans(s, cf.res); len(sp) > 0 {
						cf.matched = true
						spans = append(spans, sp...)
					}
				}
				if masked, ok := maskSpans(s, spans); ok {
					x[k] = masked
					changed = true
				}
				continue
			}
			if redactFieldsSpanUnion(val, filters) {
				changed = true
			}
		}
	case []any:
		for _, e := range x {
			if redactFieldsSpanUnion(e, filters) {
				changed = true
			}
		}
	}
	return changed
}

// matchInFields reports whether any regex matches the string value of a map key
// in `fields`, anywhere in v. Used by exclude to drop a list item based on its
// CONTENT fields only (not encoded/metadata fields).
func matchInFields(v any, fields map[string]bool, res []*regexp.Regexp) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok && fields[k] {
				for _, re := range res {
					if re.MatchString(s) {
						return true
					}
				}
				continue
			}
			if matchInFields(val, fields, res) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if matchInFields(e, fields, res) {
				return true
			}
		}
	}
	return false
}

// compileFilterPattern compiles one pattern under a Match mode into a regexp:
// "regex" uses the pattern verbatim; "contains" (default) escapes it and makes it
// case-insensitive, so a literal substring match. This single helper backs both
// redact and exclude, which is what makes their matching consistent.
func compileFilterPattern(pattern, match string) (*regexp.Regexp, error) {
	if match == "regex" {
		return regexp.Compile(pattern)
	}
	return regexp.Compile("(?i)" + regexp.QuoteMeta(pattern))
}

// compileFilters compiles a pattern list under a match mode, skipping any that
// fail to compile (best-effort, as before).
func compileFilters(patterns []string, match string) []*regexp.Regexp {
	res := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := compileFilterPattern(p, match); err == nil {
			res = append(res, re)
		}
	}
	return res
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func redactLabel(f ResponseFilter) string {
	if f.Label != "" {
		return f.Label
	}
	return "redacted"
}

// Redaction describes a region of a field that should be masked.
type Redaction struct {
	Field string `json:"field"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

// PolicyDecision is the result of evaluating a policy. The Action field drives
// the control flow in the MCP server and API router. Filters contains
// ResponseFilter objects to be applied to the response after execution.
// Rewrite is used by script evaluators to return a modified response.
type PolicyDecision struct {
	Action     string           `json:"action"` // "allow", "deny", "approval_required"
	Reason     string           `json:"reason,omitempty"`
	Redactions []Redaction      `json:"redactions,omitempty"`
	Rewrite    string           `json:"rewrite,omitempty"` // if set, replace the response with this content
	Filters    []ResponseFilter `json:"filters,omitempty"` // post-execution content filters
}

// Evaluator is the interface all policy evaluators implement.
type Evaluator interface {
	Evaluate(ctx context.Context, req *PolicyRequest) (*PolicyDecision, error)
	Type() string
}

// ResponseFilterError carries a failure to instantiate or run a response
// filter. Callers SHOULD treat this as a fail-closed signal — the un-redacted
// response must NOT be returned to the agent when a filter cannot run, since
// the filter is what enforces secret redaction. Swallowing the error here
// would silently disable e.g. an SSN redactor that targets a now-removed
// allowlisted interpreter.
type ResponseFilterError struct {
	Filter ResponseFilter
	Err    error
}

func (e *ResponseFilterError) Error() string {
	// Walk a chain of identifiers until we find a non-empty one, so the
	// audit row stays attributable even when a misconfigured filter
	// (no Label, no ScriptCommand, no ScriptPath) reaches this point.
	label := e.Filter.Label
	if label == "" {
		label = e.Filter.ScriptCommand
	}
	if label == "" {
		label = e.Filter.ScriptPath
	}
	if label == "" {
		label = "<unknown>"
	}
	return fmt.Sprintf("response filter %q failed: %v", label, e.Err)
}

func (e *ResponseFilterError) Unwrap() error { return e.Err }

// ApplyResponseFilters applies a list of response filters to a JSON response.
// Returns the (potentially modified) response and a summary of what was done.
// On a script-filter construction or evaluation failure, returns the original
// response unchanged and a non-nil *ResponseFilterError so the caller can
// fail closed (e.g. surface a deny decision) rather than leak un-redacted
// content. Non-script filter errors (a regex that fails to compile is
// already best-effort skipped) do NOT raise this error.
func ApplyResponseFilters(responseJSON []byte, filters []ResponseFilter, contentFields []string) ([]byte, string, error) {
	if len(filters) == 0 {
		return responseJSON, "", nil
	}

	result := string(responseJSON)
	var actions []string

	// Phase 1 — EXCLUSIONS: drop an item if ANY exclude filter matches it (union
	// of drops ⇒ order-free). Done before redaction so masking only touches the
	// items that survive.
	result, exActions := applyExclusionsUnion(result, filters, contentFields)
	actions = append(actions, exActions...)

	// Phase 2 — REDACTIONS: mask the UNION of match spans computed on the
	// original string (overlap/adjacency-merged, masked in place) ⇒ order-free.
	result, rActions := applyRedactionsSpanUnion(result, filters, contentFields)
	actions = append(actions, rActions...)

	// Phase 3 — SCRIPTS: opaque post-filter rewrites. This is the ONE
	// order-dependent step (a script sees whatever ran before it); they run in
	// filter order. A construct/run failure MUST fail closed — returning the
	// un-redacted response would leak content the caller relies on us to scrub.
	for _, f := range filters {
		if f.ScriptPath == "" {
			continue
		}
		eval, err := NewScriptEvaluator(map[string]any{"command": f.ScriptCommand, "script": f.ScriptPath})
		if err != nil {
			return responseJSON, strings.Join(actions, "; "), &ResponseFilterError{Filter: f, Err: err}
		}
		scriptReq := &PolicyRequest{
			Phase:    "post",
			Metadata: map[string]any{"phase": "post", "response": result},
		}
		scriptDec, err := eval.Evaluate(context.Background(), scriptReq)
		if err != nil {
			return responseJSON, strings.Join(actions, "; "), &ResponseFilterError{Filter: f, Err: err}
		}
		if scriptDec.Rewrite != "" {
			result = scriptDec.Rewrite
			actions = append(actions, "script-filtered")
		}
	}

	return []byte(result), strings.Join(actions, "; "), nil
}

// applyExclusionsUnion drops a list item when ANY exclude filter matches it
// (each filter under its own match mode + effective field set). Because it's a
// union of drops, the result is independent of filter order. Returns the
// (possibly rewritten) response and per-key action summaries.
func applyExclusionsUnion(result string, filters []ResponseFilter, contentFields []string) (string, []string) {
	var exs []*cRedact
	for _, f := range filters {
		if len(f.ExcludePatterns) == 0 {
			continue
		}
		exs = append(exs, &cRedact{f: f, res: compileFilters(f.ExcludePatterns, f.Match), fields: f.fieldSet(contentFields)})
	}
	if len(exs) == 0 {
		return result, nil
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		// Not a JSON object — only a whole-response exclude can match it.
		for _, e := range exs {
			if e.fields == nil && anyMatch(e.res, result) {
				return "", []string{"response filtered: matched exclude pattern"}
			}
		}
		return result, nil
	}

	var actions []string
	changed := false
	// Handle list formats: {"emails": [...]}, {"messages": [...]}, etc.
	for _, key := range []string{"emails", "messages", "items", "threads", "results"} {
		items, ok := data[key].([]any)
		if !ok {
			continue
		}
		var filtered []any
		removed := 0
		for _, item := range items {
			if excludedByAny(item, exs) {
				removed++
			} else {
				filtered = append(filtered, item)
			}
		}
		if removed > 0 {
			data[key] = filtered
			if total, ok := data["total"].(float64); ok {
				data["total"] = total - float64(removed)
			}
			// Clear pagination token to prevent side-channel leakage.
			for _, ptKey := range []string{"next_page_token", "nextPageToken"} {
				delete(data, ptKey)
			}
			actions = append(actions, fmt.Sprintf("excluded %d item(s)", removed))
			changed = true
		}
	}
	if !changed {
		return result, nil
	}
	rewritten, _ := json.Marshal(data)
	return string(rewritten), actions
}

// excludedByAny reports whether item matches any exclude filter (union of drops).
// Field-aware filters match only within content fields (so a hit inside
// base64/metadata never drops the item); whole-response filters match the
// item's serialized JSON.
func excludedByAny(item any, exs []*cRedact) bool {
	for _, e := range exs {
		if e.fields == nil {
			itemJSON, _ := json.Marshal(item)
			if anyMatch(e.res, string(itemJSON)) {
				return true
			}
		} else if matchInFields(item, e.fields, e.res) {
			return true
		}
	}
	return false
}

// applyRedactionsSpanUnion masks the union of every redaction filter's match
// spans, computed on the ORIGINAL string and merged in place — so the result is
// independent of filter order. Field-aware filters (those with a content-field
// set) run first against the decoded JSON's content-field values; whole-response
// filters (auth-scrub / back-compat, fields == nil) then run against the whole
// serialized string. Within each group, span-union makes order irrelevant; the
// two groups apply in a fixed order. A filter that contributes ≥1 span is
// recorded by its label (preserving audit attribution, e.g. auth_value_scrubbed).
func applyRedactionsSpanUnion(result string, filters []ResponseFilter, contentFields []string) (string, []string) {
	var fieldAware, wholeResp []*cRedact
	for _, f := range filters {
		if len(f.RedactPatterns) == 0 {
			continue
		}
		cf := &cRedact{f: f, res: compileFilters(f.RedactPatterns, f.Match), fields: f.fieldSet(contentFields)}
		if cf.fields == nil {
			wholeResp = append(wholeResp, cf)
		} else {
			fieldAware = append(fieldAware, cf)
		}
	}
	if len(fieldAware) == 0 && len(wholeResp) == 0 {
		return result, nil
	}

	// Field-aware: decode once, span-union per content-field value, re-marshal
	// only if anything changed (preserve original bytes otherwise).
	if len(fieldAware) > 0 {
		var data any
		if err := json.Unmarshal([]byte(result), &data); err == nil {
			if redactFieldsSpanUnion(data, fieldAware) {
				if rewritten, mErr := json.Marshal(data); mErr == nil {
					result = string(rewritten)
				}
			}
		}
	}

	// Whole-response: span-union over the entire (already field-redacted) string.
	if len(wholeResp) > 0 {
		var spans [][2]int
		for _, cf := range wholeResp {
			if sp := redactSpans(result, cf.res); len(sp) > 0 {
				cf.matched = true
				spans = append(spans, sp...)
			}
		}
		if masked, ok := maskSpans(result, spans); ok {
			result = masked
		}
	}

	var actions []string
	for _, cf := range fieldAware {
		if cf.matched {
			actions = append(actions, redactLabel(cf.f))
		}
	}
	for _, cf := range wholeResp {
		if cf.matched {
			actions = append(actions, redactLabel(cf.f))
		}
	}
	return result, actions
}
