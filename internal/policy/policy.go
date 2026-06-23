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

// --- field-aware redaction ---
//
// Transforms apply SEQUENTIALLY in the order the engine hands them. Post
// obligations are sorted by (Order, Name) in internal/iam/obligations.go, so the
// slice ApplyResponseFilters receives is already in operator-set rank order.
// Order is therefore meaningful and deterministic — a redaction ranked before an
// exclusion can mask the very text the exclusion keys on. redactInFields masks,
// in place, every match of a single filter's patterns within the connector's
// content-field string values; non-content fields (ids, base64 attachment data,
// metadata) are never touched.
func redactInFields(v any, fields map[string]bool, res []*regexp.Regexp) bool {
	changed := false
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok {
				if fields[k] {
					ns := s
					for _, re := range res {
						ns = re.ReplaceAllString(ns, "[REDACTED]")
					}
					if ns != s {
						x[k] = ns
						changed = true
					}
				}
				continue
			}
			if redactInFields(val, fields, res) {
				changed = true
			}
		}
	case []any:
		for _, e := range x {
			if redactInFields(e, fields, res) {
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

// ApplyResponseFilters applies response filters to a JSON response IN THE ORDER
// GIVEN. The slice is already in operator-set rank order — the engine sorts post
// obligations by (Order, Name) (internal/iam/obligations.go) before handing them
// here. Each filter operates on the running result, so order is meaningful and
// deterministic: a redaction ranked before an exclusion masks the text the
// exclusion would otherwise key on. Returns the (possibly modified) response and
// a summary of what was done. On a script-filter construction or evaluation
// failure, returns the ORIGINAL response unchanged and a non-nil
// *ResponseFilterError so the caller can fail closed rather than leak un-redacted
// content. (A regex that fails to compile is best-effort skipped and does NOT
// raise this error.)
func ApplyResponseFilters(responseJSON []byte, filters []ResponseFilter, contentFields []string) ([]byte, string, error) {
	if len(filters) == 0 {
		return responseJSON, "", nil
	}

	result := string(responseJSON)
	var actions []string

	for _, f := range filters {
		if len(f.ExcludePatterns) > 0 {
			r, act := applyExclusion(result, f, contentFields)
			result = r
			actions = append(actions, act...)
		}
		if len(f.RedactPatterns) > 0 {
			r, act := applyRedaction(result, f, contentFields)
			result = r
			actions = append(actions, act...)
		}
		if f.ScriptPath != "" {
			// Opaque post-filter rewrite — a construct/run failure MUST fail
			// closed: return the ORIGINAL response, not the partially transformed
			// one, so a broken scrub can never leak content.
			r, act, err := applyScript(result, f)
			if err != nil {
				return responseJSON, strings.Join(actions, "; "), err
			}
			result = r
			actions = append(actions, act...)
		}
	}

	return []byte(result), strings.Join(actions, "; "), nil
}

// applyExclusion drops list items matching this filter's patterns (within its
// effective field set), handling the standard list shapes. Field-aware filters
// match only within content fields (a hit inside base64/metadata never drops the
// item); a whole-response filter matches the item's serialized JSON.
func applyExclusion(result string, f ResponseFilter, contentFields []string) (string, []string) {
	res := compileFilters(f.ExcludePatterns, f.Match)
	if len(res) == 0 {
		return result, nil
	}
	fields := f.fieldSet(contentFields)

	var data map[string]any
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		// Not a JSON object — only a whole-response exclude can match it.
		if fields == nil && anyMatch(res, result) {
			return "", []string{"response filtered: matched exclude pattern"}
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
			if itemExcluded(item, res, fields) {
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

// itemExcluded reports whether item matches the exclude filter. Field-aware
// filters match only within content fields (so a hit inside base64/metadata never
// drops the item); a whole-response filter matches the item's serialized JSON.
func itemExcluded(item any, res []*regexp.Regexp, fields map[string]bool) bool {
	if fields == nil {
		itemJSON, _ := json.Marshal(item)
		return anyMatch(res, string(itemJSON))
	}
	return matchInFields(item, fields, res)
}

// applyRedaction masks every match of this filter's patterns with "[REDACTED]"
// on the running result. Field-aware (only within the connector's content-field
// string values) when the filter has an effective field set; whole-response
// otherwise (the connector-agnostic auth-value scrub / back-compat path). A
// filter that masks ≥1 match is recorded by its label (audit attribution, e.g.
// auth_value_scrubbed).
func applyRedaction(result string, f ResponseFilter, contentFields []string) (string, []string) {
	res := compileFilters(f.RedactPatterns, f.Match)
	if len(res) == 0 {
		return result, nil
	}
	fields := f.fieldSet(contentFields)
	matched := false

	if fields == nil {
		out := result
		for _, re := range res {
			nr := re.ReplaceAllString(out, "[REDACTED]")
			if nr != out {
				out = nr
				matched = true
			}
		}
		result = out
	} else {
		var data any
		if err := json.Unmarshal([]byte(result), &data); err == nil {
			if redactInFields(data, fields, res) {
				matched = true
				if rewritten, mErr := json.Marshal(data); mErr == nil {
					result = string(rewritten)
				}
			}
		}
	}

	if matched {
		return result, []string{redactLabel(f)}
	}
	return result, nil
}

// applyScript runs an opaque post-filter rewrite on the running result. A
// construct/run failure returns a *ResponseFilterError so the caller can fail
// closed (never leak the un-rewritten content).
func applyScript(result string, f ResponseFilter) (string, []string, error) {
	eval, err := NewScriptEvaluator(map[string]any{"command": f.ScriptCommand, "script": f.ScriptPath})
	if err != nil {
		return result, nil, &ResponseFilterError{Filter: f, Err: err}
	}
	scriptReq := &PolicyRequest{
		Phase:    "post",
		Metadata: map[string]any{"phase": "post", "response": result},
	}
	scriptDec, err := eval.Evaluate(context.Background(), scriptReq)
	if err != nil {
		return result, nil, &ResponseFilterError{Filter: f, Err: err}
	}
	if scriptDec.Rewrite != "" {
		return scriptDec.Rewrite, []string{"script-filtered"}, nil
	}
	return result, nil, nil
}
