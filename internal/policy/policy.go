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

// redactInFields walks decoded JSON and replaces regex matches with [REDACTED]
// in the string value of any map key in `fields`, recursively. Returns whether
// anything changed. Non-content fields (ids, base64 attachment data, metadata)
// are never touched. Returns the count of fields modified.
func redactInFields(v any, fields map[string]bool, res []*regexp.Regexp) bool {
	changed := false
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok && fields[k] {
				ns := s
				for _, re := range res {
					ns = re.ReplaceAllString(ns, "[REDACTED]")
				}
				if ns != s {
					x[k] = ns
					changed = true
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

	for _, f := range filters {
		// Effective content-field set for this filter (nil ⇒ whole-response —
		// the back-compat / auth-scrub path).
		fields := f.fieldSet(contentFields)

		// Exclude: drop list items matching ANY pattern. Field-aware when the
		// connector declares content fields (match only those fields, so a hit
		// inside base64/metadata never drops the item); whole-item otherwise.
		if len(f.ExcludePatterns) > 0 {
			res := compileFilters(f.ExcludePatterns, f.Match)

			var data map[string]any
			if err := json.Unmarshal([]byte(result), &data); err != nil {
				// Not a JSON object — only whole-response mode can match it.
				if fields == nil && anyMatch(res, result) {
					result = ""
					actions = append(actions, "response filtered: matched exclude pattern")
				}
				continue
			}

			// Handle list formats: {"emails": [...]}, {"messages": [...]}, etc.
			for _, key := range []string{"emails", "messages", "items", "threads", "results"} {
				items, ok := data[key].([]any)
				if !ok {
					continue
				}

				var filtered []any
				removed := 0
				for _, item := range items {
					hit := false
					if fields == nil {
						itemJSON, _ := json.Marshal(item)
						hit = anyMatch(res, string(itemJSON))
					} else {
						hit = matchInFields(item, fields, res)
					}
					if hit {
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
					rewritten, _ := json.Marshal(data)
					result = string(rewritten)
					actions = append(actions, fmt.Sprintf("excluded %d item(s)", removed))
				}
			}
		}

		// Redact: mask matches with [REDACTED]. Field-aware (only content-field
		// string values) when content fields are declared; whole-response
		// otherwise (back-compat / the connector-agnostic auth-value scrub).
		if len(f.RedactPatterns) > 0 {
			res := compileFilters(f.RedactPatterns, f.Match)
			if fields == nil {
				for _, re := range res {
					nr := re.ReplaceAllString(result, "[REDACTED]")
					if nr != result {
						result = nr
						actions = append(actions, redactLabel(f))
					}
				}
			} else {
				var data any
				if err := json.Unmarshal([]byte(result), &data); err == nil {
					if redactInFields(data, fields, res) {
						if rewritten, mErr := json.Marshal(data); mErr == nil {
							result = string(rewritten)
							actions = append(actions, redactLabel(f))
						}
					}
				}
			}
		}

		// Script: run a post-filter script. A failure to construct or run
		// the evaluator MUST fail closed — silently skipping the filter
		// would return un-redacted content to the agent.
		if f.ScriptPath != "" {
			scriptConfig := map[string]any{
				"command": f.ScriptCommand,
				"script":  f.ScriptPath,
			}
			eval, err := NewScriptEvaluator(scriptConfig)
			if err != nil {
				return responseJSON, strings.Join(actions, "; "), &ResponseFilterError{Filter: f, Err: err}
			}
			scriptReq := &PolicyRequest{
				Phase: "post",
				Metadata: map[string]any{
					"phase":    "post",
					"response": result,
				},
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
	}

	return []byte(result), strings.Join(actions, "; "), nil
}
