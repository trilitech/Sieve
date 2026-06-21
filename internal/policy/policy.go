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
	Match         string `json:"match,omitempty"`
	ScriptPath    string `json:"script_path,omitempty"`    // post-filter script
	ScriptCommand string `json:"script_command,omitempty"` // e.g. "python3"
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
func ApplyResponseFilters(responseJSON []byte, filters []ResponseFilter) ([]byte, string, error) {
	if len(filters) == 0 {
		return responseJSON, "", nil
	}

	result := string(responseJSON)
	var actions []string

	for _, f := range filters {
		// Exclude: drop list items (or the whole response) matching ANY pattern,
		// interpreted per f.Match (contains|regex) — same matching model as redact.
		if len(f.ExcludePatterns) > 0 {
			res := make([]*regexp.Regexp, 0, len(f.ExcludePatterns))
			for _, p := range f.ExcludePatterns {
				if re, err := compileFilterPattern(p, f.Match); err == nil {
					res = append(res, re)
				}
			}
			matchAny := func(s string) bool {
				for _, re := range res {
					if re.MatchString(s) {
						return true
					}
				}
				return false
			}

			var data map[string]any
			if err := json.Unmarshal([]byte(result), &data); err != nil {
				// Not a JSON object — match against the whole response.
				if matchAny(result) {
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
					itemJSON, _ := json.Marshal(item)
					if matchAny(string(itemJSON)) {
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

		// Redact: mask matches of ANY pattern with [REDACTED], per f.Match.
		for _, pattern := range f.RedactPatterns {
			re, err := compileFilterPattern(pattern, f.Match)
			if err != nil {
				continue
			}
			newResult := re.ReplaceAllString(result, "[REDACTED]")
			if newResult != result {
				result = newResult
				if f.Label != "" {
					actions = append(actions, f.Label)
				} else {
					actions = append(actions, "redacted")
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
