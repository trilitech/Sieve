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
	"errors"
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

// compileFilters compiles a pattern list under a match mode. A pattern that
// fails to compile is FATAL, not skipped: a protective redact/exclude whose
// pattern is malformed must fail CLOSED (the whole response is withheld by the
// caller) rather than silently degrade to a no-op that leaks the very content it
// was meant to remove.
func compileFilters(patterns []string, match string) ([]*regexp.Regexp, error) {
	res := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := compileFilterPattern(p, match)
		if err != nil {
			return nil, fmt.Errorf("invalid %s pattern %q: %w", matchLabel(match), p, err)
		}
		res = append(res, re)
	}
	return res, nil
}

// matchLabel names the match mode for error messages.
func matchLabel(match string) string {
	if match == "regex" {
		return "regex"
	}
	return "contains"
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
// a summary of what was done. On ANY filter failure — a script-filter
// construct/run failure, or a redact/exclude pattern that won't compile —
// returns the ORIGINAL response unchanged and a non-nil *ResponseFilterError so
// the caller can fail closed rather than leak un-redacted content. A protective
// filter that cannot run must never silently pass content through.
func ApplyResponseFilters(responseJSON []byte, filters []ResponseFilter, contentFields []string) ([]byte, string, error) {
	if len(filters) == 0 {
		return responseJSON, "", nil
	}

	result := string(responseJSON)
	var actions []string

	for _, f := range filters {
		if len(f.ExcludePatterns) > 0 {
			r, act, err := applyExclusion(result, f, contentFields)
			if err != nil {
				return responseJSON, strings.Join(actions, "; "), err
			}
			result = r
			actions = append(actions, act...)
		}
		if len(f.RedactPatterns) > 0 {
			r, act, err := applyRedaction(result, f, contentFields)
			if err != nil {
				return responseJSON, strings.Join(actions, "; "), err
			}
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
// effective field set). List detection is shape-agnostic (see excludeTree): any
// top-level array-of-objects key, the connector envelope `body`, and GraphQL
// `nodes` arrays are treated as item lists — it does NOT chase a hardcoded key
// allowlist, so a new connector returning a list under a new key
// (`pull_requests`, `records`, …) is filtered too. Field-aware filters match only
// within content fields (a hit inside base64/metadata never drops the item); a
// whole-response filter matches the item's serialized JSON. Nested structural
// arrays inside a kept item (labels/assignees/comments) are never recursed into,
// so kept items aren't corrupted.
func applyExclusion(result string, f ResponseFilter, contentFields []string) (string, []string, error) {
	res, err := compileFilters(f.ExcludePatterns, f.Match)
	if err != nil {
		return result, nil, &ResponseFilterError{Filter: f, Err: err}
	}
	if len(res) == 0 {
		return result, nil, nil
	}
	fields := f.fieldSet(contentFields)

	var data any
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		// The body is not valid JSON at all.
		if fields == nil {
			// Opaque whole-response filter — a match nukes the whole response.
			if anyMatch(res, result) {
				return "", []string{"response filtered: matched exclude pattern"}, nil
			}
			return result, nil, nil
		}
		// A field-aware exclude cannot act on a non-JSON body. Fail CLOSED
		// (withhold) rather than pass the unfilterable content through.
		return result, nil, &ResponseFilterError{Filter: f, Err: fmt.Errorf("exclude filter %q: response body is not JSON, cannot apply field-aware exclusion", f.Label)}
	}

	switch d := data.(type) {
	case []any:
		// Top-level JSON array root ([...]).
		filtered, removed := excludeItems(d, res, fields)
		if removed == 0 {
			return result, nil, nil
		}
		rewritten, _ := json.Marshal(filtered)
		return string(rewritten), []string{fmt.Sprintf("excluded %d item(s)", removed)}, nil
	case map[string]any:
		// FIX: the connector wraps a NON-JSON upstream response as
		// body:{"raw":"…"} (github/gitlab client). The outer envelope parses as an
		// object, so a field-aware/exclude filter finds no list and would silently
		// no-op — leaking exactly the content the operator meant to withhold. Fail
		// CLOSED: an opaque body can't be verified against the exclude patterns.
		if envelopeBodyIsOpaqueRaw(d) {
			return result, nil, &ResponseFilterError{Filter: f, Err: fmt.Errorf("exclude filter %q: upstream response body is opaque non-JSON (raw), cannot verify exclusion", f.Label)}
		}
		removed := excludeTree(d, res, fields)
		if removed == 0 {
			return result, nil, nil
		}
		rewritten, _ := json.Marshal(d)
		return string(rewritten), []string{fmt.Sprintf("excluded %d item(s)", removed)}, nil
	default:
		// Scalar JSON root (string/number/bool/null).
		if fields == nil {
			if anyMatch(res, result) {
				return "", []string{"response filtered: matched exclude pattern"}, nil
			}
			return result, nil, nil
		}
		return result, nil, &ResponseFilterError{Filter: f, Err: fmt.Errorf("exclude filter %q: response body is not a filterable object, cannot apply field-aware exclusion", f.Label)}
	}
}

// excludeTree filters the item lists in a decoded map response and returns the
// total removed. It recognizes three list positions and NOTHING deeper, which is
// what makes it both generic (no hardcoded key set) and safe (it never recurses
// into a kept item's internals, so structural sub-arrays like labels/assignees
// are untouched):
//
//   - Connector envelope {status, headers, body}: the payload list lives under
//     `body` — either a bare array, or a collection object (has a count/cursor
//     signal) whose array children are the list (e.g. github search
//     {total_count, items}). Also scrubs the `Link` pagination header, which the
//     envelope surfaces to the agent.
//   - Otherwise the root map is the container: every direct array-of-objects key
//     is an item list (messages/emails/records/pull_requests/…). Count + cursor
//     side-channels on the root are closed.
//   - GraphQL `nodes` arrays anywhere (Linear/GitHub-v4 connection shape).
func excludeTree(root map[string]any, res []*regexp.Regexp, fields map[string]bool) int {
	if isEnvelope(root) {
		removed := 0
		switch b := root["body"].(type) {
		case []any:
			filtered, r := excludeItems(b, res, fields)
			if r > 0 {
				root["body"] = filtered
				removed += r
			}
		case map[string]any:
			// Only treat a body OBJECT as a collection when it carries a count or
			// cursor — so a single-object get (body:{id,title,labels:[…]}) is not
			// mistaken for a list and its labels/assignees over-dropped.
			if hasListSignal(b) {
				removed += excludeContainer(b, res, fields)
			}
			removed += excludeFromNodes(b, res, fields)
		}
		if removed > 0 {
			scrubEnvelopeLink(root)
		}
		return removed
	}
	removed := excludeContainer(root, res, fields)
	removed += excludeFromNodes(root, res, fields)
	return removed
}

// excludeItems returns items with exclude-matching entries dropped and the count
// removed. Field-aware filters match only within content fields; a whole-response
// filter matches the item's serialized JSON.
func excludeItems(items []any, res []*regexp.Regexp, fields map[string]bool) ([]any, int) {
	// Non-nil slice so an all-removed list serialises as [] rather than null.
	filtered := make([]any, 0, len(items))
	removed := 0
	for _, item := range items {
		if itemExcluded(item, res, fields) {
			removed++
		} else {
			filtered = append(filtered, item)
		}
	}
	return filtered, removed
}

// excludeContainer drops matching items from every direct array-of-objects child
// of m (any key — not a hardcoded set) and, if anything was removed, closes the
// count + pagination side-channels on m. Scalar arrays (labelIds:["x"]) are
// skipped, and array elements are never recursed into, so nested structural
// arrays of kept items are left intact. `nodes` is handled by excludeFromNodes
// (which also resets pageInfo), so it is skipped here.
func excludeContainer(m map[string]any, res []*regexp.Regexp, fields map[string]bool) int {
	removed := 0
	for k, val := range m {
		if k == "nodes" {
			continue
		}
		arr, ok := val.([]any)
		if !ok || !isObjectList(arr) {
			continue
		}
		filtered, r := excludeItems(arr, res, fields)
		if r > 0 {
			m[k] = filtered
			removed += r
		}
	}
	if removed > 0 {
		decrementCountFields(m, removed)
		clearPaginationTokens(m)
		resetPageInfo(m)
	}
	return removed
}

// excludeFromNodes recurses the decoded response and applies the exclude to any
// GraphQL-style `nodes` array (the Linear/GitHub-v4 connection shape,
// data.<conn>.nodes). It returns the number of items removed. On each object that
// owns a `nodes` array it also closes the side-channels — decrementing count fields
// (incl. GraphQL `totalCount`) and clearing pagination (top-level cursors and a
// nested `pageInfo`). It does not recurse into a `nodes` array's own items, so a
// dropped item is removed whole and sub-connections of kept items are left intact.
func excludeFromNodes(v any, res []*regexp.Regexp, fields map[string]bool) int {
	removed := 0
	switch x := v.(type) {
	case map[string]any:
		if nodes, ok := x["nodes"].([]any); ok {
			filtered, r := excludeItems(nodes, res, fields)
			if r > 0 {
				x["nodes"] = filtered
				decrementCountFields(x, r)
				clearPaginationTokens(x)
				resetPageInfo(x)
				removed += r
			}
		}
		for k, val := range x {
			if k == "nodes" {
				continue // handled at this level; don't descend into the item list
			}
			removed += excludeFromNodes(val, res, fields)
		}
	case []any:
		for _, e := range x {
			removed += excludeFromNodes(e, res, fields)
		}
	}
	return removed
}

// isObjectList reports whether arr contains at least one JSON object — the shape
// of an item list. A pure scalar array (labelIds:["a","b"]) is not a list root
// and must not be item-filtered.
func isObjectList(arr []any) bool {
	for _, e := range arr {
		if _, ok := e.(map[string]any); ok {
			return true
		}
	}
	return false
}

// isEnvelope reports whether m is the connector response envelope
// {status, headers, body} that the github/gitlab (and mcp_proxy) connectors emit.
func isEnvelope(m map[string]any) bool {
	if _, ok := m["body"]; !ok {
		return false
	}
	if _, ok := m["headers"].(map[string]any); !ok {
		return false
	}
	_, ok := m["status"]
	return ok
}

// hasListSignal reports whether m carries a count or pagination field — i.e. it
// looks like a collection response rather than a single object. Used to decide
// whether an envelope body OBJECT's array children are item lists.
func hasListSignal(m map[string]any) bool {
	for _, k := range countFields {
		if _, ok := m[k]; ok {
			return true
		}
	}
	for _, k := range paginationKeys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	_, ok := m["pageInfo"]
	return ok
}

// envelopeBodyIsOpaqueRaw reports whether m is the connector envelope whose body
// is the exact non-JSON wrapper {"raw":"…"} the client emits when the upstream
// response wasn't valid JSON. Narrow by construction (single "raw" string key) so
// a normal single-object body is not mistaken for it.
func envelopeBodyIsOpaqueRaw(m map[string]any) bool {
	if !isEnvelope(m) {
		return false
	}
	body, ok := m["body"].(map[string]any)
	if !ok || len(body) != 1 {
		return false
	}
	_, ok = body["raw"].(string)
	return ok
}

// scrubEnvelopeLink removes the `Link` pagination header from a connector
// envelope's headers after items were withheld, so "more pages exist" (github/
// gitlab REST paginate via Link) isn't leaked around an exclusion.
func scrubEnvelopeLink(root map[string]any) {
	if hdrs, ok := root["headers"].(map[string]any); ok {
		delete(hdrs, "Link")
		delete(hdrs, "link")
	}
}

// resetPageInfo blanks a GraphQL `pageInfo` object on m (cursors + has*Page
// flags) after items were withheld from a sibling list.
func resetPageInfo(m map[string]any) {
	if pi, ok := m["pageInfo"].(map[string]any); ok {
		delete(pi, "endCursor")
		delete(pi, "startCursor")
		pi["hasNextPage"] = false
		pi["hasPreviousPage"] = false
	}
}

// countFields and paginationKeys enumerate the response fields across connector
// shapes that would otherwise leak an exclusion: a count of how many items exist
// (total/count/Gmail's resultSizeEstimate) or a cursor to page past the dropped
// item. After an exclude, every present count is decremented and every present
// cursor is cleared.
var countFields = []string{"total", "count", "resultSizeEstimate", "totalCount", "total_count"}
var paginationKeys = []string{
	"next_page_token", "nextPageToken", "nextLink",
	"cursor", "next_cursor", "page_token", "pageToken",
}

func decrementCountFields(data map[string]any, removed int) {
	for _, k := range countFields {
		if v, ok := data[k].(float64); ok {
			nv := v - float64(removed)
			if nv < 0 {
				nv = 0
			}
			data[k] = nv
		}
	}
}

func clearPaginationTokens(data map[string]any) {
	for _, k := range paginationKeys {
		delete(data, k)
	}
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
func applyRedaction(result string, f ResponseFilter, contentFields []string) (string, []string, error) {
	res, err := compileFilters(f.RedactPatterns, f.Match)
	if err != nil {
		return result, nil, &ResponseFilterError{Filter: f, Err: err}
	}
	if len(res) == 0 {
		return result, nil, nil
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
		if err := json.Unmarshal([]byte(result), &data); err != nil {
			// A field-aware redaction cannot act on a non-JSON body. Fail CLOSED
			// (withhold) rather than return the raw body unchanged — a silent
			// pass-through would leak exactly the content the operator meant to mask.
			return result, nil, &ResponseFilterError{Filter: f, Err: fmt.Errorf("redact filter %q: response body is not JSON, cannot apply field-aware redaction", f.Label)}
		}
		// Same opaque-body fail-closed as exclude: a NON-JSON upstream wrapped as
		// body:{"raw":"…"} parses as an object but carries no content fields to
		// mask, so a field-aware redact would silently pass it through.
		if m, ok := data.(map[string]any); ok && envelopeBodyIsOpaqueRaw(m) {
			return result, nil, &ResponseFilterError{Filter: f, Err: fmt.Errorf("redact filter %q: upstream response body is opaque non-JSON (raw), cannot apply field-aware redaction", f.Label)}
		}
		if redactInFields(data, fields, res) {
			matched = true
			if rewritten, mErr := json.Marshal(data); mErr == nil {
				result = string(rewritten)
			}
		}
	}

	if matched {
		return result, []string{redactLabel(f)}, nil
	}
	return result, nil, nil
}

// applyScript runs an opaque post-filter rewrite on the running result. It fails
// CLOSED via a *ResponseFilterError whenever it cannot positively confirm a
// clean outcome, so a broken/denying scrub can never leak the un-rewritten
// content:
//   - the script path is re-validated against the allowlist at exec time
//     (defense-in-depth: a path that left the allowlist since save, or a
//     tampered config, must not reach the interpreter — mirrors runScriptCondition);
//   - a construct or evaluation error fails closed;
//   - a rewrite is applied;
//   - a genuine {"action":"allow"} with no rewrite is a legit no-op (the script
//     inspected the response and chose not to modify it);
//   - ANY other outcome (deny / approval_required / a runtime failure that the
//     evaluator surfaces as a deny PolicyDecision with a nil error) fails closed
//     — returning the un-rewritten response here was the original fail-OPEN bug.
func applyScript(result string, f ResponseFilter) (string, []string, error) {
	if err := ValidateScriptPath(f.ScriptPath); err != nil {
		return result, nil, &ResponseFilterError{Filter: f, Err: err}
	}
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
	if scriptDec.Action == "allow" {
		return result, nil, nil
	}
	reason := scriptDec.Reason
	if reason == "" {
		reason = fmt.Sprintf("script filter returned no rewrite (action %q)", scriptDec.Action)
	}
	return result, nil, &ResponseFilterError{Filter: f, Err: errors.New(reason)}
}
