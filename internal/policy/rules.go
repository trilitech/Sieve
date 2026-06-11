// Package policy implements the Sieve policy engine that governs what AI agents
// can and cannot do.
// rules.go contains the rules-based policy evaluator, the most common evaluator
// type. It implements a first-match-wins model inspired by firewall rule chains:
// rules are evaluated top-to-bottom and the first rule whose conditions match
// determines the outcome. If no rule matches, the configured default action
// (typically "deny") applies.
// Rules are evaluated in a single pre-execution phase. Post-execution content
// filtering is handled via ResponseFilter objects that are collected during
// evaluation and applied by the caller after the operation executes.
// Match conditions within a single rule use AND logic: all specified conditions
// must be true for the rule to fire. An empty match block matches everything,
// which is useful for catch-all rules at the bottom of the list.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Rule is a single entry in an ordered rule list.
type Rule struct {
	// Match conditions — all must be true for the rule to fire (AND logic).
	// Empty/nil match = matches everything.
	Match *RuleMatch `json:"match,omitempty"`

	// Action to take when matched.
	Action string `json:"action"` // "allow", "deny", "approval_required", "script"

	// Reason shown to the agent when this rule fires.
	Reason string `json:"reason,omitempty"`

	// Script config — only for action="script".
	Script *ScriptAction `json:"script,omitempty"`

	// FilterExclude — KEPT for backward compatibility. Translates to a
	// ResponseFilter with ExcludeContaining at evaluation time.
	FilterExclude string `json:"filter_exclude,omitempty"`

	// RedactPatterns — KEPT for backward compatibility. Translates to a
	// ResponseFilter with RedactPatterns at evaluation time.
	RedactPatterns []string `json:"redact_patterns,omitempty"`

	// ResponseFilter — per-rule post-processing applied after execution
	// when this rule matches with "allow".
	ResponseFilter *ResponseFilter `json:"response_filter,omitempty"`
}

// RuleMatch defines conditions for a rule to fire.
type RuleMatch struct {
	// Operations to match (exact names). Empty = match all.
	Operations []string `json:"operations,omitempty"`

	// The rules evaluator no longer checks this field; all rules evaluate
	// in pre-execution mode. Post-execution filtering uses ResponseFilter.
	// Phase field removed — single-phase model. Field kept in JSON for backward compat only.

	// ContentContains — match if the response in metadata contains
	// this string (case-insensitive).
	ContentContains string `json:"content_contains,omitempty"`

	// From — match if the email's from address matches any of these
	// (supports * prefix glob like "*@company.com").
	From []string `json:"from,omitempty"`

	// SubjectContains — match if subject contains any of these strings
	// (case-insensitive).
	SubjectContains []string `json:"subject_contains,omitempty"`

	// Labels — match if the email has at least one of these labels.
	Labels []string `json:"labels,omitempty"`

	// To — match if the recipient address matches any of these
	// (supports * prefix glob like "*@company.com").
	To []string `json:"to,omitempty"`

	// Model — match if the LLM model matches any of these
	// (supports * glob like "claude-*").
	Model []string `json:"model,omitempty"`

	// Providers — match if the provider matches any of these (exact match).
	Providers []string `json:"providers,omitempty"`

	// Path — glob match against the request path (for HTTP proxy).
	Path string `json:"path,omitempty"`

	// Method — match against the request's HTTP method (for HTTP proxy).
	// Comparison is case-insensitive; entries are exact strings (no glob).
	// Examples: ["GET"], ["POST", "PUT"], ["DELETE"]. Empty = match any
	// method. Reads params["method"] (set by the API router on every
	// proxy request) so the field is meaningful only for http_proxy
	// connections; for other connectors the field is silently ignored.
	Method []string `json:"method,omitempty"`

	// BodyContains — case-insensitive substring check against the request body.
	BodyContains string `json:"body_contains,omitempty"`

	// MaxTokens — if > 0, request's max_tokens must not exceed this value.
	MaxTokens int `json:"max_tokens,omitempty"`

	// MaxCost — if > 0, request's estimated cost must not exceed this value.
	MaxCost float64 `json:"max_cost,omitempty"`

	// InstanceType — match against EC2 instance types (exact match).
	InstanceType []string `json:"instance_type,omitempty"`

	// Region — match against AWS region (exact match).
	Region string `json:"region,omitempty"`

	// Bucket — glob match against S3 bucket name.
	Bucket string `json:"bucket,omitempty"`

	// KeyPrefix — prefix match against S3 object key.
	KeyPrefix string `json:"key_prefix,omitempty"`

	// --- Google services ---

	// MimeType — glob match against params["mime_type"] (Drive).
	MimeType string `json:"mime_type,omitempty"`

	// Owner — glob match against params["owner"] (Drive).
	Owner string `json:"owner,omitempty"`

	// CalendarID — exact match against params["calendar_id"] (Calendar).
	CalendarID string `json:"calendar_id,omitempty"`

	// Attendee — glob match against params["attendee"] (Calendar).
	Attendee string `json:"attendee,omitempty"`

	// SpreadsheetID — exact match against params["spreadsheet_id"] (Sheets).
	SpreadsheetID string `json:"spreadsheet_id,omitempty"`

	// DocumentID — exact match against params["document_id"] (Docs).
	DocumentID string `json:"document_id,omitempty"`

	// TitleContains — case-insensitive substring match against params["title"] (Docs).
	TitleContains string `json:"title_contains,omitempty"`

	// --- AWS ---

	// MaxCount — numeric comparison against params["max_count"] or params["count"] (EC2).
	MaxCount int `json:"max_count,omitempty"`

	// AMI — glob match against params["ami"] or params["image_id"] (EC2).
	AMI string `json:"ami,omitempty"`

	// VPC — exact match against params["vpc_id"] or params["subnet_id"] (EC2).
	VPC string `json:"vpc,omitempty"`

	// Ports — comma-separated allowed ports; params["port"] must be in the list (EC2).
	Ports string `json:"ports,omitempty"`

	// CIDR — if set to "!0.0.0.0/0", deny 0.0.0.0/0; otherwise match pattern against params["cidr"] (EC2).
	CIDR string `json:"cidr,omitempty"`

	// FunctionName — glob match against params["function_name"] (Lambda).
	FunctionName string `json:"function_name,omitempty"`

	// Recipient — glob match against params["recipient"] or params["to"] (SES).
	Recipient string `json:"recipient,omitempty"`

	// TableName — exact match against params["table_name"] or params["table"] (DynamoDB).
	TableName string `json:"table_name,omitempty"`

	// --- Hyperstack ---

	// Flavor — exact match against params["flavor"].
	Flavor string `json:"flavor,omitempty"`

	// MaxVMs — numeric comparison against params["count"].
	MaxVMs int `json:"max_vms,omitempty"`

	// --- LLM provider-specific ---

	// ExtendedThinking — match against params["extended_thinking"] ("enabled"/"disabled").
	ExtendedThinking string `json:"extended_thinking,omitempty"`

	// SystemPromptContains — case-insensitive substring against params["system"] or params["system_prompt"].
	SystemPromptContains string `json:"system_prompt_contains,omitempty"`

	// MaxTemperature — numeric comparison against params["temperature"].
	MaxTemperature float64 `json:"max_temperature,omitempty"`

	// JSONMode — match against params["response_format"] ("required"/"forbidden").
	JSONMode string `json:"json_mode,omitempty"`

	// Grounding — match against params["grounding"] ("enabled"/"disabled").
	Grounding string `json:"grounding,omitempty"`

	// SafetyThreshold — match against params["safety_settings"] or params["safety"].
	SafetyThreshold string `json:"safety_threshold,omitempty"`

	// --- Additional service-specific ---

	// SharedStatus — match against params["shared_status"] (Drive: "shared with me"/"owned by me").
	SharedStatus string `json:"shared_status,omitempty"`

	// ContactGroup — exact match against params["contact_group"] or params["group"] (People).
	ContactGroup string `json:"contact_group,omitempty"`

	// AllowedFields — comma-separated list checked against params["fields"] (People).
	AllowedFields string `json:"allowed_fields,omitempty"`

	// RangePattern — glob match against params["range"] (Sheets).
	RangePattern string `json:"range_pattern,omitempty"`

	// Tag — match against params["tag"] (EC2, format "key=value").
	Tag string `json:"tag,omitempty"`

	// SenderIdentity — exact match against params["sender"] or params["from"] (SES).
	SenderIdentity string `json:"sender_identity,omitempty"`

	// IndexName — exact match against params["index_name"] or params["index"] (DynamoDB).
	IndexName string `json:"index_name,omitempty"`

	// --- Slack ---

	// Channel — glob match against params["channel"]. Used by Slack ops
	// that take a channel target (read_channel_history, read_thread,
	// post_message). Supports leading/trailing "*". Compared
	// case-insensitively, so a "#general" pattern matches an agent
	// param of either "#general" or "C0123ABCDE" only when the agent
	// sent the literal name — Slack channel IDs and names are different
	// values, so operators should pick whichever form their agents pass.
	Channel string `json:"channel,omitempty"`

	// SlackUser — glob match against params["user"]. Used by Slack
	// read_user_profile to gate which user records an agent may pull
	// (e.g. allow "U01ADMIN*" only). Distinct from the email-oriented
	// From/To fields above. Kept as a separate Go name to avoid
	// shadowing those existing string-slice fields.
	SlackUser string `json:"user,omitempty"`

	// TextContains — case-insensitive substring match against
	// params["text"]. Primary gate for Slack post_message body content.
	// Use a deny rule to block keywords; combine with `operations:
	// ["post_message"]` to scope the rule. The field is intentionally
	// generic enough to be reusable by any future connector whose write
	// op uses a "text" param.
	TextContains string `json:"text_contains,omitempty"`
}

// ScriptAction defines a script to run for action="script".
type ScriptAction struct {
	Command string `json:"command"` // e.g. "python3"
	Path    string `json:"path"`    // script file path
	Timeout string `json:"timeout"` // e.g. "5s"
}

// RulesConfig is the config for the rules evaluator.
type RulesConfig struct {
	Rules           []Rule           `json:"rules"`
	DefaultAction   string           `json:"default_action"` // "allow" or "deny", default "deny"
	Scope           string           `json:"scope,omitempty"`
	ResponseFilters []ResponseFilter `json:"response_filters,omitempty"` // global post-processing filters
}

// RulesEvaluator evaluates an ordered list of rules using first-match-wins
// semantics. Redact patterns are precompiled at construction time to avoid
// repeated regex compilation on every request.
type RulesEvaluator struct {
	config         RulesConfig
	redactCompiled map[int][]*regexp.Regexp // precompiled per rule index
}

// NewRulesEvaluator creates a RulesEvaluator from a generic config map.
func NewRulesEvaluator(config map[string]any, providers map[string]LLMProviderConfig) (*RulesEvaluator, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("rules evaluator: marshal config: %w", err)
	}

	var rc RulesConfig
	if err := json.Unmarshal(data, &rc); err != nil {
		return nil, fmt.Errorf("rules evaluator: parse config: %w", err)
	}

	// Default to deny-by-default: if no rule matches, the safest posture
	// is to block the action rather than allow it.
	if rc.DefaultAction == "" {
		rc.DefaultAction = "deny"
	}

	// Precompile redact patterns.
	compiled := make(map[int][]*regexp.Regexp)
	for i, rule := range rc.Rules {
		if len(rule.RedactPatterns) > 0 {
			var patterns []*regexp.Regexp
			for _, p := range rule.RedactPatterns {
				re, err := regexp.Compile(p)
				if err != nil {
					return nil, fmt.Errorf("rules evaluator: rule %d: invalid redact pattern %q: %w", i, p, err)
				}
				patterns = append(patterns, re)
			}
			compiled[i] = patterns
		}
	}

	return &RulesEvaluator{config: rc, redactCompiled: compiled}, nil
}

func (r *RulesEvaluator) Type() string { return "rules" }

// Evaluate iterates rules top to bottom. First matching rule wins.
// Rules always evaluate in pre-execution mode. Post-execution content
// filtering is handled via ResponseFilter objects attached to the decision.
func (r *RulesEvaluator) Evaluate(ctx context.Context, req *PolicyRequest) (*PolicyDecision, error) {
	// First-match-wins: iterate rules in order. The first rule whose conditions
	// all match determines the decision. This makes rule ordering critical —
	// more specific rules must come before broader catch-all rules.
	for i, rule := range r.config.Rules {
		if !r.matches(&rule, req) {
			continue
		}

		// This rule matched — its action is authoritative.
		switch rule.Action {
		case "allow", "filter":
			decision := &PolicyDecision{
				Action: "allow",
				Reason: rule.Reason,
			}
			r.applyRedactions(decision, i, req)
			r.collectFilters(decision, &rule)
			return decision, nil

		case "deny":
			reason := rule.Reason
			if reason == "" {
				reason = fmt.Sprintf("denied by rule %d", i+1)
			}
			return &PolicyDecision{Action: "deny", Reason: reason}, nil

		case "approval_required":
			reason := rule.Reason
			if reason == "" {
				reason = fmt.Sprintf("approval required by rule %d", i+1)
			}
			return &PolicyDecision{Action: "approval_required", Reason: reason}, nil

		case "script":
			// Script actions delegate the decision to an external process,
			// enabling custom logic that's too complex for declarative rules.
			// Missing script config is treated as deny (fail-closed).
			if rule.Script == nil {
				return &PolicyDecision{Action: "deny", Reason: "rule has action=script but no script config"}, nil
			}
			scriptConfig := map[string]any{
				"command": rule.Script.Command,
				"script":  rule.Script.Path,
				"timeout": rule.Script.Timeout,
			}
			eval, err := NewScriptEvaluator(scriptConfig)
			if err != nil {
				return &PolicyDecision{Action: "deny", Reason: "script evaluator error: " + err.Error()}, nil
			}
			return eval.Evaluate(ctx, req)

		default:
			// Unknown action, skip to next rule.
			continue
		}
	}

	// No rule matched — use the configured default (typically "deny" for
	// fail-closed security).
	return &PolicyDecision{
		Action: r.config.DefaultAction,
		Reason: "default policy",
	}, nil
}

// collectFilters gathers ResponseFilter objects from a matched rule and from
// the global config, attaching them to the decision for post-execution use.
func (r *RulesEvaluator) collectFilters(decision *PolicyDecision, rule *Rule) {
	// Per-rule ResponseFilter (new style).
	if rule.ResponseFilter != nil {
		decision.Filters = append(decision.Filters, *rule.ResponseFilter)
	}

	// Legacy backward-compat: translate FilterExclude into a ResponseFilter.
	if rule.FilterExclude != "" {
		decision.Filters = append(decision.Filters, ResponseFilter{
			ExcludeContaining: rule.FilterExclude,
		})
	}

	// Legacy backward-compat: translate RedactPatterns into a ResponseFilter.
	if len(rule.RedactPatterns) > 0 {
		decision.Filters = append(decision.Filters, ResponseFilter{
			RedactPatterns: rule.RedactPatterns,
		})
	}

	// Global response filters from the config.
	decision.Filters = append(decision.Filters, r.config.ResponseFilters...)
}

// matches checks if a rule's conditions all match the request. All specified
// conditions must be true (AND logic). This means adding more conditions to a
// rule makes it narrower, not broader. A nil match block matches everything,
// useful for default/catch-all rules.
func (r *RulesEvaluator) matches(rule *Rule, req *PolicyRequest) bool {
	m := rule.Match
	if m == nil {
		return true // no conditions = match everything
	}

	// Operation check.
	if len(m.Operations) > 0 {
		matched := false
		for _, op := range m.Operations {
			if op == "*" || op == req.Operation {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Content contains check (typically used with response data in metadata).
	if m.ContentContains != "" {
		response, _ := req.Metadata["response"].(string)
		if !strings.Contains(strings.ToLower(response), strings.ToLower(m.ContentContains)) {
			return false
		}
	}

	// From address check. The "from" field may appear in metadata (extracted
	// from the response) or in params (provided by the agent). We check both
	// locations to support matching regardless of where the data originates.
	if len(m.From) > 0 {
		from := getStringParamSafe(req.Metadata, "from")
		if from == "" {
			from = getStringParamSafe(req.Params, "from")
		}
		fromLower := strings.ToLower(from)
		matched := false
		for _, pattern := range m.From {
			pattern = strings.ToLower(pattern)
			if pattern == fromLower {
				matched = true
			} else if strings.HasPrefix(pattern, "*") && strings.HasSuffix(fromLower, pattern[1:]) {
				matched = true
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Subject contains check.
	if len(m.SubjectContains) > 0 {
		subject, _ := req.Metadata["subject"].(string)
		subjectLower := strings.ToLower(subject)
		matched := false
		for _, kw := range m.SubjectContains {
			if strings.Contains(subjectLower, strings.ToLower(kw)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Label check. Labels are tricky because they may arrive as structured
	// metadata (parsed []any) or be embedded in a raw JSON response string.
	// The fallback to raw string matching handles the case where the response
	// contains label data that hasn't been explicitly extracted into metadata.
	// Label check. Three paths:
	// 1. Structured labels in metadata (parsed []any) → match against those
	// 2. Labels in raw response string → raw substring match
	// 3. No label data at all → fail-closed (don't match)
	if len(m.Labels) > 0 {
		labelsVerified := false

		// Path 1: structured labels from metadata
		if labels, ok := req.Metadata["labels"].([]any); ok && len(labels) > 0 {
			var emailLabels []string
			for _, l := range labels {
				if s, ok := l.(string); ok {
					emailLabels = append(emailLabels, strings.ToLower(s))
				}
			}
			matched := false
			for _, want := range m.Labels {
				for _, have := range emailLabels {
					if strings.EqualFold(want, have) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				return false
			}
			labelsVerified = true
		}

		// Path 2: raw response string fallback
		if !labelsVerified {
			if response, ok := req.Metadata["response"].(string); ok {
				responseLower := strings.ToLower(response)
				if strings.Contains(responseLower, `"labels"`) {
					matched := false
					for _, want := range m.Labels {
						if strings.Contains(responseLower, strings.ToLower(want)) {
							matched = true
							break
						}
					}
					if !matched {
						return false
					}
					labelsVerified = true
				}
			}
		}

		// Path 3: no label data found — fail-closed
		if !labelsVerified {
			return false
		}
	}

	// To address check (same glob pattern as From).
	if len(m.To) > 0 {
		to := getStringParamSafe(req.Metadata, "to")
		if to == "" {
			to = getStringParamSafe(req.Params, "to")
		}
		toLower := strings.ToLower(to)
		matched := false
		for _, pattern := range m.To {
			pattern = strings.ToLower(pattern)
			if pattern == toLower {
				matched = true
			} else if strings.HasPrefix(pattern, "*") && strings.HasSuffix(toLower, pattern[1:]) {
				matched = true
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Model check (glob support).
	if len(m.Model) > 0 {
		model, _ := req.Params["model"].(string)
		if model == "" {
			model, _ = req.Metadata["model"].(string)
		}
		modelLower := strings.ToLower(model)
		matched := false
		for _, pattern := range m.Model {
			pattern = strings.ToLower(pattern)
			if pattern == modelLower {
				matched = true
			} else if strings.HasPrefix(pattern, "*") && strings.HasSuffix(modelLower, pattern[1:]) {
				matched = true
			} else if strings.HasSuffix(pattern, "*") && strings.HasPrefix(modelLower, pattern[:len(pattern)-1]) {
				matched = true
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Provider check (exact match).
	if len(m.Providers) > 0 {
		provider, _ := req.Params["provider"].(string)
		if provider == "" {
			provider, _ = req.Metadata["provider"].(string)
		}
		providerLower := strings.ToLower(provider)
		matched := false
		for _, p := range m.Providers {
			if strings.ToLower(p) == providerLower {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Path check (glob support).
	if m.Path != "" {
		path, _ := req.Params["path"].(string)
		if path == "" {
			path, _ = req.Metadata["path"].(string)
		}
		pattern := strings.ToLower(m.Path)
		pathLower := strings.ToLower(path)
		matched := false
		if pattern == pathLower {
			matched = true
		} else if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pathLower, pattern[1:]) {
			matched = true
		} else if strings.HasSuffix(pattern, "*") && strings.HasPrefix(pathLower, pattern[:len(pattern)-1]) {
			matched = true
		}
		if !matched {
			return false
		}
	}

	// Method check — case-insensitive equality against any of the
	// configured methods. Reads params["method"] (set by the API router
	// for transparent http_proxy requests) with a metadata fallback.
	if len(m.Method) > 0 {
		method, _ := req.Params["method"].(string)
		if method == "" {
			method, _ = req.Metadata["method"].(string)
		}
		methodUpper := strings.ToUpper(strings.TrimSpace(method))
		matched := false
		for _, want := range m.Method {
			if strings.ToUpper(strings.TrimSpace(want)) == methodUpper {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Body contains check.
	if m.BodyContains != "" {
		body, _ := req.Params["body"].(string)
		if !strings.Contains(strings.ToLower(body), strings.ToLower(m.BodyContains)) {
			return false
		}
	}

	// MaxTokens check (uses clamped getIntParam to prevent overflow).
	if m.MaxTokens > 0 {
		reqTokens := getIntParam(req.Params, "max_tokens")
		if reqTokens > m.MaxTokens {
			return false
		}
	}

	// MaxCost check (uses getFloatParam which clamps negatives to 0).
	if m.MaxCost > 0 {
		cost := getFloatParam(req.Params, "max_cost")
		if cost == 0 {
			cost = getFloatParam(req.Metadata, "estimated_cost")
		}
		if cost > m.MaxCost {
			return false
		}
	}

	// InstanceType check (exact match).
	if len(m.InstanceType) > 0 {
		it, _ := req.Params["instance_type"].(string)
		itLower := strings.ToLower(it)
		matched := false
		for _, t := range m.InstanceType {
			if strings.ToLower(t) == itLower {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Region check (exact match).
	if m.Region != "" {
		region, _ := req.Params["region"].(string)
		if !strings.EqualFold(m.Region, region) {
			return false
		}
	}

	// Bucket check (glob support).
	if m.Bucket != "" {
		bucket, _ := req.Params["bucket"].(string)
		pattern := strings.ToLower(m.Bucket)
		bucketLower := strings.ToLower(bucket)
		matched := false
		if pattern == bucketLower {
			matched = true
		} else if strings.HasPrefix(pattern, "*") && strings.HasSuffix(bucketLower, pattern[1:]) {
			matched = true
		} else if strings.HasSuffix(pattern, "*") && strings.HasPrefix(bucketLower, pattern[:len(pattern)-1]) {
			matched = true
		}
		if !matched {
			return false
		}
	}

	// KeyPrefix check (prefix match).
	if m.KeyPrefix != "" {
		key, _ := req.Params["key"].(string)
		if !strings.HasPrefix(key, m.KeyPrefix) {
			return false
		}
	}

	// MimeType check (glob support).
	if m.MimeType != "" {
		mt, _ := req.Params["mime_type"].(string)
		if mt == "" {
			mt, _ = req.Metadata["mime_type"].(string)
		}
		if !globMatch(m.MimeType, mt) {
			return false
		}
	}

	// Owner check (glob support).
	if m.Owner != "" {
		owner, _ := req.Params["owner"].(string)
		if owner == "" {
			owner, _ = req.Metadata["owner"].(string)
		}
		if !globMatch(m.Owner, owner) {
			return false
		}
	}

	// CalendarID check (exact match, case-insensitive).
	if m.CalendarID != "" {
		calID, _ := req.Params["calendar_id"].(string)
		if calID == "" {
			calID, _ = req.Metadata["calendar_id"].(string)
		}
		if !strings.EqualFold(m.CalendarID, calID) {
			return false
		}
	}

	// Attendee check (glob support).
	if m.Attendee != "" {
		attendee, _ := req.Params["attendee"].(string)
		if attendee == "" {
			attendee, _ = req.Metadata["attendee"].(string)
		}
		if !globMatch(m.Attendee, attendee) {
			return false
		}
	}

	// SpreadsheetID check (exact match, case-insensitive).
	if m.SpreadsheetID != "" {
		ssID, _ := req.Params["spreadsheet_id"].(string)
		if ssID == "" {
			ssID, _ = req.Metadata["spreadsheet_id"].(string)
		}
		if !strings.EqualFold(m.SpreadsheetID, ssID) {
			return false
		}
	}

	// DocumentID check (exact match, case-insensitive).
	if m.DocumentID != "" {
		docID, _ := req.Params["document_id"].(string)
		if docID == "" {
			docID, _ = req.Metadata["document_id"].(string)
		}
		if !strings.EqualFold(m.DocumentID, docID) {
			return false
		}
	}

	// TitleContains check (case-insensitive substring).
	if m.TitleContains != "" {
		title, _ := req.Params["title"].(string)
		if title == "" {
			title, _ = req.Metadata["title"].(string)
		}
		if !strings.Contains(strings.ToLower(title), strings.ToLower(m.TitleContains)) {
			return false
		}
	}

	// MaxCount check (numeric comparison).
	if m.MaxCount > 0 {
		reqCount := getIntParam(req.Params, "max_count")
		if reqCount == 0 {
			reqCount = getIntParam(req.Params, "count")
		}
		if reqCount > m.MaxCount {
			return false
		}
	}

	// AMI check (glob support).
	if m.AMI != "" {
		ami, _ := req.Params["ami"].(string)
		if ami == "" {
			ami, _ = req.Params["image_id"].(string)
		}
		if ami == "" {
			ami, _ = req.Metadata["ami"].(string)
		}
		if !globMatch(m.AMI, ami) {
			return false
		}
	}

	// VPC check (exact match against vpc_id or subnet_id).
	if m.VPC != "" {
		vpc, _ := req.Params["vpc_id"].(string)
		if vpc == "" {
			vpc, _ = req.Params["subnet_id"].(string)
		}
		if vpc == "" {
			vpc, _ = req.Metadata["vpc_id"].(string)
		}
		if !strings.EqualFold(m.VPC, vpc) {
			return false
		}
	}

	// Ports check (comma-separated allowed list).
	if m.Ports != "" {
		port, _ := req.Params["port"].(string)
		if port == "" {
			// Try numeric port.
			switch v := req.Params["port"].(type) {
			case float64:
				port = strconv.Itoa(int(v))
			case int:
				port = strconv.Itoa(v)
			}
		}
		if port == "" {
			port, _ = req.Metadata["port"].(string)
		}
		allowed := strings.Split(m.Ports, ",")
		matched := false
		for _, a := range allowed {
			if strings.TrimSpace(a) == strings.TrimSpace(port) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// CIDR check.
	if m.CIDR != "" {
		cidr, _ := req.Params["cidr"].(string)
		if cidr == "" {
			cidr, _ = req.Metadata["cidr"].(string)
		}
		if strings.HasPrefix(m.CIDR, "!") {
			// Negation: deny if cidr equals the negated value.
			denied := m.CIDR[1:]
			if cidr == denied {
				return false
			}
		} else {
			if !strings.EqualFold(m.CIDR, cidr) {
				return false
			}
		}
	}

	// FunctionName check (glob support).
	if m.FunctionName != "" {
		fn, _ := req.Params["function_name"].(string)
		if fn == "" {
			fn, _ = req.Metadata["function_name"].(string)
		}
		if !globMatch(m.FunctionName, fn) {
			return false
		}
	}

	// Recipient check (glob support, checks "recipient" then "to").
	if m.Recipient != "" {
		rcpt, _ := req.Params["recipient"].(string)
		if rcpt == "" {
			rcpt, _ = req.Params["to"].(string)
		}
		if rcpt == "" {
			rcpt, _ = req.Metadata["recipient"].(string)
		}
		if !globMatch(m.Recipient, rcpt) {
			return false
		}
	}

	// TableName check (exact match, checks "table_name" then "table").
	if m.TableName != "" {
		table, _ := req.Params["table_name"].(string)
		if table == "" {
			table, _ = req.Params["table"].(string)
		}
		if table == "" {
			table, _ = req.Metadata["table_name"].(string)
		}
		if !strings.EqualFold(m.TableName, table) {
			return false
		}
	}

	// Flavor check (exact match).
	if m.Flavor != "" {
		flavor, _ := req.Params["flavor"].(string)
		if flavor == "" {
			flavor, _ = req.Metadata["flavor"].(string)
		}
		if !strings.EqualFold(m.Flavor, flavor) {
			return false
		}
	}

	// MaxVMs check (numeric comparison against "count").
	if m.MaxVMs > 0 {
		count := getIntParam(req.Params, "count")
		if count > m.MaxVMs {
			return false
		}
	}

	// ExtendedThinking check.
	if m.ExtendedThinking != "" {
		val, _ := req.Params["extended_thinking"].(string)
		if val == "" {
			// Check boolean form: true → "enabled"
			if b, ok := req.Params["extended_thinking"].(bool); ok {
				if b {
					val = "enabled"
				} else {
					val = "disabled"
				}
			}
		}
		if !strings.EqualFold(m.ExtendedThinking, val) {
			return false
		}
	}

	// SystemPromptContains check.
	if m.SystemPromptContains != "" {
		sys, _ := req.Params["system"].(string)
		if sys == "" {
			sys, _ = req.Params["system_prompt"].(string)
		}
		if !strings.Contains(strings.ToLower(sys), strings.ToLower(m.SystemPromptContains)) {
			return false
		}
	}

	// MaxTemperature check.
	if m.MaxTemperature > 0 {
		var temp float64
		switch v := req.Params["temperature"].(type) {
		case float64:
			temp = v
		case int:
			temp = float64(v)
		case string:
			f, err := strconv.ParseFloat(v, 64)
			if err == nil {
				temp = f
			}
		}
		if temp > m.MaxTemperature {
			return false
		}
	}

	// JSONMode check.
	if m.JSONMode != "" {
		rf, _ := req.Params["response_format"].(string)
		if m.JSONMode == "required" && rf != "json_object" && rf != "json" {
			return false
		}
		if m.JSONMode == "forbidden" && (rf == "json_object" || rf == "json") {
			return false
		}
	}

	// Grounding check.
	if m.Grounding != "" {
		val, _ := req.Params["grounding"].(string)
		if val == "" {
			if b, ok := req.Params["grounding"].(bool); ok {
				if b {
					val = "enabled"
				} else {
					val = "disabled"
				}
			}
		}
		if !strings.EqualFold(m.Grounding, val) {
			return false
		}
	}

	// SafetyThreshold check.
	if m.SafetyThreshold != "" {
		val, _ := req.Params["safety"].(string)
		if val == "" {
			val, _ = req.Params["safety_settings"].(string)
		}
		if !strings.EqualFold(m.SafetyThreshold, val) {
			return false
		}
	}

	// SharedStatus check (Drive).
	if m.SharedStatus != "" {
		val, _ := req.Params["shared_status"].(string)
		if !strings.EqualFold(m.SharedStatus, val) {
			return false
		}
	}

	// ContactGroup check (People).
	if m.ContactGroup != "" {
		val, _ := req.Params["contact_group"].(string)
		if val == "" {
			val, _ = req.Params["group"].(string)
		}
		if !strings.EqualFold(m.ContactGroup, val) {
			return false
		}
	}

	// AllowedFields check (People) — each requested field must be in allowed list.
	if m.AllowedFields != "" {
		requested, _ := req.Params["fields"].(string)
		if requested != "" {
			allowed := strings.Split(strings.ToLower(m.AllowedFields), ",")
			allowedSet := make(map[string]bool)
			for _, f := range allowed {
				allowedSet[strings.TrimSpace(f)] = true
			}
			for _, f := range strings.Split(strings.ToLower(requested), ",") {
				if !allowedSet[strings.TrimSpace(f)] {
					return false
				}
			}
		}
	}

	// RangePattern check (Sheets).
	if m.RangePattern != "" {
		val, _ := req.Params["range"].(string)
		if !globMatch(m.RangePattern, val) {
			return false
		}
	}

	// Tag check (EC2, format "key=value").
	if m.Tag != "" {
		val, _ := req.Params["tag"].(string)
		if val == "" {
			val, _ = req.Params["tags"].(string)
		}
		if !strings.EqualFold(m.Tag, val) {
			return false
		}
	}

	// SenderIdentity check (SES).
	if m.SenderIdentity != "" {
		val, _ := req.Params["sender"].(string)
		if val == "" {
			val, _ = req.Params["from"].(string)
		}
		if !strings.EqualFold(m.SenderIdentity, val) {
			return false
		}
	}

	// IndexName check (DynamoDB).
	if m.IndexName != "" {
		val, _ := req.Params["index_name"].(string)
		if val == "" {
			val, _ = req.Params["index"].(string)
		}
		if !strings.EqualFold(m.IndexName, val) {
			return false
		}
	}

	// Channel check (Slack, glob).
	if m.Channel != "" {
		val, _ := req.Params["channel"].(string)
		if !globMatch(m.Channel, val) {
			return false
		}
	}

	// SlackUser check (Slack, glob against params["user"]).
	if m.SlackUser != "" {
		val, _ := req.Params["user"].(string)
		if !globMatch(m.SlackUser, val) {
			return false
		}
	}

	// TextContains check (Slack post_message body, case-insensitive substring).
	if m.TextContains != "" {
		val, _ := req.Params["text"].(string)
		if !strings.Contains(strings.ToLower(val), strings.ToLower(m.TextContains)) {
			return false
		}
	}

	return true
}

// globMatch performs a case-insensitive glob match supporting prefix-* and *-suffix patterns.
func globMatch(pattern, value string) bool {
	pattern = strings.ToLower(pattern)
	value = strings.ToLower(value)
	if pattern == value {
		return true
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(value, pattern[1:]) {
		return true
	}
	if strings.HasSuffix(pattern, "*") && strings.HasPrefix(value, pattern[:len(pattern)-1]) {
		return true
	}
	return false
}

// getIntParam extracts an integer from a params map, handling float64, int, and string types.
// Guards against float64→int overflow by clamping to max int.
func getIntParam(params map[string]any, key string) int {
	switch v := params[key].(type) {
	case float64:
		if v > float64(math.MaxInt32) {
			return math.MaxInt32
		}
		if v < 0 {
			return 0
		}
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(v)
		return n
	}
	return 0
}

// getStringParam extracts a string from a params/metadata map. Handles the case
// where the value is a []string or []any (takes the first element) to prevent
// type mismatch bypasses where an agent sends an array instead of a string.
func getStringParamSafe(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	case []string:
		if len(v) > 0 {
			return v[0]
		}
	case []any:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

// getFloatParam extracts a float64 from a params map. Clamps negative values to 0.
func getFloatParam(params map[string]any, key string) float64 {
	switch v := params[key].(type) {
	case float64:
		if v < 0 {
			return 0
		}
		return v
	case int:
		return float64(v)
	case string:
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < 0 {
			return 0
		}
		return f
	}
	return 0
}

// applyRedactions computes redaction positions from precompiled patterns.
func (r *RulesEvaluator) applyRedactions(decision *PolicyDecision, ruleIdx int, req *PolicyRequest) {
	patterns, ok := r.redactCompiled[ruleIdx]
	if !ok {
		return
	}

	// Look for body in metadata or response.
	body, _ := req.Metadata["body"].(string)
	if body == "" {
		body, _ = req.Metadata["response"].(string)
	}
	if body == "" {
		return
	}

	for _, re := range patterns {
		for _, loc := range re.FindAllStringIndex(body, -1) {
			decision.Redactions = append(decision.Redactions, Redaction{
				Field: "body",
				Start: loc[0],
				End:   loc[1],
			})
		}
	}
}

