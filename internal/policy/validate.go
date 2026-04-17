package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/murbard/Sieve/internal/connector"
)

// matchFieldToParams maps each RuleMatch field name to the operation parameter
// name(s) it checks. Fields that check response metadata (not request params)
// are excluded — they're always valid because the connector populates them.
var matchFieldToParams = map[string][]string{
	"to":                     {"to"},
	"model":                  {"model"},
	"providers":              {"provider"},
	"path":                   {"path"},
	"body_contains":          {"body"},
	"max_tokens":             {"max_tokens"},
	"max_cost":               {"max_cost", "estimated_cost"},
	"instance_type":          {"instance_type", "InstanceType"},
	"region":                 {"region", "Region"},
	"bucket":                 {"bucket", "Bucket"},
	"key_prefix":             {"key", "Key"},
	"mime_type":              {"mime_type"},
	"owner":                  {"owner"},
	"calendar_id":            {"calendar_id"},
	"attendee":               {"attendee"},
	"spreadsheet_id":         {"spreadsheet_id"},
	"document_id":            {"document_id"},
	"title_contains":         {"title"},
	"max_count":              {"max_count", "count"},
	"ami":                    {"ami", "image_id"},
	"vpc":                    {"vpc_id", "subnet_id"},
	"ports":                  {"port"},
	"cidr":                   {"cidr"},
	"function_name":          {"function_name"},
	"recipient":              {"recipient", "to"},
	"table_name":             {"table_name", "table"},
	"index_name":             {"index_name", "index"},
	"flavor":                 {"flavor"},
	"max_vms":                {"count"},
	"shared_status":          {"shared_status"},
	"contact_group":          {"contact_group", "group"},
	"allowed_fields":         {"fields"},
	"range_pattern":          {"range"},
	"tag":                    {"tag", "tags"},
	"sender_identity":        {"sender", "from"},
	"extended_thinking":      {"extended_thinking"},
	"system_prompt_contains": {"system", "system_prompt"},
	"max_temperature":        {"temperature"},
	"json_mode":              {"response_format"},
	"grounding":              {"grounding"},
	"safety_threshold":       {"safety", "safety_settings"},
}

// Response-based fields are checked against connector output, not agent input.
// These are always valid regardless of operations.
var responseBasedFields = map[string]bool{
	"from":             true,
	"subject_contains": true,
	"content_contains": true,
	"labels":           true,
}

// ValidatePolicy checks a policy config against the available operations.
// Returns a list of validation errors. An empty list means the policy is valid.
func ValidatePolicy(config map[string]any, ops []connector.OperationDef) []string {
	data, err := json.Marshal(config)
	if err != nil {
		return []string{fmt.Sprintf("invalid config: %v", err)}
	}

	var rc RulesConfig
	if err := json.Unmarshal(data, &rc); err != nil {
		return []string{fmt.Sprintf("invalid rules config: %v", err)}
	}

	// Build lookup: operation name → set of param names.
	opParams := make(map[string]map[string]bool)
	for _, op := range ops {
		params := make(map[string]bool)
		for pName := range op.Params {
			params[pName] = true
		}
		opParams[op.Name] = params
	}

	// All valid operation names.
	validOps := make(map[string]bool)
	for _, op := range ops {
		validOps[op.Name] = true
	}

	var errors []string

	for i, rule := range rc.Rules {
		ruleNum := i + 1

		// Validate action.
		switch rule.Action {
		case "allow", "deny", "approval_required", "filter", "script":
			// ok
		default:
			errors = append(errors, fmt.Sprintf("rule %d: unknown action %q", ruleNum, rule.Action))
		}

		if rule.Match == nil {
			continue // catch-all rule, always valid
		}

		// Validate operation names exist.
		for _, opName := range rule.Match.Operations {
			if opName == "*" {
				continue
			}
			if !validOps[opName] {
				errors = append(errors, fmt.Sprintf("rule %d: unknown operation %q", ruleNum, opName))
			}
		}

		// If no operations specified, the rule matches all — all filters are potentially valid.
		if len(rule.Match.Operations) == 0 {
			continue
		}

		// For each match field that's set, check if at least one of the rule's
		// operations has the corresponding param.
		matchJSON, _ := json.Marshal(rule.Match)
		var matchMap map[string]any
		json.Unmarshal(matchJSON, &matchMap)

		for fieldName, paramNames := range matchFieldToParams {
			val, exists := matchMap[fieldName]
			if !exists {
				continue
			}
			// Check if the value is actually set (not zero/empty).
			if isEmpty(val) {
				continue
			}

			// Skip response-based fields — they don't depend on request params.
			if responseBasedFields[fieldName] {
				continue
			}

			// Check: does at least one operation in this rule have any of the param names?
			anyOpHasParam := false
			for _, opName := range rule.Match.Operations {
				if opName == "*" {
					anyOpHasParam = true
					break
				}
				params, ok := opParams[opName]
				if !ok {
					continue
				}
				for _, pName := range paramNames {
					if params[pName] {
						anyOpHasParam = true
						break
					}
				}
				if anyOpHasParam {
					break
				}
			}

			if !anyOpHasParam {
				// Build a helpful message listing which operations DO have this param.
				var validFor []string
				for _, op := range ops {
					for _, pName := range paramNames {
						if _, ok := op.Params[pName]; ok {
							validFor = append(validFor, op.Name)
							break
						}
					}
				}
				if len(validFor) > 0 {
					errors = append(errors, fmt.Sprintf(
						"rule %d: filter %q does not apply to %s — it is valid for: %s",
						ruleNum, fieldName,
						strings.Join(rule.Match.Operations, ", "),
						strings.Join(validFor, ", "),
					))
				} else {
					errors = append(errors, fmt.Sprintf(
						"rule %d: filter %q does not apply to any of the specified operations",
						ruleNum, fieldName,
					))
				}
			}
		}
	}

	return errors
}

func isEmpty(v any) bool {
	switch val := v.(type) {
	case string:
		return val == ""
	case []any:
		return len(val) == 0
	case []string:
		return len(val) == 0
	case float64:
		return val == 0
	case int:
		return val == 0
	case nil:
		return true
	}
	return false
}
