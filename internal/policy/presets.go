package policy

import "fmt"

// --- Rule-based presets ---

func RulesPresetReadOnly() map[string]any {
	return map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails", "read_email", "read_email_raw", "read_thread", "list_labels", "get_attachment"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
		"scope":          "gmail",
	}
}

func RulesPresetDrafter() map[string]any {
	return map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email", "send_draft", "reply"}},
				"action": "approval_required",
				"reason": "Sending requires approval",
			},
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails", "read_email", "read_email_raw", "read_thread", "list_labels", "get_attachment", "create_draft", "update_draft"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
		"scope":          "gmail",
	}
}

func RulesPresetFullAssist() map[string]any {
	return map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email", "send_draft", "reply"}},
				"action": "approval_required",
				"reason": "Sending requires approval",
			},
		},
		"default_action": "allow",
		"scope":          "gmail",
	}
}

func RulesPresetTriage() map[string]any {
	return map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails", "read_email", "read_email_raw", "read_thread", "list_labels", "get_attachment", "add_label", "remove_label", "archive"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
		"scope":          "gmail",
	}
}

func RulesPresetGitHubReadOnly() map[string]any {
	return map[string]any{
		"rules": []any{
			map[string]any{
				"match": map[string]any{"operations": []any{
					"github_list_repos", "github_get_file", "github_list_issues",
					"github_list_prs", "github_get_pr", "github_search_code",
				}},
				"action": "allow",
			},
		},
		"default_action": "deny",
		"scope":          "github",
	}
}

// RulesPresetGitHubWithApproval mirrors the Gmail "drafter" pattern for
// GitHub: read ops pass through, write ops require human approval. Users who
// want repo-level allowlisting should copy this preset and add an
// `owner: "<org>/*"` matcher to each rule.
func RulesPresetGitHubWithApproval() map[string]any {
	return map[string]any{
		"rules": []any{
			map[string]any{
				"match": map[string]any{"operations": []any{
					"github_put_file", "github_create_issue", "github_comment_issue",
					"github_create_pr", "github_request",
				}},
				"action": "approval_required",
				"reason": "GitHub write operations require approval",
			},
			map[string]any{
				"match": map[string]any{"operations": []any{
					"github_list_repos", "github_get_file", "github_list_issues",
					"github_list_prs", "github_get_pr", "github_search_code",
				}},
				"action": "allow",
			},
		},
		"default_action": "deny",
		"scope":          "github",
	}
}

var rulesPresets = map[string]func() map[string]any{
	"read-only":             RulesPresetReadOnly,
	"drafter":               RulesPresetDrafter,
	"full-assist":           RulesPresetFullAssist,
	"triage":                RulesPresetTriage,
	"github-read-only":      RulesPresetGitHubReadOnly,
	"github-with-approval":  RulesPresetGitHubWithApproval,
}

// GetRulesPreset returns a rules-type preset by name.
func GetRulesPreset(name string) (map[string]any, error) {
	fn, ok := rulesPresets[name]
	if !ok {
		return nil, fmt.Errorf("unknown rules preset: %q", name)
	}
	return fn(), nil
}

// RulesPresetNames returns available rules preset names.
func RulesPresetNames() []string {
	names := make([]string, 0, len(rulesPresets))
	for name := range rulesPresets {
		names = append(names, name)
	}
	return names
}
