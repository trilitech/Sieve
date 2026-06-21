// Package linear implements a Sieve connector for the Linear GraphQL API
// (https://developers.linear.app/docs/graphql/working-with-the-graphql-api).
//
// Linear's API is GraphQL-only — there are no REST endpoints. Every
// curated operation in ops.go is a fixed GraphQL query/mutation; the
// linear_request escape hatch surfaces arbitrary GraphQL through the
// same auth pipeline so agents can reach uncovered shapes without
// waiting for a new curated op.
//
// v1 supports Personal API Keys (Authorization: <key>); OAuth (with the
// `Bearer` prefix) is a deliberate omission. The cleanest add path is a
// `token_type` field on Config that selects between the two header
// shapes at request time — see client.go::doGraphQL.
//
// Issues, projects, and comments are identified by Linear IDs (UUIDs)
// returned by the list operations. Issue identifier strings like
// "ENG-123" are also accepted by Linear's `issue(id: ...)` query — the
// curated ops pass the param through verbatim.
package linear

import (
	"context"
	"fmt"
	"net/http"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/httpguard"
)

// ConnectorType is the type string used in the registry, audit logs,
// MCP tool prefix (`linear_<op>` when a token has multiple connections),
// and policy match rules.
const ConnectorType = "linear"

// Connector implements connector.Connector for Linear.
type Connector struct {
	config     *Config
	httpClient *http.Client
}

// Factory returns a connector.Factory.
//
// Outbound SSRF guard: the underlying HTTP client is httpguard.Client,
// which enforces scheme + IP-range deny rules on every dial and
// redirect (DNS-rebinding-safe). Linear's production API base is fixed
// to api.linear.app so the per-connection outbound_allowlist is
// normally empty; tests pointing at a 127.0.0.1 httptest.Server supply
// 127.0.0.0/8 in outbound_allowlist to permit the loopback dial.
//
// Without this guard, a base_url override pointing at an internal
// address would let the connector reach intranet services through a
// stored API key (the SSRF surface). The allowlist is opt-in: an
// operator must explicitly add the CIDR.
func Factory() connector.Factory {
	return func(raw map[string]any) (connector.Connector, error) {
		cfg, err := parseConfig(raw)
		if err != nil {
			return nil, err
		}
		allowlistStrings, _ := raw["outbound_allowlist"].([]string)
		if allowlistStrings == nil {
			if rs, ok := raw["outbound_allowlist"].([]any); ok {
				for _, v := range rs {
					if s, ok := v.(string); ok {
						allowlistStrings = append(allowlistStrings, s)
					}
				}
			}
		}
		allowlist, err := httpguard.ParseCIDRs(allowlistStrings)
		if err != nil {
			return nil, fmt.Errorf("linear: outbound_allowlist: %w", err)
		}
		return &Connector{
			config:     cfg,
			httpClient: newHTTPClient(allowlist),
		}, nil
	}
}

// Meta returns connector metadata for registration.
//
// SetupFields drive the generic data-driven create + edit forms. Every
// persisted Config key is declared here — adding a Config field without
// a matching SetupField is the bug class PR #31 closes (architecture
// test in cmd/sieve).
func Meta() connector.ConnectorMeta {
	return connector.ConnectorMeta{
		Type:        ConnectorType,
		Name:        "Linear",
		Description: "Read and write Linear issues, comments, and teams via personal API key.",
		Category:    "Project Management",
		Operations:  operations,
		// Issue/comment text is the filterable content; ids/states are metadata.
		ContentFields: []connector.ContentField{
			{Key: "title", Label: "Title"},
			{Key: "description", Label: "Description"},
			{Key: "body", Label: "Comment body"},
		},
		SetupFields: []connector.Field{
			{
				Name:        "api_key",
				Label:       "Personal API Key",
				Type:        "password",
				Required:    true,
				Editable:    true,
				Secret:      true,
				Placeholder: "lin_api_...",
				HelpText:    "Create one under Linear Settings → API → Personal API keys. Leave blank on edit to keep the stored value.",
			},
			{
				Name:        "base_url",
				Label:       "Base URL",
				Type:        "text",
				Required:    false,
				Editable:    true,
				Placeholder: defaultBaseURL,
				HelpText:    "Override for test endpoints. Leave blank for api.linear.app.",
			},
			{
				Name:        "outbound_allowlist",
				Label:       "Outbound allowlist (CIDRs)",
				Type:        "json",
				Required:    false,
				Editable:    true,
				Placeholder: `["127.0.0.0/8"]`,
				HelpText:    "JSON array of CIDR blocks the connector is allowed to dial in addition to public Internet ranges. Leave empty for production (api.linear.app). Required to point base_url at a private/loopback address.",
			},
		},
	}
}

func (l *Connector) Type() string                         { return ConnectorType }
func (l *Connector) Operations() []connector.OperationDef { return operations }

// Validate confirms the API key works by querying `viewer { id }` —
// the cheapest authenticated GraphQL query Linear exposes.
//
// Semantics match gitlab/anthropic (post-#19 review): Validate returns
// ErrNeedsReauth ONLY when the key is rejected (401/403, or a GraphQL
// AUTHENTICATION_ERROR extension). Any other outcome — 5xx, transient
// network errors, unexpected shapes — leaves Validate succeeding so a
// transient outage doesn't block saving the connection. The error will
// repeat on first agent call and surface in the audit log there.
func (l *Connector) Validate(ctx context.Context) error {
	resp, err := l.doGraphQL(ctx, `query { viewer { id } }`, nil)
	if err != nil {
		// Transport error: don't refuse the save.
		return nil
	}
	if resp.Status == http.StatusUnauthorized || resp.Status == http.StatusForbidden {
		return fmt.Errorf("linear: api_key rejected by %s (status %d): %w",
			l.config.BaseURL, resp.Status, connector.ErrNeedsReauth)
	}
	// Linear also signals auth failures via GraphQL errors with
	// extensions.type = "authentication error" or "forbidden" (HTTP 200).
	// The extension key is `type` (NOT `code`) and the value is a
	// lowercase string with spaces — confirmed by Linear's own SDK
	// (linear/linear: packages/sdk/src/error.ts's errorMap). Catch
	// these shapes so the operator sees the right error at save-time
	// rather than during the first agent call.
	for _, gerr := range resp.Errors {
		t, _ := gerr.Extensions["type"].(string)
		if t == "authentication error" || t == "forbidden" {
			return fmt.Errorf("linear: api_key rejected: %s: %w",
				gerr.Message, connector.ErrNeedsReauth)
		}
	}
	return nil
}

// Execute dispatches a Sieve operation name to the appropriate handler.
func (l *Connector) Execute(ctx context.Context, op string, params map[string]any) (any, error) {
	switch op {
	case "linear_request":
		return l.opRequest(ctx, params)
	case "linear_list_issues":
		return l.opListIssues(ctx, params)
	case "linear_get_issue":
		return l.opGetIssue(ctx, params)
	case "linear_create_issue":
		return l.opCreateIssue(ctx, params)
	case "linear_update_issue":
		return l.opUpdateIssue(ctx, params)
	case "linear_list_teams":
		return l.opListTeams(ctx, params)
	case "linear_list_users":
		return l.opListUsers(ctx, params)
	case "linear_list_workflow_states":
		return l.opListWorkflowStates(ctx, params)
	case "linear_list_comments":
		return l.opListComments(ctx, params)
	case "linear_create_comment":
		return l.opCreateComment(ctx, params)
	default:
		return nil, fmt.Errorf("linear: unknown operation %q", op)
	}
}

// --- param-extraction helpers (mirror gitlab connector pattern) ---

func getString(p map[string]any, key string) string {
	if v, ok := p[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func requireString(p map[string]any, key string) (string, error) {
	s := getString(p, key)
	if s == "" {
		return "", fmt.Errorf("linear: param %q required", key)
	}
	return s, nil
}

func getInt(p map[string]any, key string) int {
	n, _ := getIntPresent(p, key)
	return n
}

// getIntPresent reports both the int value and whether the key was
// present on the params map. Required for fields like Linear's
// `priority` where 0 is a valid value ("no priority"): a plain
// getInt-and-check-zero loses the explicit-zero case.
func getIntPresent(p map[string]any, key string) (int, bool) {
	v, ok := p[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

func getMap(p map[string]any, key string) map[string]any {
	if v, ok := p[key]; ok {
		if m, ok := v.(map[string]any); ok {
			return m
		}
	}
	return nil
}
