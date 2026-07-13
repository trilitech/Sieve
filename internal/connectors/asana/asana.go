// Package asana implements a Sieve connector for the Asana REST API
// (https://developers.asana.com/reference/rest-api-reference).
//
// Auth is a Bearer token — a Personal Access Token (app.asana.com → Developer
// console) or an OAuth access token; both are sent as `Authorization: Bearer
// <token>`. The asana_request escape hatch surfaces arbitrary endpoints through
// the same auth pipeline; curated ops cover the common read/write surface
// (workspaces, projects, tasks, stories/comments, users).
//
// Modeled on the notion/gitlab connectors (REST {status,headers,body} envelope,
// httpguard SSRF guard, outbound_allowlist opt-in). Asana wraps every request
// body and response under a "data" key — write ops build {"data": {...}} for
// the caller; list responses come back as {data:[...], next_page:{...}} which
// the response filters recognize via the generic array-of-objects list walk.
package asana

import (
	"context"
	"fmt"
	"net/http"
	"reflect"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/httpguard"
)

// ConnectorType is the type string used in the registry, audit logs, MCP tool
// prefix (`asana_<op>` when a token has multiple connections), and policy rules.
const ConnectorType = "asana"

// Connector implements connector.Connector for Asana.
type Connector struct {
	config     *Config
	httpClient *http.Client
}

// Factory returns a connector.Factory.
//
// Outbound SSRF guard: the underlying HTTP client is httpguard.Client, which
// enforces scheme + IP-range deny rules on every dial and redirect. Asana's
// production API base is fixed to app.asana.com so the per-connection
// outbound_allowlist is normally empty; tests pointing at a 127.0.0.1
// httptest.Server supply 127.0.0.0/8. The allowlist is opt-in.
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
			return nil, fmt.Errorf("asana: outbound_allowlist: %w", err)
		}
		return &Connector{
			config:     cfg,
			httpClient: newHTTPClient(allowlist),
		}, nil
	}
}

// Meta returns connector metadata for registration.
func Meta() connector.ConnectorMeta {
	return connector.ConnectorMeta{
		Type:        ConnectorType,
		Name:        "Asana",
		Description: "Read and write Asana tasks, projects, and comments via a personal access token.",
		Category:    "Project Management",
		Operations:  operations,
		// Task name/notes and story text are the filterable content; gids/dates
		// are metadata.
		ContentFields: []connector.ContentField{
			{Key: "name", Label: "Name"},
			{Key: "notes", Label: "Notes"},
			{Key: "text", Label: "Comment text"},
		},
		SetupFields: []connector.Field{
			{
				Name:        "api_key",
				Label:       "Personal Access Token",
				Type:        "password",
				Required:    true,
				Editable:    true,
				Secret:      true,
				Placeholder: "1/1234567890:abcdef…",
				HelpText:    "Create one at app.asana.com/0/my-apps (Developer console → Personal access tokens). Leave blank on edit to keep the stored value.",
			},
			{
				Name:        "base_url",
				Label:       "Base URL",
				Type:        "text",
				Required:    false,
				Editable:    true,
				Placeholder: defaultBaseURL,
				HelpText:    "Override for test endpoints. Leave blank for app.asana.com.",
			},
			{
				Name:        "outbound_allowlist",
				Label:       "Outbound allowlist (CIDRs)",
				Type:        "json_array",
				Required:    false,
				Editable:    true,
				Placeholder: `["127.0.0.0/8"]`,
				HelpText:    "JSON array of CIDR blocks the connector may dial in addition to public Internet ranges. Leave empty for production (app.asana.com). Required to point base_url at a private/loopback address.",
			},
		},
	}
}

func (a *Connector) Type() string                         { return ConnectorType }
func (a *Connector) Operations() []connector.OperationDef { return operations }

// ConfigSchemaKeys implements connector.ConfigSchemaProvider: the persisted
// config keys are the JSON-tagged fields of Config. outbound_allowlist is read
// from the raw map in Factory and declared as a SetupField, so it is covered
// by the architecture invariant without appearing here.
func (a *Connector) ConfigSchemaKeys() []string {
	return connector.ConfigKeysFromTags(reflect.TypeOf(Config{}))
}

// Validate confirms the token works via GET /users/me — the cheapest
// authenticated Asana endpoint.
//
// Semantics match gitlab/notion (post-#19 review): Validate returns
// ErrNeedsReauth ONLY when the token is rejected (401/403). Any other outcome —
// 5xx, transient network errors, unexpected shapes — leaves Validate succeeding
// so a transient outage doesn't block saving the connection.
func (a *Connector) Validate(ctx context.Context) error {
	resp, err := a.doRequest(ctx, http.MethodGet, "/users/me", nil, nil)
	if err != nil {
		return nil
	}
	if resp.Status == http.StatusUnauthorized || resp.Status == http.StatusForbidden {
		return fmt.Errorf("asana: token rejected by %s (status %d): %w",
			a.config.BaseURL, resp.Status, connector.ErrNeedsReauth)
	}
	return nil
}

// Execute dispatches a Sieve operation name to the appropriate handler.
func (a *Connector) Execute(ctx context.Context, op string, params map[string]any) (any, error) {
	switch op {
	case "asana_request":
		return a.opRequest(ctx, params)
	case "asana_list_workspaces":
		return a.opListWorkspaces(ctx, params)
	case "asana_list_projects":
		return a.opListProjects(ctx, params)
	case "asana_get_project":
		return a.opGetProject(ctx, params)
	case "asana_list_tasks":
		return a.opListTasks(ctx, params)
	case "asana_get_task":
		return a.opGetTask(ctx, params)
	case "asana_create_task":
		return a.opCreateTask(ctx, params)
	case "asana_update_task":
		return a.opUpdateTask(ctx, params)
	case "asana_list_stories":
		return a.opListStories(ctx, params)
	case "asana_create_story":
		return a.opCreateStory(ctx, params)
	case "asana_list_users":
		return a.opListUsers(ctx, params)
	default:
		return nil, fmt.Errorf("asana: unknown operation %q", op)
	}
}

// --- param-extraction helpers (mirror gitlab/notion connectors) ---

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
		return "", fmt.Errorf("asana: param %q required", key)
	}
	return s, nil
}

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
