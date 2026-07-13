// Package notion implements a Sieve connector for the Notion REST API
// (https://developers.notion.com/reference/intro).
//
// Auth is an internal integration token sent as `Authorization: Bearer
// <token>`, plus the required `Notion-Version` header (see client.go). The
// notion_request escape hatch surfaces arbitrary endpoints through the same
// auth pipeline so agents can reach uncovered shapes without waiting for a new
// curated op; the curated ops cover the common read/write surface (search,
// pages, blocks, databases, users, comments).
//
// Modeled on the gitlab connector (REST {status,headers,body} envelope,
// httpguard SSRF guard, outbound_allowlist opt-in) and the linear connector
// (api-key SetupFields). Rich request bodies (page properties, block children,
// database query filters) are passed as JSON-string params — the same shape
// gitlab_request uses for its `body` param — because the connector ParamDef
// type system is scalar-only (string/int/bool/[]string).
package notion

import (
	"context"
	"fmt"
	"net/http"
	"reflect"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/httpguard"
)

// ConnectorType is the type string used in the registry, audit logs, MCP tool
// prefix (`notion_<op>` when a token has multiple connections), and policy
// match rules.
const ConnectorType = "notion"

// Connector implements connector.Connector for Notion.
type Connector struct {
	config     *Config
	httpClient *http.Client
}

// Factory returns a connector.Factory.
//
// Outbound SSRF guard: the underlying HTTP client is httpguard.Client, which
// enforces scheme + IP-range deny rules on every dial and redirect
// (DNS-rebinding-safe). Notion's production API base is fixed to
// api.notion.com so the per-connection outbound_allowlist is normally empty;
// tests pointing at a 127.0.0.1 httptest.Server supply 127.0.0.0/8 to permit
// the loopback dial. The allowlist is opt-in: an operator must explicitly add
// the CIDR before a base_url override can reach a private address.
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
			return nil, fmt.Errorf("notion: outbound_allowlist: %w", err)
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
// persisted Config key is declared here (the cmd/sieve architecture test
// enforces the invariant).
func Meta() connector.ConnectorMeta {
	return connector.ConnectorMeta{
		Type:        ConnectorType,
		Name:        "Notion",
		Description: "Read and write Notion pages, databases, blocks, and comments via an internal integration token.",
		Category:    "Productivity",
		Operations:  operations,
		// Notion text is nested rich_text; these are the human-readable string
		// keys the response filters may redact/exclude within.
		ContentFields: []connector.ContentField{
			{Key: "plain_text", Label: "Text"},
			{Key: "title", Label: "Title"},
		},
		SetupFields: []connector.Field{
			{
				Name:        "api_key",
				Label:       "Integration Token",
				Type:        "password",
				Required:    true,
				Editable:    true,
				Secret:      true,
				Placeholder: "ntn_... or secret_...",
				HelpText:    "Create an internal integration at notion.so/my-integrations, copy its token, and share the pages/databases you want reachable with the integration. Leave blank on edit to keep the stored value.",
			},
			{
				Name:        "base_url",
				Label:       "Base URL",
				Type:        "text",
				Required:    false,
				Editable:    true,
				Placeholder: defaultBaseURL,
				HelpText:    "Override for test endpoints. Leave blank for api.notion.com.",
			},
			{
				Name:        "outbound_allowlist",
				Label:       "Outbound allowlist (CIDRs)",
				Type:        "json_array",
				Required:    false,
				Editable:    true,
				Placeholder: `["127.0.0.0/8"]`,
				HelpText:    "JSON array of CIDR blocks the connector may dial in addition to public Internet ranges. Leave empty for production (api.notion.com). Required to point base_url at a private/loopback address.",
			},
			// Set automatically by the OAuth install flow; never entered by hand.
			// EditOnly + non-Editable ⇒ rendered on neither the create nor edit
			// form, but declared so the architecture test accepts them as
			// persisted config keys.
			{
				Name:     "workspace_id",
				Label:    "Workspace ID",
				Type:     "text",
				Required: false,
				Editable: false,
				EditOnly: true,
				HelpText: "Set by the OAuth install; identifies the Notion workspace this token belongs to.",
			},
			{
				Name:     "workspace_name",
				Label:    "Workspace name",
				Type:     "text",
				Required: false,
				Editable: false,
				EditOnly: true,
				HelpText: "Set by the OAuth install.",
			},
		},
	}
}

func (n *Connector) Type() string                         { return ConnectorType }
func (n *Connector) Operations() []connector.OperationDef { return operations }

// ConfigSchemaKeys implements connector.ConfigSchemaProvider: the persisted
// config keys are exactly the JSON-tagged fields of Config. outbound_allowlist
// is read from the raw map in Factory and declared as a SetupField, so it is
// covered by the architecture invariant without appearing here.
func (n *Connector) ConfigSchemaKeys() []string {
	return connector.ConfigKeysFromTags(reflect.TypeOf(Config{}))
}

// Validate confirms the token works via GET /v1/users/me — the cheapest
// authenticated Notion endpoint (returns the bot user for the integration).
//
// Semantics match gitlab/linear (post-#19 review): Validate returns
// ErrNeedsReauth ONLY when the token is rejected (401/403). Any other outcome
// — 5xx, transient network errors, unexpected shapes — leaves Validate
// succeeding so a transient outage doesn't block saving the connection. The
// error will repeat on first agent call and surface in the audit log there.
func (n *Connector) Validate(ctx context.Context) error {
	resp, err := n.doRequest(ctx, http.MethodGet, "/users/me", nil, nil)
	if err != nil {
		// Transport error: don't refuse the save.
		return nil
	}
	if resp.Status == http.StatusUnauthorized || resp.Status == http.StatusForbidden {
		return fmt.Errorf("notion: token rejected by %s (status %d): %w",
			n.config.BaseURL, resp.Status, connector.ErrNeedsReauth)
	}
	return nil
}

// Execute dispatches a Sieve operation name to the appropriate handler.
func (n *Connector) Execute(ctx context.Context, op string, params map[string]any) (any, error) {
	switch op {
	case "notion_request":
		return n.opRequest(ctx, params)
	case "notion_search":
		return n.opSearch(ctx, params)
	case "notion_get_page":
		return n.opGetPage(ctx, params)
	case "notion_create_page":
		return n.opCreatePage(ctx, params)
	case "notion_update_page":
		return n.opUpdatePage(ctx, params)
	case "notion_get_block_children":
		return n.opGetBlockChildren(ctx, params)
	case "notion_append_block_children":
		return n.opAppendBlockChildren(ctx, params)
	case "notion_query_database":
		return n.opQueryDatabase(ctx, params)
	case "notion_get_database":
		return n.opGetDatabase(ctx, params)
	case "notion_list_users":
		return n.opListUsers(ctx, params)
	case "notion_get_comments":
		return n.opGetComments(ctx, params)
	case "notion_create_comment":
		return n.opCreateComment(ctx, params)
	default:
		return nil, fmt.Errorf("notion: unknown operation %q", op)
	}
}

// --- param-extraction helpers (mirror gitlab/linear connectors) ---

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
		return "", fmt.Errorf("notion: param %q required", key)
	}
	return s, nil
}

// getIntPresent reports both the int value and whether the key was present.
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
