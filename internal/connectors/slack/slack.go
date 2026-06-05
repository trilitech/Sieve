package slack

import (
	"context"
	"fmt"

	"github.com/trilitech/Sieve/internal/connector"
)

// ConnectorType is the stable string used by the registry, audit logs,
// MCP tool prefix (`slack_<op>` when the token has multiple
// connections), and policy match rules.
const ConnectorType = "slack"

// Connector is the per-connection Slack adapter. One instance per
// connections.Connection — owns a client (with the bound token) and a
// validated Config.
//
// Implements connector.Connector via Type/Operations/Execute/Validate.
type Connector struct {
	cfg    *Config
	client *client
}

// Type returns the connector identifier.
func (c *Connector) Type() string { return ConnectorType }

// Operations returns the curated operation set. The slice is
// read-only so we hand out the same instance every call.
func (c *Connector) Operations() []connector.OperationDef { return operations }

// Execute dispatches one operation. Param shapes are documented in
// contracts/slack.md.
func (c *Connector) Execute(ctx context.Context, op string, params map[string]any) (any, error) {
	return c.execute(ctx, op, params)
}

// Validate calls Slack auth.test. Used at connection-creation time
// (so a bad pasted token is rejected fast) and as the periodic
// health check the connector.Connector interface requires.
func (c *Connector) Validate(ctx context.Context) error {
	return c.validate(ctx)
}

// Factory returns a connector.Factory bound to slack.com. The factory
// pulls two optional injections from the config map:
//
//   - "_base_url"          (string)  — overrides the production
//     endpoint for tests and the e2e testserver. Production configs
//     omit this and fall back to https://slack.com.
//   - "_on_terminal_auth"  (func())  — invoked when the classifier
//     flags an upstream response as a terminal-auth failure (token
//     revoked, account deactivated, etc.). The connections.Service
//     wires this to SetStatus(id, "reauth_required") via the same
//     indirection Gmail uses for `_on_token_refresh`. Nil-safe.
//
// Bot tokens (KindOAuth/KindToken) are classic non-rotating credentials, so
// their token source is static. KindUserOAuth installs against a Slack app
// with Token Rotation enabled carry a refresh_token; for those, buildTokenSource
// returns a refreshing source that renews the user token and persists the
// rotated pair via the `_on_token_refresh` / `_on_token_refresh_failure`
// callbacks the connections service injects (the same seam Gmail uses).
func Factory() connector.Factory {
	return func(raw map[string]any) (connector.Connector, error) {
		cfg, err := parseConfig(raw)
		if err != nil {
			return nil, err
		}
		if err := cfg.validate(); err != nil {
			return nil, fmt.Errorf("slack: invalid config: %w", err)
		}
		baseURL, _ := raw["_base_url"].(string)
		if baseURL == "" {
			baseURL = defaultBaseURL
		}
		ts, err := buildTokenSource(cfg, baseURL, raw)
		if err != nil {
			return nil, err
		}
		onTerminalAuth, _ := raw["_on_terminal_auth"].(func())
		cli, err := newClient(ts, baseURL, onTerminalAuth)
		if err != nil {
			return nil, err
		}
		return &Connector{cfg: cfg, client: cli}, nil
	}
}

// Meta returns connector metadata for registration. SetupFields drive
// the admin UI's "Add connection" form for the direct-token path; the
// OAuth path is rendered separately by the connection picker (see
// internal/web/templates/connections.html and the per-service
// handlers).
func Meta() connector.ConnectorMeta {
	return connector.ConnectorMeta{
		Type:        ConnectorType,
		Name:        "Slack",
		Description: "Read channels, search messages, post replies via OAuth or pasted bot token.",
		Category:    "Communication",
		SetupFields: []connector.Field{
			{
				Name:        "bot_token",
				Label:       "Bot token (xoxb-…)",
				Type:        "password",
				Required:    true,
				Placeholder: "xoxb-…",
				HelpText:    "Find under your Slack app's OAuth & Permissions page after install.",
			},
		},
	}
}
