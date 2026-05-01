package slack

import (
	"context"

	"github.com/trilitech/Sieve/internal/connector"
)

// Connector is the per-connection Slack adapter. One instance per
// connections.Connection — owns a client (with the bound token) and a
// validated Config.
//
// Implements connector.Connector via Type/Operations/Execute/Validate
// (all four are required by the interface — see internal/connector).
//
// The factory + Meta + Field metadata that bind this struct into the
// connector.Registry land in the next commit (Task #6 — connector
// main + web handlers). For now this is the bare implementation
// surface the contract tests in this commit drive against.
type Connector struct {
	cfg    *Config
	client *client
}

// Type returns the connector.Connector identifier. Stable string used
// by the registry, audit logs, MCP tool prefix, and policy rules.
func (c *Connector) Type() string { return "slack" }

// Operations returns the curated operation set. See ops.go for the
// table; the slice is read-only so we hand out the same instance.
func (c *Connector) Operations() []connector.OperationDef { return operations }

// Execute dispatches one operation. Param shapes are documented in
// contracts/slack.md.
func (c *Connector) Execute(ctx context.Context, op string, params map[string]any) (any, error) {
	return c.execute(ctx, op, params)
}

// Validate confirms the bound token works. Used at connection-creation
// time (so a bad paste fails fast) and as the connector.Connector
// health check (so admins see a stale credential surface as
// reauth_required on first use, not silent failure).
func (c *Connector) Validate(ctx context.Context) error {
	return c.validate(ctx)
}
