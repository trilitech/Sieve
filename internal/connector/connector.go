package connector

import (
	"context"
	"errors"
)

// ErrNeedsReauth signals that a connection's stored credentials cannot be
// used or refreshed and the human operator must re-authenticate (typically
// in the web UI). Connectors return this — wrapped with %w if they have
// upstream context — when they detect an unrecoverable token failure
// (e.g., OAuth invalid_grant: refresh token revoked, expired, or rotated
// out from under us). The API/MCP layers map errors.Is(err, ErrNeedsReauth)
// to a structured response that points the caller at the re-auth URL
// instead of bubbling a generic 500.
var ErrNeedsReauth = errors.New("connection needs re-authentication")

// ErrOperationNotEnabled signals that a connector exposes an operation in
// its catalog (so policies can bind against the name) but refuses to
// execute it in the current Sieve version. Connectors return this —
// wrapped with %w plus a connector-supplied reason string — from
// Execute. The API layer maps errors.Is(err, ErrOperationNotEnabled)
// to HTTP 501 Not Implemented; the MCP layer surfaces it as a tool
// error with the canonical "operation_not_enabled:" text prefix.
// Distinct from ErrNeedsReauth (403, credential-state problem) and from
// generic 5xx (something is broken). Today's only producer is Slack's
// search_messages (gated until user-token install ships).
var ErrOperationNotEnabled = errors.New("operation not enabled")

// Connector is the interface that all service connectors must implement.
type Connector interface {
	Type() string
	Operations() []OperationDef
	Execute(ctx context.Context, op string, params map[string]any) (any, error)
	Validate(ctx context.Context) error
}

// OperationDef describes a single operation a connector supports.
type OperationDef struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Params      map[string]ParamDef `json:"params"`
	ReadOnly    bool                `json:"read_only"`
}

// ParamDef describes a parameter for an operation.
type ParamDef struct {
	Type        string `json:"type"` // "string", "int", "bool", "[]string"
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// Factory creates a connector instance from stored credentials.
type Factory func(config map[string]any) (Connector, error)

// ConnectorMeta describes a connector type for the UI catalog.
type ConnectorMeta struct {
	Type        string   `json:"type"`         // e.g. "google", "http_proxy"
	Name        string   `json:"name"`         // e.g. "Gmail"
	Description string   `json:"description"`  // e.g. "Read, draft, and send email"
	Category    string   `json:"category"`     // e.g. "Google", "AWS", "Communication"
	SetupFields []Field  `json:"setup_fields"` // fields needed to create a connection
}

// Field describes a form field for connection setup.
type Field struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Type        string `json:"type"`  // "text", "password", "oauth", "select"
	Required    bool   `json:"required"`
	Placeholder string `json:"placeholder,omitempty"`
	HelpText    string `json:"help_text,omitempty"`
}

// Registry holds registered connector factories and metadata.
type Registry struct {
	factories map[string]Factory
	metas     map[string]ConnectorMeta
}

func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]Factory),
		metas:     make(map[string]ConnectorMeta),
	}
}

// Register adds a connector factory with metadata.
func (r *Registry) Register(meta ConnectorMeta, factory Factory) {
	r.factories[meta.Type] = factory
	r.metas[meta.Type] = meta
}

// Create creates a connector instance from stored config.
func (r *Registry) Create(connectorType string, config map[string]any) (Connector, error) {
	factory, ok := r.factories[connectorType]
	if !ok {
		return nil, &ErrUnknownConnector{Type: connectorType}
	}
	return factory(config)
}

// Types returns all registered connector type names.
func (r *Registry) Types() []string {
	types := make([]string, 0, len(r.factories))
	for t := range r.factories {
		types = append(types, t)
	}
	return types
}

// HasType checks if a connector type is registered.
func (r *Registry) HasType(connectorType string) bool {
	_, ok := r.factories[connectorType]
	return ok
}

// Meta returns metadata for a connector type.
func (r *Registry) Meta(connectorType string) (ConnectorMeta, bool) {
	m, ok := r.metas[connectorType]
	return m, ok
}

// Catalog returns all connector metadata grouped by category.
func (r *Registry) Catalog() map[string][]ConnectorMeta {
	catalog := make(map[string][]ConnectorMeta)
	for _, m := range r.metas {
		catalog[m.Category] = append(catalog[m.Category], m)
	}
	return catalog
}

// AllMetas returns all connector metadata as a flat list.
func (r *Registry) AllMetas() []ConnectorMeta {
	metas := make([]ConnectorMeta, 0, len(r.metas))
	for _, m := range r.metas {
		metas = append(metas, m)
	}
	return metas
}

type ErrUnknownConnector struct {
	Type string
}

func (e *ErrUnknownConnector) Error() string {
	return "unknown connector type: " + e.Type
}
