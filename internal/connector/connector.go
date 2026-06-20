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

	// --- IAM taxonomy (internal/iam) ---

	// Action overrides the Cedar action leaf id. Empty ⇒ the taxonomy derives
	// "<connectorType>/<Name>". Rarely set; the derived form is canonical.
	Action string `json:"-"`

	// ResourceType is the SINGLE Cedar entity type this op targets (review M1:
	// one type per op, never "finest available"). Empty ⇒ the op targets the
	// connection itself (Sieve::Connection). Used by schema appliesTo and as the
	// invariant the Resource mapper must satisfy.
	ResourceType string `json:"-"`

	// Resource maps a request to the concrete resource entity (leaf + any
	// object-level ancestors above the connection), e.g. a GitHub repo with its
	// owner. Nil ⇒ the resource is the connection. The leaf's Type MUST equal
	// ResourceType (enforced by a taxonomy test). Pure; no I/O.
	Resource ResourceMapper `json:"-"`
}

// ResourceRef is one entity in a request's resource chain, in IAM terms.
type ResourceRef struct {
	Type string // namespaced entity type, e.g. "Sieve::Github::Repo"
	ID   string // entity id, e.g. "<conn>/<owner>/<repo>"
}

// ResourceMapper derives the resource a request targets: the leaf entity plus
// any object-level ancestors ABOVE the connection (leaf-first). The taxonomy
// appends the connection and connector. An empty/nil result ⇒ the connection is
// the resource. Example (GitHub get-file): returns [Repo, Owner].
type ResourceMapper func(connID string, params map[string]any) []ResourceRef

// ResourceType declares a connector's object entity type for schema generation:
// its namespaced name and the type it is `in` (its parent). Parent "" ⇒ the
// parent is Sieve::Connection.
type ResourceType struct {
	Name   string // "Sieve::Github::Repo"
	Parent string // "Sieve::Github::Owner"; "" ⇒ Sieve::Connection
}

// ContextEnricher optionally adds derived context attributes to a request
// (recipient domains for sends, http method for escape hatches, estimated cost).
// Declared here; invoked by the PEP/PIP in PR-D. Pure; no I/O.
type ContextEnricher interface {
	EnrichContext(op string, params map[string]any) map[string]any
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
	Type        string  `json:"type"`         // e.g. "google", "http_proxy"
	Name        string  `json:"name"`         // e.g. "Gmail"
	Description string  `json:"description"`  // e.g. "Read, draft, and send email"
	Category    string  `json:"category"`     // e.g. "Google", "AWS", "Communication"
	SetupFields []Field `json:"setup_fields"` // fields needed to create a connection

	// Operations is the STATIC op catalog for IAM taxonomy + schema generation
	// (the policy-bindable surface). For connectors whose runtime Operations()
	// is dynamic (mcp_proxy discovers tools), this is the fixed taxonomy op(s)
	// policies bind to — not the discovered set. Empty is allowed (the schema
	// generator skips a connector with no declared ops).
	Operations []OperationDef `json:"-"`

	// ResourceTypes declares this connector's object entity types for schema
	// generation (their names + parent edges). The connection/connector
	// container types are generic and added by the generator.
	ResourceTypes []ResourceType `json:"-"`
}

// Field describes a form field for connection setup and editing.
//
// SetupFields is the single source of truth for the generic connection
// forms: the create flow renders/parses every non-EditOnly field, the
// edit page renders/parses every Editable field. Adding a field here is
// the ONLY step needed to surface it in both forms — the web layer has
// no per-connector form code. (Bespoke flows — Google OAuth, Slack
// install — bypass this mechanism entirely.)
type Field struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Type        string `json:"type"` // "text", "password", "oauth", "select", "checkbox", "textarea", "number", "json"
	Required    bool   `json:"required"`
	Placeholder string `json:"placeholder,omitempty"`
	HelpText    string `json:"help_text,omitempty"`

	// Editable fields appear on the connection-edit page and may be
	// changed after creation. Fields without it are create-time-only
	// (shown on the create form, frozen thereafter).
	Editable bool `json:"editable,omitempty"`
	// EditOnly marks operational settings with no meaning at creation
	// time (response-size caps, scrub toggles). They render only on the
	// edit page. EditOnly fields are never Required at create.
	EditOnly bool `json:"edit_only,omitempty"`
	// Secret values (API keys, tokens) are never echoed back into the
	// edit form. An empty submitted value on edit means "keep stored".
	Secret bool `json:"secret,omitempty"`
	// Default is the value assumed when the stored config has no entry.
	// Used by checkbox fields ("true"/"false") to distinguish "unset,
	// use default" from "explicitly off".
	Default string `json:"default,omitempty"`
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
