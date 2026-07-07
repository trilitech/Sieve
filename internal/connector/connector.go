package connector

import (
	"context"
	"errors"
	"reflect"
	"strings"
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
// execute it for the current connection's configuration. Connectors
// return this — wrapped with %w plus a connector-supplied reason string —
// from Execute. The API layer maps errors.Is(err, ErrOperationNotEnabled)
// to HTTP 501 Not Implemented; the MCP layer surfaces it as a tool
// error with the canonical "operation_not_enabled:" text prefix.
// Distinct from ErrNeedsReauth (403, credential-state problem) and from
// generic 5xx (something is broken). Today's only producer is Slack's
// search_messages: it runs for real on user-token connections
// (auth_kind=user_token) and returns this sentinel on bot-token
// connections, since Slack's search.messages API only accepts user
// tokens. The op stays in the catalog regardless so policies that
// mention search_messages keep binding either kind.
var ErrOperationNotEnabled = errors.New("operation not enabled")

// Connector is the interface that all service connectors must implement.
type Connector interface {
	Type() string
	Operations() []OperationDef
	Execute(ctx context.Context, op string, params map[string]any) (any, error)
	Validate(ctx context.Context) error
}

// EditConfigNormalizer lets a connector migrate or normalize a stored
// config map before the generic edit page projects fields from it.
// Used to handle legacy aliases (e.g. mcp_proxy's target_url → url) so
// older rows are editable without forcing the operator to re-type a
// value that's already stored. Called both at edit-page render time AND
// before UpdateConfig writes the saved form back, so the normalized
// shape eventually lands in the persisted config.
//
// Implementations should mutate-and-return the input map. The normalize
// step MUST be idempotent — running it on an already-normalized config
// must be a no-op.
type EditConfigNormalizer interface {
	NormalizeForEdit(cfg map[string]any) map[string]any
}

// ConfigSchemaProvider exposes the JSON keys a connector's persisted Config
// can carry. The architecture test in cmd/sieve/registry_arch_test.go uses
// this to verify ConnectorMeta.SetupFields covers the entire persisted
// shape — no connector may write a config key its Meta doesn't declare,
// regardless of whether the connector ships a bespoke create flow (OAuth,
// App install) or relies on the generic data-driven form.
//
// Connectors with a typed `type Config struct` typically implement this by
// returning ConfigKeysFromTags(reflect.TypeOf(Config{})). Connectors that
// persist a free-form map (httpproxy, mcpproxy) don't need to implement it
// — their persisted keys are guaranteed by construction to come from
// SetupFields-driven form parsing.
type ConfigSchemaProvider interface {
	ConfigSchemaKeys() []string
}

// ConfigKeysFromTags returns the JSON tag names of a struct type's fields.
// Untagged fields, anonymous embeds, and `-` tags are skipped. The tag's
// `,omitempty` (and similar) suffixes are stripped. Used by typed-Config
// connectors to implement ConfigSchemaProvider via reflection rather than
// maintaining a parallel string list (which would itself drift).
//
// Panics if t is not a struct — call sites are static
// reflect.TypeOf(Config{}) in package init / method bodies, so a wrong
// type means a programming error, not a runtime condition.
func ConfigKeysFromTags(t reflect.Type) []string {
	if t.Kind() != reflect.Struct {
		panic("connector.ConfigKeysFromTags: expected struct, got " + t.Kind().String())
	}
	keys := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		// Strip ",omitempty" and similar comma-separated suffixes.
		if c := strings.IndexByte(tag, ','); c >= 0 {
			tag = tag[:c]
		}
		if tag == "" {
			continue
		}
		keys = append(keys, tag)
	}
	return keys
}

// OperationDef describes a single operation a connector supports.
type OperationDef struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Params      map[string]ParamDef `json:"params"`
	ReadOnly    bool                `json:"read_only"`

	// Disabled marks an operation that exists in the contract but is NOT usable
	// in this build (e.g. Slack search_messages needs a user-token install). The
	// rule/guardrail builders render it greyed-out and unselectable so an operator
	// can't scope a rule to an op that will only ever 501 at runtime.
	// DisabledReason is the short operator-facing explanation.
	Disabled       bool   `json:"disabled,omitempty"`
	DisabledReason string `json:"disabled_reason,omitempty"`

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

// RuleScope declares a connector-specific resource the admin rule-builder can
// scope a rule to (e.g. a GitHub owner or repo). The builder constructs the
// Cedar entity id from the selected connection id + the user-entered field
// values via IDFormat — "{conn}" plus one "{<field.Key>}" per Field — and emits
// `resource in <EntityType>::"<id>"`. IDFormat MUST match the connector's
// runtime ResourceMapper so a scoped rule and a live request agree.
type RuleScope struct {
	Key        string       // form key
	Label      string       // UI label, e.g. "Repository"
	EntityType string       // namespaced entity type, e.g. "Sieve::Github::Repo"
	Fields     []ScopeField // inputs needed to build the id
	IDFormat   string       // e.g. "{conn}/{owner}/{repo}"
	Help       string
}

// ScopeField is one text input contributing to a RuleScope entity id.
type ScopeField struct {
	Key         string // substituted as {Key} in RuleScope.IDFormat
	Label       string
	Placeholder string
}

// RuleCondition declares a connector-specific predicate the rule-builder can add
// to a rule. The builder turns (operator, value) into a Cedar boolean over
// CtxPath and ANDs it into the rule's `when` clause. Kinds:
//   - "number":           CtxPath <op> <value>           (op: <=,<,>=,>,==)
//   - "string":           CtxPath == "<value>"
//   - "one_of":           ["<v1>","<v2>"].contains(CtxPath)       (scalar in a set
//     — e.g. allow only listed models)
//   - "domain_allowlist": ["<v1>","<v2>"].containsAll(CtxPath)  (every actual
//     value must be in the allowed set — e.g. send only to listed domains)
//   - "bool":             CtxPath == true|false                  (a flag param)
//
// Ops restricts the condition to specific operation NAMES (empty ⇒ every op). The
// rule-builder only OFFERS a condition when one of its ops is in the selected op
// scope, and the compiler guards it so it binds ONLY those ops — so e.g. a
// recipient_count cap scoped to send ops does not fail-close reads on an
// all-operations rule.
type RuleCondition struct {
	Key     string // form key
	Label   string
	Help    string
	Kind    string   // "number" | "string" | "one_of" | "domain_allowlist" | "bool"
	CtxPath string   // Cedar path, e.g. "context.param.amount", "context.recipient_domains"
	Ops     []string // operation names this condition applies to; empty ⇒ all ops
}

// ContentField names a response text field that is safe/intended for content
// filtering (redact/exclude). Key is the JSON field name as it appears in the
// connector's response (e.g. "body", "subject"); Label is the operator-facing
// name shown as a checkbox in the filter UI.
type ContentField struct {
	Key   string
	Label string
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

	// RuleScopes / RuleConditions drive the admin rule-builder's
	// connector-tailored controls (resource scoping + conditions). Empty ⇒ the
	// builder offers only operation + connection scoping for this connector.
	RuleScopes     []RuleScope     `json:"-"`
	RuleConditions []RuleCondition `json:"-"`

	// ContentFields declares the response's text fields safe/intended for content
	// filtering (redact/exclude) — e.g. an email's subject + body, NOT its id,
	// labels, or base64 attachment data. Response filters apply ONLY within these
	// fields' string values (matched by key name, anywhere in the response), so a
	// 16-digit run inside a base64 MIME part is never redacted and metadata is
	// never dropped. Empty ⇒ filters fall back to whole-response matching (e.g.
	// the http_proxy auth-value scrub, which must catch the secret anywhere).
	ContentFields []ContentField `json:"-"`

	// EnrichContext optionally derives extra request-context attributes (e.g.
	// recipient_domains for a send) that connector RuleConditions reference via
	// their CtxPath. Pure; no I/O. Exposed as a Meta func (not the instance
	// ContextEnricher interface) so the PDP can enrich without constructing a
	// configured connector / touching the keyring. Nil ⇒ no enrichment.
	EnrichContext func(op string, params map[string]any) map[string]any `json:"-"`
}

// Field describes a form field for connection setup and editing.
//
// SetupFields is the single source of truth for the generic connection
// forms: the create flow renders/parses every non-EditOnly field, the
// edit page renders/parses every Editable field. Adding a field here is
// the ONLY step needed to surface it in both forms — the web layer has
// no per-connector form code.
//
// CRITICAL invariant (enforced by the architecture test in
// cmd/sieve/registry_arch_test.go): every key a connector persists in
// its config — INCLUDING keys written by bespoke create flows (Google
// OAuth, GitHub PAT/App install, Slack OAuth) — MUST be declared as a
// SetupField on Meta(). Bespoke flows own their own HTML and parsing,
// but the field MUST still appear here so the architectural test and
// the edit page agree on the persisted shape. Mark such fields with
// Editable=false + EditOnly=true if the generic form should not
// render them; the test only checks declaration, not rendering.
type Field struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Type        string `json:"type"` // "text", "password", "oauth", "select", "checkbox", "textarea", "number", "json" (object), "json_array"
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

// ContentFieldKeys returns the response content-field JSON keys for a connector
// type (for field-aware response filtering), or nil if it declares none — in
// which case filters fall back to whole-response matching.
func (r *Registry) ContentFieldKeys(connectorType string) []string {
	if r == nil {
		return nil
	}
	m, ok := r.metas[connectorType]
	if !ok || len(m.ContentFields) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m.ContentFields))
	for _, c := range m.ContentFields {
		keys = append(keys, c.Key)
	}
	return keys
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
