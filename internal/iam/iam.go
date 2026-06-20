// Package iam is Sieve's authorization engine (the PDP, per NIST SP 800-162),
// built on Cedar (github.com/cedar-policy/cedar-go). It evaluates a request
// against the union of enabled Cedar policies (deny-overrides-permit,
// default-deny) and resolves the obligations — approval, guards, response
// filters — carried as annotations on the determining permits.
//
// Design: docs/architecture/iam/01-spec.md. The cedar-go dependency is isolated
// to engine.go (the single seam); the rest of the package speaks Sieve types.
//
// This is PR-A: the engine + obligation resolution + tests. It performs no I/O
// and is not yet wired to the request path. Connector taxonomy (PR-B), storage
// (PR-C), and the PEP switchover (PR-D) build on this.
package iam

// EntityUID identifies a Cedar entity in Sieve terms: a namespaced type and an
// id, e.g. {Type: "Sieve::Google::Message", ID: "work-gmail/msg_123"}.
type EntityUID struct {
	Type string
	ID   string
}

// Entity is one node in the request's entity store: its UID, its parents (the
// hierarchy edges Cedar's `in` walks — action→groups, resource→connection→
// connector, token→role→role-groups), and any attributes referenced by
// conditions. Because cedar.Authorize takes no schema, the store is the ONLY
// source of hierarchy at decision time (spec §8, review C3).
type Entity struct {
	UID     EntityUID
	Parents []EntityUID
	Attrs   map[string]any
}

// Request is the Sieve-level authorization request the PEP assembles (spec
// §5.5). Principal/Action/Resource are the three Cedar request components;
// Entities is the complete entity store for this request (the three plus every
// ancestor/group they reference); Context is the enriched environment.
type Request struct {
	Principal EntityUID
	Action    EntityUID
	Resource  EntityUID
	Entities  []Entity
	Context   map[string]any
}

// Decision is the engine's result. Allow is the Cedar decision; Obligations are
// resolved only on Allow (spec §7.3). Determining lists the Sieve policy ids
// that decided the request (the satisfied permits on allow, the satisfied
// forbids on deny) — the "why" surfaced to audit + the explorer (spec §11).
type Decision struct {
	Allow       bool
	Reason      string
	Determining []string
	Obligations Obligations
	// EvalErrors holds per-policy evaluation errors (Cedar skips errored
	// policies — spec §6). They never change the outcome; they are logged so a
	// policy that silently fails closed is visible.
	EvalErrors []EvalError
}

// EvalError is a single policy that errored during evaluation (and was skipped).
type EvalError struct {
	PolicyID string
	Message  string
}

// Obligations are the actions attached to an allow. Every one can only narrow
// (deny) or transform — never grant (spec §7, the monotonicity invariant).
type Obligations struct {
	// Approval: at least one determining permit carried @approval("required").
	Approval bool
	// Guards run pre-execution and may DENY (script_guard, rate_limit). Order
	// among them is irrelevant — any deny denies.
	Guards []Filter
	// Post run on the response and may only TRANSFORM (redact, exclude_items,
	// script_filter). Applied in ascending (Order, Name) — deterministic.
	Post []Filter
	// AuditLabel is the joined @audit_label of the determining permits.
	AuditLabel string
}

// Policy is a stored Sieve policy: a stable id and its Cedar text (one or more
// permit/forbid statements with annotations). The connection set a policy
// applies to lives in a `when` clause (`resource in [..]`) — sets are invalid in
// the principal/resource scope (H4 spike; spec §9.1).
type Policy struct {
	ID    string
	Cedar string
}

// Filter is one entry of the obligation/filter library (spec §7.1): a named,
// reusable transform or guard. Kind selects the behavior; Config holds its
// parameters; Order sequences post-filters.
type Filter struct {
	Name   string
	Kind   FilterKind
	Order  int
	Config map[string]any
}

// FilterKind enumerates the library kinds (spec §7.1).
type FilterKind string

const (
	KindRedact       FilterKind = "redact"        // post: regex-mask response
	KindExcludeItems FilterKind = "exclude_items" // post: drop matching list items
	KindScriptFilter FilterKind = "script_filter" // post: script transforms response
	KindScriptGuard  FilterKind = "script_guard"  // pre: script may deny
	KindRateLimit    FilterKind = "rate_limit"    // pre: quota may deny
)

// phase reports whether a kind runs pre-execution (guard) or post (transform).
func (k FilterKind) isPre() bool { return k == KindScriptGuard || k == KindRateLimit }

// FilterLibrary resolves filter names referenced by a policy's @filters
// annotation. PR-A uses an in-memory impl; PR-C backs it with iam_filters.
type FilterLibrary interface {
	// Get returns the named filter and whether it exists. A missing filter is
	// a fail-closed error at resolution time (spec §7.5).
	Get(name string) (Filter, bool)
}

// MapFilterLibrary is an in-memory FilterLibrary (tests, and a cache base).
type MapFilterLibrary map[string]Filter

// Get implements FilterLibrary.
func (m MapFilterLibrary) Get(name string) (Filter, bool) {
	f, ok := m[name]
	return f, ok
}
