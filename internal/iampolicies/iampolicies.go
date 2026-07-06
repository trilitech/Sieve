// Package iampolicies is the storage layer for the IAM engine (internal/iam):
// Cedar policies, the filter library, and role-group membership. It coexists
// with the legacy internal/policies + internal/roles stores while the
// iam_enabled flag is off (docs/architecture/iam/). Connections and tokens are
// never touched here — credentials are preserved.
package iampolicies

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/iam"
)

// ErrDuplicateName is returned by CreatePolicy/UpdatePolicy when the policy name
// collides with an existing one (the name column is UNIQUE). Handlers map it to
// a friendly banner instead of surfacing the raw constraint error as HTTP 500.
var ErrDuplicateName = errors.New("a policy with that name already exists")

// isUniqueViolation reports whether err is a SQLite UNIQUE-constraint failure.
func isUniqueViolation(err error) bool {
	var se sqlite3.Error
	return errors.As(err, &se) && se.ExtendedCode == sqlite3.ErrConstraintUnique
}

// filtersAnnRE matches an @filters("a b c") annotation in a policy's Cedar.
var filtersAnnRE = regexp.MustCompile(`@filters\("([^"]*)"\)`)

// StoredPolicy is a persisted IAM policy (Cedar text + metadata).
type StoredPolicy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Cedar       string    `json:"cedar"`
	SpecJSON    string    `json:"spec_json"` // structured builder rule, for edit-in-place ("" if raw/migrated)
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// StoredGuardrail is a persisted guardrail (spec §7.2): a permit-only Cedar
// overlay carrying @approval/@filters annotations, evaluated in the second pass
// to attach obligations to an allowed request. Same shape as StoredPolicy but a
// distinct table and a permit-only save check.
type StoredGuardrail struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Cedar       string    `json:"cedar"`
	SpecJSON    string    `json:"spec_json"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// Service is the IAM storage service. It caches the compiled engine and
// rebuilds it lazily after any policy/filter mutation (invalidate()).
type Service struct {
	db *database.DB

	mu     sync.Mutex
	engine *iam.Engine
	dirty  bool
}

func NewService(db *database.DB) *Service { return &Service{db: db, dirty: true} }

// invalidate marks the cached engine stale; the next Engine() rebuilds.
func (s *Service) invalidate() {
	s.mu.Lock()
	s.dirty = true
	s.mu.Unlock()
}

// Engine returns the cached IAM engine, rebuilding it from storage if a
// policy/filter changed since the last build. A broken policy surfaces as an
// error (the caller fails closed).
func (s *Service) Engine() (*iam.Engine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine != nil && !s.dirty {
		return s.engine, nil
	}
	eng, err := s.BuildEngine()
	if err != nil {
		return nil, err
	}
	s.engine, s.dirty = eng, false
	return eng, nil
}

// --- policies ---

// CreatePolicy stores a new IAM policy.
func (s *Service) CreatePolicy(name, description, cedar string, enabled bool) (*StoredPolicy, error) {
	id := generateID()
	now := time.Now().UTC()
	_, err := s.db.DB.Exec(
		`INSERT INTO iam_policies (id, name, description, cedar_text, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, name, description, cedar, boolToInt(enabled), now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateName, name)
		}
		return nil, fmt.Errorf("insert iam policy: %w", err)
	}
	s.invalidate()
	return &StoredPolicy{ID: id, Name: name, Description: description, Cedar: cedar, Enabled: enabled, CreatedAt: now}, nil
}

// SetPolicyEnabled toggles a policy's enabled flag.
func (s *Service) SetPolicyEnabled(id string, enabled bool) error {
	res, err := s.db.DB.Exec(`UPDATE iam_policies SET enabled = ? WHERE id = ?`, boolToInt(enabled), id)
	if err != nil {
		return fmt.Errorf("set enabled: %w", err)
	}
	s.invalidate()
	return mustAffect(res, id)
}

// CreatePolicyWithSpec stores a new policy together with its structured builder
// form-state in a SINGLE insert, so the enforced Cedar and the reloadable spec
// can never desync — a two-step CreatePolicy + SetPolicySpec could leave an
// enforced rule with no reloadable form if the second write failed.
func (s *Service) CreatePolicyWithSpec(name, description, cedar, specJSON string, enabled bool) (*StoredPolicy, error) {
	id := generateID()
	now := time.Now().UTC()
	_, err := s.db.DB.Exec(
		`INSERT INTO iam_policies (id, name, description, cedar_text, spec_json, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, name, description, cedar, specJSON, boolToInt(enabled), now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateName, name)
		}
		return nil, fmt.Errorf("insert iam policy: %w", err)
	}
	s.invalidate()
	return &StoredPolicy{ID: id, Name: name, Description: description, Cedar: cedar, SpecJSON: specJSON, Enabled: enabled, CreatedAt: now}, nil
}

// UpdatePolicyWithSpec updates a policy's Cedar + metadata AND its structured
// form-state in a SINGLE update, keeping the enforced Cedar and the reloadable
// spec in sync (avoids the update-then-SetPolicySpec desync footgun where a
// failed second write leaves new Cedar enforced but the old form on reload).
func (s *Service) UpdatePolicyWithSpec(id, name, description, cedar, specJSON string, enabled bool) error {
	res, err := s.db.DB.Exec(
		`UPDATE iam_policies SET name = ?, description = ?, cedar_text = ?, spec_json = ?, enabled = ? WHERE id = ?`,
		name, description, cedar, specJSON, boolToInt(enabled), id,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: %q", ErrDuplicateName, name)
		}
		return fmt.Errorf("update iam policy: %w", err)
	}
	s.invalidate()
	return mustAffect(res, id)
}

// GetPolicy returns a policy by id.
func (s *Service) GetPolicy(id string) (*StoredPolicy, error) {
	row := s.db.DB.QueryRow(
		`SELECT id, name, description, cedar_text, spec_json, enabled, created_at FROM iam_policies WHERE id = ?`, id)
	var p StoredPolicy
	var enabled int
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Cedar, &p.SpecJSON, &enabled, &p.CreatedAt); err != nil {
		return nil, fmt.Errorf("get iam policy %q: %w", id, err)
	}
	p.Enabled = enabled != 0
	return &p, nil
}

// ListPolicies returns all stored policies (enabled and not).
func (s *Service) ListPolicies() ([]StoredPolicy, error) {
	rows, err := s.db.DB.Query(
		`SELECT id, name, description, cedar_text, spec_json, enabled, created_at FROM iam_policies ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list iam policies: %w", err)
	}
	defer rows.Close()
	var out []StoredPolicy
	for rows.Next() {
		var p StoredPolicy
		var enabled int
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Cedar, &p.SpecJSON, &enabled, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan iam policy: %w", err)
		}
		p.Enabled = enabled != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePolicy removes a policy.
func (s *Service) DeletePolicy(id string) error {
	res, err := s.db.DB.Exec(`DELETE FROM iam_policies WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete iam policy: %w", err)
	}
	s.invalidate()
	return mustAffect(res, id)
}

// EnabledPolicies returns the enabled policies as iam.Policy (for NewEngine).
func (s *Service) EnabledPolicies() ([]iam.Policy, error) {
	all, err := s.ListPolicies()
	if err != nil {
		return nil, err
	}
	var out []iam.Policy
	for _, p := range all {
		if p.Enabled {
			out = append(out, iam.Policy{ID: p.ID, Cedar: p.Cedar})
		}
	}
	return out, nil
}

// --- guardrails (spec §7.2: permit-only obligation overlays) ---

// CreateGuardrail stores a new guardrail after enforcing the permit-only
// invariant. A forbid (or unparseable Cedar) is rejected here, including via the
// raw-Cedar escape hatch.
func (s *Service) CreateGuardrail(name, description, cedar string, enabled bool) (*StoredGuardrail, error) {
	if err := iam.ValidateGuardrailCedar(cedar); err != nil {
		return nil, err
	}
	id := generateID()
	now := time.Now().UTC()
	_, err := s.db.DB.Exec(
		`INSERT INTO iam_guardrails (id, name, description, cedar_text, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, name, description, cedar, boolToInt(enabled), now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert iam guardrail: %w", err)
	}
	s.invalidate()
	return &StoredGuardrail{ID: id, Name: name, Description: description, Cedar: cedar, Enabled: enabled, CreatedAt: now}, nil
}

// ListGuardrails returns all stored guardrails (enabled and not).
func (s *Service) ListGuardrails() ([]StoredGuardrail, error) {
	rows, err := s.db.DB.Query(
		`SELECT id, name, description, cedar_text, spec_json, enabled, created_at FROM iam_guardrails ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list iam guardrails: %w", err)
	}
	defer rows.Close()
	var out []StoredGuardrail
	for rows.Next() {
		var g StoredGuardrail
		var enabled int
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Cedar, &g.SpecJSON, &enabled, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan iam guardrail: %w", err)
		}
		g.Enabled = enabled != 0
		out = append(out, g)
	}
	return out, rows.Err()
}

// DeleteGuardrail removes a guardrail.
func (s *Service) DeleteGuardrail(id string) error {
	res, err := s.db.DB.Exec(`DELETE FROM iam_guardrails WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete iam guardrail: %w", err)
	}
	s.invalidate()
	return mustAffect(res, id)
}

// EnabledGuardrails returns the enabled guardrails as iam.Policy for NewEngine's
// guardrail set.
func (s *Service) EnabledGuardrails() ([]iam.Policy, error) {
	all, err := s.ListGuardrails()
	if err != nil {
		return nil, err
	}
	var out []iam.Policy
	for _, g := range all {
		if g.Enabled {
			out = append(out, iam.Policy{ID: g.ID, Cedar: g.Cedar})
		}
	}
	return out, nil
}

// --- transforms (spec §7: self-contained scoped response transforms) ---

// StoredTransform is a persisted scoped transform: a permit-only Cedar overlay
// carrying an inline @transform_* action, scoped global or to a role. Same shape
// as StoredGuardrail (permit-only) but its own table; it needs no filter-library
// entry to attach to.
type StoredTransform struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Cedar       string    `json:"cedar"`
	SpecJSON    string    `json:"spec_json"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// CreateTransform stores a new scoped transform (permit-only re-validated).
func (s *Service) CreateTransform(name, description, cedar, specJSON string, enabled bool) (*StoredTransform, error) {
	if err := iam.ValidateGuardrailCedar(cedar); err != nil {
		return nil, err
	}
	id := generateID()
	now := time.Now().UTC()
	_, err := s.db.DB.Exec(
		`INSERT INTO iam_transforms (id, name, description, cedar_text, spec_json, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, name, description, cedar, specJSON, boolToInt(enabled), now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert iam transform: %w", err)
	}
	s.invalidate()
	return &StoredTransform{ID: id, Name: name, Description: description, Cedar: cedar, SpecJSON: specJSON, Enabled: enabled, CreatedAt: now}, nil
}

// SetTransformEnabled toggles a transform's enabled flag.
func (s *Service) SetTransformEnabled(id string, enabled bool) error {
	res, err := s.db.DB.Exec(`UPDATE iam_transforms SET enabled = ? WHERE id = ?`, boolToInt(enabled), id)
	if err != nil {
		return fmt.Errorf("set transform enabled: %w", err)
	}
	s.invalidate()
	return mustAffect(res, id)
}

// ListTransforms returns all stored transforms (enabled and not).
func (s *Service) ListTransforms() ([]StoredTransform, error) {
	rows, err := s.db.DB.Query(
		`SELECT id, name, description, cedar_text, spec_json, enabled, created_at FROM iam_transforms ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list iam transforms: %w", err)
	}
	defer rows.Close()
	var out []StoredTransform
	for rows.Next() {
		var t StoredTransform
		var enabled int
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.Cedar, &t.SpecJSON, &enabled, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan iam transform: %w", err)
		}
		t.Enabled = enabled != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteTransform removes a transform.
func (s *Service) DeleteTransform(id string) error {
	res, err := s.db.DB.Exec(`DELETE FROM iam_transforms WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete iam transform: %w", err)
	}
	s.invalidate()
	return mustAffect(res, id)
}

// EnabledTransforms returns the enabled transforms as iam.Policy. They join the
// guardrail set (both are permit-only obligation overlays the engine reads in the
// second pass).
func (s *Service) EnabledTransforms() ([]iam.Policy, error) {
	all, err := s.ListTransforms()
	if err != nil {
		return nil, err
	}
	var out []iam.Policy
	for _, t := range all {
		if t.Enabled {
			out = append(out, iam.Policy{ID: t.ID, Cedar: t.Cedar})
		}
	}
	return out, nil
}

// DeleteTransformsForRole deletes every role-scoped transform whose Cedar targets
// roleID (part of the role-delete cascade). Global transforms are unaffected.
func (s *Service) DeleteTransformsForRole(roleID string) (int, error) {
	all, err := s.ListTransforms()
	if err != nil {
		return 0, err
	}
	marker := RoleMarker(roleID)
	n := 0
	for _, t := range all {
		if strings.Contains(t.Cedar, marker) {
			if err := s.DeleteTransform(t.ID); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// --- role cascade (delete a role → remove its rules + guardrails) ---

// RoleMarker is the Cedar substring present in any rule or guardrail that
// targets roleID (the builder emits `principal in Sieve::Role::"<id>"`, and a
// raw rule references the role the same way). Used to find role-scoped rules
// without re-parsing Cedar. Role ids are hex, so no Cedar-string escaping is
// needed.
func RoleMarker(roleID string) string {
	return iam.TypeRole + `::"` + roleID + `"`
}

// DeletePoliciesForRole deletes every stored policy whose Cedar targets roleID,
// returning the count removed. Part of the role-delete cascade so a deleted role
// never leaves orphaned rules that silently re-attach if the id is reused.
func (s *Service) DeletePoliciesForRole(roleID string) (int, error) {
	all, err := s.ListPolicies()
	if err != nil {
		return 0, err
	}
	marker := RoleMarker(roleID)
	n := 0
	for _, p := range all {
		if strings.Contains(p.Cedar, marker) {
			if err := s.DeletePolicy(p.ID); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// DeleteGuardrailsForRole deletes every stored guardrail whose Cedar targets
// roleID, returning the count removed. Companion to DeletePoliciesForRole.
func (s *Service) DeleteGuardrailsForRole(roleID string) (int, error) {
	all, err := s.ListGuardrails()
	if err != nil {
		return 0, err
	}
	marker := RoleMarker(roleID)
	n := 0
	for _, g := range all {
		if strings.Contains(g.Cedar, marker) {
			if err := s.DeleteGuardrail(g.ID); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// --- filters ---

// CreateFilter stores a filter-library entry.
func (s *Service) CreateFilter(name, description string, kind iam.FilterKind, order int, config map[string]any) (*iam.Filter, error) {
	id := generateID()
	cfgJSON, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("marshal filter config: %w", err)
	}
	_, err = s.db.DB.Exec(
		`INSERT INTO iam_filters (id, name, description, kind, sort_order, config, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, name, description, string(kind), order, string(cfgJSON), time.Now().UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("insert iam filter: %w", err)
	}
	s.invalidate()
	return &iam.Filter{Name: name, Kind: kind, Order: order, Config: config}, nil
}

// ListFilters returns every filter-library entry.
func (s *Service) ListFilters() ([]iam.Filter, error) {
	rows, err := s.db.DB.Query(`SELECT name, kind, sort_order, config FROM iam_filters ORDER BY sort_order, name`)
	if err != nil {
		return nil, fmt.Errorf("list iam filters: %w", err)
	}
	defer rows.Close()
	var out []iam.Filter
	for rows.Next() {
		var f iam.Filter
		var kind, cfgJSON string
		if err := rows.Scan(&f.Name, &kind, &f.Order, &cfgJSON); err != nil {
			return nil, fmt.Errorf("scan iam filter: %w", err)
		}
		f.Kind = iam.FilterKind(kind)
		if cfgJSON != "" {
			if err := json.Unmarshal([]byte(cfgJSON), &f.Config); err != nil {
				return nil, fmt.Errorf("unmarshal filter config (%s): %w", f.Name, err)
			}
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// FilterInUse reports whether any stored transform attachment, guardrail (or,
// for back-compat, policy) references the named filter/definition in an @filters
// annotation. The admin UI refuses to delete an in-use definition, since removing
// it would leave an enabled attachment whose @filters reference cannot be resolved
// — the next matching request would then fail closed with an unknown-filter deny.
// A reusable transform DEFINITION is attached by reference: BuildAttachmentCedar
// emits @filters(<name>) into iam_transforms, so those MUST be scanned too. @filters
// also live on guardrails (spec §7.2); legacy policies are scanned in case a
// migrated rule retained one.
func (s *Service) FilterInUse(name string) (bool, error) {
	refsName := func(cedar string) bool {
		for _, m := range filtersAnnRE.FindAllStringSubmatch(cedar, -1) {
			for _, n := range strings.Fields(m[1]) {
				if n == name {
					return true
				}
			}
		}
		return false
	}
	transforms, err := s.ListTransforms()
	if err != nil {
		return false, err
	}
	for _, t := range transforms {
		if refsName(t.Cedar) {
			return true, nil
		}
	}
	guards, err := s.ListGuardrails()
	if err != nil {
		return false, err
	}
	for _, g := range guards {
		if refsName(g.Cedar) {
			return true, nil
		}
	}
	pols, err := s.ListPolicies()
	if err != nil {
		return false, err
	}
	for _, p := range pols {
		if refsName(p.Cedar) {
			return true, nil
		}
	}
	return false, nil
}

// FilterDetail is one filter-library entry with everything the admin edit form
// needs (iam.Filter omits Description, which the form shows). Returned by
// GetFilter for edit-in-place.
type FilterDetail struct {
	Name        string
	Description string
	Kind        iam.FilterKind
	Order       int
	Config      map[string]any
}

// GetFilter returns one filter-library entry by name (for edit-in-place).
func (s *Service) GetFilter(name string) (*FilterDetail, error) {
	row := s.db.DB.QueryRow(`SELECT name, description, kind, sort_order, config FROM iam_filters WHERE name = ?`, name)
	var f FilterDetail
	var kind, cfgJSON string
	if err := row.Scan(&f.Name, &f.Description, &kind, &f.Order, &cfgJSON); err != nil {
		return nil, fmt.Errorf("get iam filter %q: %w", name, err)
	}
	f.Kind = iam.FilterKind(kind)
	if cfgJSON != "" {
		if err := json.Unmarshal([]byte(cfgJSON), &f.Config); err != nil {
			return nil, fmt.Errorf("unmarshal filter config (%s): %w", f.Name, err)
		}
	}
	return &f, nil
}

// UpdateFilter modifies a filter-library entry in place. The name is the stable
// key (rules/guardrails reference a filter by name via @filters, so renaming
// would silently detach them) — description, kind, sort_order, and config change.
func (s *Service) UpdateFilter(name, description string, kind iam.FilterKind, order int, config map[string]any) error {
	cfgJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal filter config: %w", err)
	}
	res, err := s.db.DB.Exec(
		`UPDATE iam_filters SET description = ?, kind = ?, sort_order = ?, config = ? WHERE name = ?`,
		description, string(kind), order, string(cfgJSON), name,
	)
	if err != nil {
		return fmt.Errorf("update iam filter: %w", err)
	}
	s.invalidate()
	return mustAffect(res, name)
}

// DeleteFilter removes a filter-library entry by name.
func (s *Service) DeleteFilter(name string) error {
	res, err := s.db.DB.Exec(`DELETE FROM iam_filters WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("delete iam filter: %w", err)
	}
	s.invalidate()
	return mustAffect(res, name)
}

// FilterLibrary loads all filters into an in-memory iam.FilterLibrary.
func (s *Service) FilterLibrary() (iam.MapFilterLibrary, error) {
	fs, err := s.ListFilters()
	if err != nil {
		return nil, err
	}
	lib := make(iam.MapFilterLibrary, len(fs))
	for _, f := range fs {
		lib[f.Name] = f
	}
	return lib, nil
}

// --- engine ---

// BuildEngine loads the enabled policies + filter library and constructs the
// IAM engine. A broken policy (unparseable Cedar) surfaces as an error here;
// callers (PR-D) decide whether to fail closed or exclude it.
func (s *Service) BuildEngine() (*iam.Engine, error) {
	pols, err := s.EnabledPolicies()
	if err != nil {
		return nil, err
	}
	guards, err := s.EnabledGuardrails()
	if err != nil {
		return nil, err
	}
	// Scoped transforms join the guardrail set: both are permit-only obligation
	// overlays the engine reads in the second pass. A transform carries its action
	// inline (@transform_*); a legacy guardrail references the filter library.
	transforms, err := s.EnabledTransforms()
	if err != nil {
		return nil, err
	}
	guards = append(guards, transforms...)
	lib, err := s.FilterLibrary()
	if err != nil {
		return nil, err
	}
	return iam.NewEngine(pols, guards, lib)
}

// ValidateCedar reports whether cedar parses and compiles as a single IAM policy
// against the current filter library. The admin UI calls this BEFORE storing a
// policy (builder-generated or raw) so one un-parseable statement can't fail the
// whole engine rebuild and lock out every decision.
func (s *Service) ValidateCedar(cedar string) error {
	lib, err := s.FilterLibrary()
	if err != nil {
		return err
	}
	_, err = iam.NewEngine([]iam.Policy{{ID: "_validate", Cedar: cedar}}, nil, lib)
	return err
}

// --- helpers ---

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func mustAffect(res interface{ RowsAffected() (int64, error) }, id string) error {
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("id %q not found", id)
	}
	return nil
}

func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
