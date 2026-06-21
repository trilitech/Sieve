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
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/iam"
)

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
		return nil, fmt.Errorf("insert iam policy: %w", err)
	}
	s.invalidate()
	return &StoredPolicy{ID: id, Name: name, Description: description, Cedar: cedar, Enabled: enabled, CreatedAt: now}, nil
}

// UpdatePolicy modifies a policy's name, description, Cedar, and enabled flag.
func (s *Service) UpdatePolicy(id, name, description, cedar string, enabled bool) error {
	res, err := s.db.DB.Exec(
		`UPDATE iam_policies SET name = ?, description = ?, cedar_text = ?, enabled = ? WHERE id = ?`,
		name, description, cedar, boolToInt(enabled), id,
	)
	if err != nil {
		return fmt.Errorf("update iam policy: %w", err)
	}
	s.invalidate()
	return mustAffect(res, id)
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

// SetPolicySpec stores the structured builder rule (JSON) beside the compiled
// Cedar so the admin UI can reload it for edit-in-place. It does not touch the
// Cedar or the engine, so no invalidate.
func (s *Service) SetPolicySpec(id, specJSON string) error {
	res, err := s.db.DB.Exec(`UPDATE iam_policies SET spec_json = ? WHERE id = ?`, specJSON, id)
	if err != nil {
		return fmt.Errorf("set policy spec: %w", err)
	}
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

// UpdateGuardrail modifies a guardrail (permit-only re-validated).
func (s *Service) UpdateGuardrail(id, name, description, cedar string, enabled bool) error {
	if err := iam.ValidateGuardrailCedar(cedar); err != nil {
		return err
	}
	res, err := s.db.DB.Exec(
		`UPDATE iam_guardrails SET name = ?, description = ?, cedar_text = ?, enabled = ? WHERE id = ?`,
		name, description, cedar, boolToInt(enabled), id,
	)
	if err != nil {
		return fmt.Errorf("update iam guardrail: %w", err)
	}
	s.invalidate()
	return mustAffect(res, id)
}

// SetGuardrailEnabled toggles a guardrail's enabled flag.
func (s *Service) SetGuardrailEnabled(id string, enabled bool) error {
	res, err := s.db.DB.Exec(`UPDATE iam_guardrails SET enabled = ? WHERE id = ?`, boolToInt(enabled), id)
	if err != nil {
		return fmt.Errorf("set guardrail enabled: %w", err)
	}
	s.invalidate()
	return mustAffect(res, id)
}

// SetGuardrailSpec stores the structured builder form (JSON) for edit-in-place.
func (s *Service) SetGuardrailSpec(id, specJSON string) error {
	res, err := s.db.DB.Exec(`UPDATE iam_guardrails SET spec_json = ? WHERE id = ?`, specJSON, id)
	if err != nil {
		return fmt.Errorf("set guardrail spec: %w", err)
	}
	return mustAffect(res, id)
}

// GetGuardrail returns a guardrail by id.
func (s *Service) GetGuardrail(id string) (*StoredGuardrail, error) {
	row := s.db.DB.QueryRow(
		`SELECT id, name, description, cedar_text, spec_json, enabled, created_at FROM iam_guardrails WHERE id = ?`, id)
	var g StoredGuardrail
	var enabled int
	if err := row.Scan(&g.ID, &g.Name, &g.Description, &g.Cedar, &g.SpecJSON, &enabled, &g.CreatedAt); err != nil {
		return nil, fmt.Errorf("get iam guardrail %q: %w", id, err)
	}
	g.Enabled = enabled != 0
	return &g, nil
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

// FilterInUse reports whether any stored guardrail (or, for back-compat, policy)
// references the named filter in an @filters annotation. The admin UI refuses to
// delete an in-use filter, since removing it would fail-close every guardrail
// that references it. @filters live on guardrails (spec §7.2); legacy policies
// are still scanned in case a migrated rule retained one.
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

// --- role groups ---

// CreateRoleGroup creates a named principal group.
func (s *Service) CreateRoleGroup(name string) (string, error) {
	id := generateID()
	if _, err := s.db.DB.Exec(`INSERT INTO iam_role_groups (id, name, created_at) VALUES (?, ?, ?)`,
		id, name, time.Now().UTC()); err != nil {
		return "", fmt.Errorf("create role group: %w", err)
	}
	return id, nil
}

// AddRoleToGroup adds a role to a group (idempotent).
func (s *Service) AddRoleToGroup(groupID, roleID string) error {
	_, err := s.db.DB.Exec(
		`INSERT OR IGNORE INTO iam_role_group_members (group_id, role_id) VALUES (?, ?)`, groupID, roleID)
	if err != nil {
		return fmt.Errorf("add role to group: %w", err)
	}
	return nil
}

// GroupsForRole returns the group ids a role belongs to (for the PIP's
// principal hierarchy).
func (s *Service) GroupsForRole(roleID string) ([]string, error) {
	rows, err := s.db.DB.Query(`SELECT group_id FROM iam_role_group_members WHERE role_id = ?`, roleID)
	if err != nil {
		return nil, fmt.Errorf("groups for role: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
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
