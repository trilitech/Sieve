// Package tokens manages API tokens that authenticate AI agents to Sieve.
// Each token is a capability handle bound to a SET of roles (RBAC, spec §5.1):
// the agent's capability is the union of all its roles' rules. The token itself
// is a random 32-byte secret with a "sieve_tok_" prefix.
// Security design:
// - Only the SHA-256 hash is stored. Plaintext returned once at creation.
// - All failure modes return generic "invalid token" to prevent enumeration.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
	"github.com/trilitech/Sieve/internal/database"
)

// Token represents a stored API token. A token is assigned a SET of roles
// (RBAC composition): the agent gets the union of every role's rules.
type Token struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	RoleIDs   []string   `json:"role_ids"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Revoked   bool       `json:"revoked"`
}

// PrimaryRole returns the first assigned role, or "" if none. Used by the
// legacy (non-IAM) decision path, which is single-role; the IAM path uses the
// full RoleIDs set.
func (t *Token) PrimaryRole() string {
	if len(t.RoleIDs) == 0 {
		return ""
	}
	return t.RoleIDs[0]
}

// CreateRequest is used when creating a new token.
type CreateRequest struct {
	Name string
	// RoleIDs is the set of roles assigned to the token (RBAC composition).
	RoleIDs []string
	// RoleID is a single-role convenience: if RoleIDs is empty and RoleID is
	// set, the token is created with exactly that one role. Prefer RoleIDs.
	RoleID    string
	ExpiresIn time.Duration // 0 means no expiry
}

// roles returns the effective role set, honoring the single-role convenience.
func (r *CreateRequest) roles() []string {
	if len(r.RoleIDs) > 0 {
		return r.RoleIDs
	}
	if r.RoleID != "" {
		return []string{r.RoleID}
	}
	return nil
}

// ErrDuplicateName is returned by Create when the requested name is already
// held by a LIVE token (one that is neither revoked nor past its expiry).
// Handlers map it to HTTP 409 with a banner rather than letting the raw
// UNIQUE-constraint failure surface as a 500.
var ErrDuplicateName = errors.New("a token with that name is already active")

// ErrEmptyName is returned by Create when the name is blank. The web form
// marks the field required, so this only fires on a hand-rolled POST — but it
// is a 400, not the 500 a UNIQUE collision on "" used to produce.
var ErrEmptyName = errors.New("token name is required")

// isUniqueViolation reports whether err is a SQLite UNIQUE-constraint failure.
func isUniqueViolation(err error) bool {
	var se sqlite3.Error
	return errors.As(err, &se) && se.ExtendedCode == sqlite3.ErrConstraintUnique
}

// retiredName is the name a dead token is archived under when a new token
// claims its name. The token id is appended, so the archived name is unique by
// construction and archiving can never itself collide — including when two
// tokens of the same name retire on the same day.
func retiredName(name, id string) string {
	return fmt.Sprintf("%s (retired %s)", name, id)
}

// retireNameHolder frees name for reuse, or reports why it cannot be freed.
//
// A token name is a human handle for a job ("taxes-agent"), and rotation is the
// normal lifecycle of such a job, so a dead token must not hold its name
// hostage: forcing taxes-agent-2 / taxes-agent-nov is what actually destroys
// the ability to follow one agent's history across rotations. The incumbent is
// therefore renamed out of the way and the new token takes the name over.
//
// This is safe because the name is never load-bearing: the Cedar principal is
// Sieve::Token::"<id>" scoped through roles, so authorization does not read it,
// and each audit row carries its own copy of the name alongside token_id, so
// existing history is unaffected by the rename and stays attributable to the
// specific token that produced it.
//
// Two LIVE tokens sharing a name stays an error — it would be ambiguous which
// one an operator is looking at when they revoke.
func retireNameHolder(tx *sql.Tx, name string, now time.Time) error {
	var (
		id        string
		expiresAt sql.NullTime
		revoked   int
	)
	err := tx.QueryRow(
		`SELECT id, expires_at, revoked FROM tokens WHERE name = ?`, name,
	).Scan(&id, &expiresAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // name is free
	}
	if err != nil {
		return fmt.Errorf("look up token name %q: %w", name, err)
	}

	dead := revoked != 0 || (expiresAt.Valid && now.After(expiresAt.Time))
	if !dead {
		return fmt.Errorf("%w: %q", ErrDuplicateName, name)
	}

	if _, err := tx.Exec(`UPDATE tokens SET name = ? WHERE id = ?`,
		retiredName(name, id), id); err != nil {
		return fmt.Errorf("retire token %q to free the name %q: %w", id, name, err)
	}
	return nil
}

// CreateResult is returned after creating a token.
type CreateResult struct {
	Token          *Token
	PlaintextToken string
}

type Service struct {
	db *database.DB
}

func NewService(db *database.DB) *Service {
	return &Service{db: db}
}

func (s *Service) Create(req *CreateRequest) (*CreateResult, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, ErrEmptyName
	}

	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generate token id: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	plaintext := "sieve_tok_" + hex.EncodeToString(tokenBytes)

	hash := sha256.Sum256([]byte(plaintext))
	tokenHash := hex.EncodeToString(hash[:])

	now := time.Now().UTC()
	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := now.Add(req.ExpiresIn)
		expiresAt = &t
	}

	roleIDs := req.roles()
	if roleIDs == nil {
		roleIDs = []string{}
	}
	roleIDsJSON, err := json.Marshal(roleIDs)
	if err != nil {
		return nil, fmt.Errorf("marshal role_ids: %w", err)
	}

	// Freeing the name and claiming it must be one atomic step, or a concurrent
	// create could retire the incumbent and then lose the race for the name.
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin token create: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := retireNameHolder(tx, name, now); err != nil {
		return nil, err
	}

	if _, err := tx.Exec(
		`INSERT INTO tokens (id, name, token_hash, role_ids, created_at, expires_at, revoked)
		 VALUES (?, ?, ?, ?, ?, ?, 0)`,
		id, name, tokenHash, string(roleIDsJSON), now, expiresAt,
	); err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateName, name)
		}
		return nil, fmt.Errorf("insert token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit token create: %w", err)
	}

	return &CreateResult{
		Token: &Token{
			ID: id, Name: name, RoleIDs: roleIDs,
			CreatedAt: now, ExpiresAt: expiresAt,
		},
		PlaintextToken: plaintext,
	}, nil
}

func (s *Service) Validate(plaintextToken string) (*Token, error) {
	hash := sha256.Sum256([]byte(plaintextToken))
	tokenHash := hex.EncodeToString(hash[:])

	row := s.db.QueryRow(
		`SELECT id, name, role_ids, created_at, expires_at, revoked
		 FROM tokens WHERE token_hash = ?`, tokenHash,
	)

	token, err := scanToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("invalid token")
		}
		return nil, fmt.Errorf("query token: %w", err)
	}

	if token.Revoked {
		return nil, fmt.Errorf("invalid token")
	}
	if token.ExpiresAt != nil && time.Now().UTC().After(*token.ExpiresAt) {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

func (s *Service) Get(id string) (*Token, error) {
	row := s.db.QueryRow(
		`SELECT id, name, role_ids, created_at, expires_at, revoked FROM tokens WHERE id = ?`, id,
	)
	token, err := scanToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("token not found")
		}
		return nil, err
	}
	return token, nil
}

func (s *Service) List() ([]Token, error) {
	rows, err := s.db.Query(
		`SELECT id, name, role_ids, created_at, expires_at, revoked FROM tokens`,
	)
	if err != nil {
		return nil, fmt.Errorf("query tokens: %w", err)
	}
	defer rows.Close()

	var tokens []Token
	for rows.Next() {
		token, err := scanTokenRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan token: %w", err)
		}
		tokens = append(tokens, *token)
	}
	return tokens, rows.Err()
}

// RemoveRoleFromAll strips roleID from every token's role set and reports how
// many tokens changed. Used by the role-delete cascade: a token that still
// listed the id would be synthesized as `in` that (now-deleted) role by the IAM
// engine — its rules/guardrails would keep applying — so the access must be
// truly revoked here, not merely hidden in the UI.
func (s *Service) RemoveRoleFromAll(roleID string) (int, error) {
	toks, err := s.List()
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, t := range toks {
		kept := make([]string, 0, len(t.RoleIDs))
		had := false
		for _, id := range t.RoleIDs {
			if id == roleID {
				had = true
				continue
			}
			kept = append(kept, id)
		}
		if !had {
			continue
		}
		roleIDsJSON, err := json.Marshal(kept)
		if err != nil {
			return changed, fmt.Errorf("marshal role_ids: %w", err)
		}
		if _, err := s.db.Exec(`UPDATE tokens SET role_ids = ? WHERE id = ?`,
			string(roleIDsJSON), t.ID); err != nil {
			return changed, fmt.Errorf("update token %q: %w", t.ID, err)
		}
		changed++
	}
	return changed, nil
}

// TokensUsingRole reports how many tokens reference roleID (for the role-delete
// blast-radius shown in the admin UI).
func (s *Service) TokensUsingRole(roleID string) (int, error) {
	toks, err := s.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, t := range toks {
		for _, id := range t.RoleIDs {
			if id == roleID {
				n++
				break
			}
		}
	}
	return n, nil
}

// UpdateRoles replaces a token's role set (RBAC edit) WITHOUT regenerating the
// secret — the token hash is untouched, only role_ids changes. Used by the
// admin UI's "edit roles".
func (s *Service) UpdateRoles(id string, roleIDs []string) error {
	if roleIDs == nil {
		roleIDs = []string{}
	}
	roleIDsJSON, err := json.Marshal(roleIDs)
	if err != nil {
		return fmt.Errorf("marshal role_ids: %w", err)
	}
	res, err := s.db.Exec(`UPDATE tokens SET role_ids = ? WHERE id = ?`,
		string(roleIDsJSON), id)
	if err != nil {
		return fmt.Errorf("update token roles: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("token not found")
	}
	return nil
}

func (s *Service) Revoke(id string) error {
	result, err := s.db.Exec(`UPDATE tokens SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("token not found")
	}
	return nil
}

func (s *Service) Delete(id string) error {
	result, err := s.db.Exec(`DELETE FROM tokens WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete token: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("token not found")
	}
	return nil
}

type scanner interface{ Scan(dest ...any) error }

func scanFromScanner(s scanner) (*Token, error) {
	var (
		token     Token
		roleIDs   sql.NullString
		expiresAt sql.NullTime
		revoked   int
	)
	err := s.Scan(&token.ID, &token.Name, &roleIDs, &token.CreatedAt, &expiresAt, &revoked)
	if err != nil {
		return nil, err
	}
	if roleIDs.Valid && roleIDs.String != "" && roleIDs.String != "[]" {
		if err := json.Unmarshal([]byte(roleIDs.String), &token.RoleIDs); err != nil {
			return nil, fmt.Errorf("parse role_ids: %w", err)
		}
	}
	if expiresAt.Valid {
		token.ExpiresAt = &expiresAt.Time
	}
	token.Revoked = revoked != 0
	return &token, nil
}

func scanToken(row *sql.Row) (*Token, error)      { return scanFromScanner(row) }
func scanTokenRow(rows *sql.Rows) (*Token, error) { return scanFromScanner(rows) }
