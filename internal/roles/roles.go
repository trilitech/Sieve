// Package roles manages reusable role definitions that bundle connections
// with their applicable policies. A role is the reusable template that
// defines "what can an agent with this role do?" Tokens reference a role
// rather than specifying connections and policies directly.
// Each role contains a list of connection bindings. Each binding pairs a
// connection ID with zero or more policy IDs. A connection with no policies
// means DENY ALL — the agent can see the connection exists but cannot
// perform any operations through it.
// Example role:
//{
//"name": "project-x-dev",
//"bindings": [
//{"connection_id": "google-work", "policy_ids": ["gmail-drafter", "drive-read-only"]},
//{"connection_id": "anthropic", "policy_ids": ["sonnet-only"]},
//{"connection_id": "aws-prod", "policy_ids": ["ec2-describe-only"]}
//]
//}
package roles

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/trilitech/Sieve/internal/database"
)

// Binding pairs a connection with its applicable policies.
type Binding struct {
	ConnectionID string   `json:"connection_id"`
	PolicyIDs    []string `json:"policy_ids"`
}

// Role is a reusable bundle of connection+policy bindings.
type Role struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Bindings  []Binding `json:"bindings"`
	CreatedAt time.Time `json:"created_at"`
}

type Service struct {
	db *database.DB
}

func NewService(db *database.DB) *Service {
	return &Service{db: db}
}

// ErrReservedConnectionID is returned by Create / Update when a binding
// references a reserved system row (e.g., `oauth_app__slack`). Reserved
// rows hold per-deployment state and MUST NOT be agent-addressable.
var ErrReservedConnectionID = errors.New("role binding references a reserved system connection id")

// isReservedConnectionID mirrors connections.IsReservedConnectionID
// without importing the package (avoids a cycle: roles ← connections
// would close on roles → connections). The set is exactly one prefix
// today; if more reserved kinds appear, mirror the change here.
func isReservedConnectionID(id string) bool {
	return strings.HasPrefix(id, "oauth_app__")
}

// validateBindings rejects bindings that reference reserved system rows.
// Called from Create and Update to keep the write paths consistent.
func validateBindings(bindings []Binding) error {
	for _, b := range bindings {
		if isReservedConnectionID(b.ConnectionID) {
			return fmt.Errorf("%w: %q", ErrReservedConnectionID, b.ConnectionID)
		}
	}
	return nil
}

// Create stores a new role.
func (s *Service) Create(name string, bindings []Binding) (*Role, error) {
	if err := validateBindings(bindings); err != nil {
		return nil, err
	}
	id := generateID()

	bindingsJSON, err := json.Marshal(bindings)
	if err != nil {
		return nil, fmt.Errorf("marshal bindings: %w", err)
	}

	now := time.Now().UTC()
	_, err = s.db.DB.Exec(
		`INSERT INTO roles (id, name, bindings, created_at) VALUES (?, ?, ?, ?)`,
		id, name, string(bindingsJSON), now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert role: %w", err)
	}

	return &Role{
		ID:        id,
		Name:      name,
		Bindings:  bindings,
		CreatedAt: now,
	}, nil
}

// Get returns a role by ID.
func (s *Service) Get(id string) (*Role, error) {
	row := s.db.DB.QueryRow(
		`SELECT id, name, bindings, created_at FROM roles WHERE id = ?`, id,
	)
	return scanRole(row)
}

// GetByName returns a role by name.
func (s *Service) GetByName(name string) (*Role, error) {
	row := s.db.DB.QueryRow(
		`SELECT id, name, bindings, created_at FROM roles WHERE name = ?`, name,
	)
	return scanRole(row)
}

// List returns all roles.
func (s *Service) List() ([]Role, error) {
	rows, err := s.db.DB.Query(
		`SELECT id, name, bindings, created_at FROM roles ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()

	var result []Role
	for rows.Next() {
		var r Role
		var bindingsJSON string
		if err := rows.Scan(&r.ID, &r.Name, &bindingsJSON, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		if err := json.Unmarshal([]byte(bindingsJSON), &r.Bindings); err != nil {
			return nil, fmt.Errorf("unmarshal bindings: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// Update modifies a role's name and bindings.
func (s *Service) Update(id, name string, bindings []Binding) error {
	if err := validateBindings(bindings); err != nil {
		return err
	}
	bindingsJSON, err := json.Marshal(bindings)
	if err != nil {
		return fmt.Errorf("marshal bindings: %w", err)
	}

	res, err := s.db.DB.Exec(
		`UPDATE roles SET name = ?, bindings = ? WHERE id = ?`,
		name, string(bindingsJSON), id,
	)
	if err != nil {
		return fmt.Errorf("update role: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("role %q not found", id)
	}
	return nil
}

// Delete removes a role.
func (s *Service) Delete(id string) error {
	res, err := s.db.DB.Exec(`DELETE FROM roles WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("role %q not found", id)
	}
	return nil
}

// ConnectionIDs returns the list of connection IDs in a role.
func (r *Role) ConnectionIDs() []string {
	ids := make([]string, len(r.Bindings))
	for i, b := range r.Bindings {
		ids[i] = b.ConnectionID
	}
	return ids
}

// PoliciesForConnection returns the policy IDs for a specific connection.
// Returns nil if the connection is not in the role (which means deny all).
func (r *Role) PoliciesForConnection(connID string) []string {
	for _, b := range r.Bindings {
		if b.ConnectionID == connID {
			return b.PolicyIDs
		}
	}
	return nil
}

func scanRole(row interface{ Scan(...any) error }) (*Role, error) {
	var r Role
	var bindingsJSON string
	if err := row.Scan(&r.ID, &r.Name, &bindingsJSON, &r.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan role: %w", err)
	}
	if err := json.Unmarshal([]byte(bindingsJSON), &r.Bindings); err != nil {
		return nil, fmt.Errorf("unmarshal bindings: %w", err)
	}
	return &r, nil
}

func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
