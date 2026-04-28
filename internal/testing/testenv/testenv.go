// Package testenv provides a complete Sieve test environment with an
// in-memory database, mock connectors, and all services initialized.
package testenv

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/approval"
	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/policies"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/secrets"
	"github.com/trilitech/Sieve/internal/settings"
	mockconn "github.com/trilitech/Sieve/internal/testing/mockconnector"
	"github.com/trilitech/Sieve/internal/tokens"
)

// Env holds all Sieve services for testing.
type Env struct {
	DB          *database.DB
	Connections *connections.Service
	Tokens      *tokens.Service
	Policies    *policies.Service
	Roles       *roles.Service
	Approval    *approval.Queue
	Audit       *audit.Logger
	Settings    *settings.Service
	Registry    *connector.Registry
	Keyring     *secrets.Keyring
	Mock        *mockconn.Mock
	DBPath      string
}

// New creates a fresh test environment with a temp database.
func New(t *testing.T) *Env {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("create test db: %v", err)
	}

	registry := connector.NewRegistry()
	mock := mockconn.New("mock")
	registry.Register(mock.Meta(), mock.Factory())

	// Tests must run unattended, so set up an in-memory keyring with a
	// fixed test passphrase. Production paths still require an admin
	// passphrase at startup.
	keyring := &secrets.Keyring{}
	saved := secrets.DefaultArgon2Params
	secrets.DefaultArgon2Params = secrets.Argon2Params{Time: 1, Memory: 8, Threads: 1, KeyLen: 32}
	if err := keyring.Setup(db.DB, []byte("test-passphrase")); err != nil {
		t.Fatalf("keyring setup: %v", err)
	}
	secrets.DefaultArgon2Params = saved

	connSvc := connections.NewService(db, registry, keyring)
	tokenSvc := tokens.NewService(db)
	policiesSvc := policies.NewService(db)
	rolesSvc := roles.NewService(db)
	approvalQ := approval.NewQueue(db)
	auditLog := audit.NewLogger(db)
	settingsSvc := settings.NewService(db)

	if err := policiesSvc.SeedPresets(); err != nil {
		t.Fatalf("seed presets: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
		os.Remove(dbPath)
	})

	return &Env{
		DB:          db,
		Connections: connSvc,
		Tokens:      tokenSvc,
		Policies:    policiesSvc,
		Roles:       rolesSvc,
		Approval:    approvalQ,
		Audit:       auditLog,
		Settings:    settingsSvc,
		Registry:    registry,
		Keyring:     keyring,
		Mock:        mock,
		DBPath:      dbPath,
	}
}

// SetupConnectionAndRole creates a mock connection, a role with the given
// policy names, and returns the role. This is the common setup for tests
// that need a working token.
func (e *Env) SetupConnectionAndRole(t *testing.T, connID string, policyNames ...string) *roles.Role {
	t.Helper()

	// Create the mock connection.
	err := e.Connections.Add(connID, "mock", "Test Connection", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	// Resolve policy IDs from names.
	var policyIDs []string
	for _, name := range policyNames {
		pol, err := e.Policies.GetByName(name)
		if err != nil {
			t.Fatalf("get policy %q: %v", name, err)
		}
		policyIDs = append(policyIDs, pol.ID)
	}

	// Create a role with the connection and policies.
	role, err := e.Roles.Create("test-role", []roles.Binding{
		{ConnectionID: connID, PolicyIDs: policyIDs},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	return role
}

// CreateToken creates a token for the given role and returns the plaintext.
func (e *Env) CreateToken(t *testing.T, roleID string) string {
	t.Helper()

	result, err := e.Tokens.Create(&tokens.CreateRequest{
		Name:   "test-token",
		RoleID: roleID,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	return result.PlaintextToken
}
