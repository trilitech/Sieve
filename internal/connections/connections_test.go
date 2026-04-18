package connections_test

import (
	"path/filepath"
	"testing"

	"github.com/murbard/Sieve/internal/connections"
	"github.com/murbard/Sieve/internal/connector"
	"github.com/murbard/Sieve/internal/database"
	"github.com/murbard/Sieve/internal/roles"
	"github.com/murbard/Sieve/internal/secrets"
	mockconn "github.com/murbard/Sieve/internal/testing/mockconnector"
)

// testKeyring builds a loaded Keyring for tests. Uses cheap argon2
// parameters so the suite stays fast.
func testKeyring(t *testing.T, db *database.DB) *secrets.Keyring {
	t.Helper()
	saved := secrets.DefaultArgon2Params
	secrets.DefaultArgon2Params = secrets.Argon2Params{Time: 1, Memory: 8, Threads: 1, KeyLen: 32}
	defer func() { secrets.DefaultArgon2Params = saved }()
	k := &secrets.Keyring{}
	if err := k.Setup(db.DB, []byte("test-passphrase")); err != nil {
		t.Fatalf("keyring setup: %v", err)
	}
	return k
}

func setup(t *testing.T) (*connections.Service, *mockconn.Mock) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	registry := connector.NewRegistry()
	mock := mockconn.New("mock")
	registry.Register(mock.Meta(), mock.Factory())

	return connections.NewService(db, registry, testKeyring(t, db)), mock
}

func TestAddAndGet(t *testing.T) {
	svc, _ := setup(t)

	err := svc.Add("my-conn", "mock", "My Connection", map[string]any{})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	conn, err := svc.Get("my-conn")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if conn.ID != "my-conn" {
		t.Fatalf("expected ID 'my-conn', got %q", conn.ID)
	}
	if conn.ConnectorType != "mock" {
		t.Fatalf("expected type 'mock', got %q", conn.ConnectorType)
	}
	if conn.DisplayName != "My Connection" {
		t.Fatalf("expected display name 'My Connection', got %q", conn.DisplayName)
	}
	// Get should not expose config.
	if conn.Config != nil {
		t.Fatalf("expected nil config from Get, got %v", conn.Config)
	}
}

func TestGetWithConfig(t *testing.T) {
	svc, _ := setup(t)

	err := svc.Add("cfg-conn", "mock", "Config Test", map[string]any{"secret": "s3cr3t"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	conn, err := svc.GetWithConfig("cfg-conn")
	if err != nil {
		t.Fatalf("get with config: %v", err)
	}
	if conn.Config == nil {
		t.Fatal("expected config to be populated")
	}
	if conn.Config["secret"] != "s3cr3t" {
		t.Fatalf("expected secret 's3cr3t', got %v", conn.Config["secret"])
	}
}

func TestAddUnknownType(t *testing.T) {
	svc, _ := setup(t)

	err := svc.Add("bad", "unknown-type", "Bad", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown connector type")
	}
}

func TestList(t *testing.T) {
	svc, _ := setup(t)

	for _, id := range []string{"a", "b", "c"} {
		if err := svc.Add(id, "mock", "Conn "+id, map[string]any{}); err != nil {
			t.Fatalf("add %s: %v", id, err)
		}
	}

	list, err := svc.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3, got %d", len(list))
	}
}

func TestRemove(t *testing.T) {
	svc, _ := setup(t)

	if err := svc.Add("del-me", "mock", "Delete Me", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}

	if err := svc.Remove("del-me"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	_, err := svc.Get("del-me")
	if err == nil {
		t.Fatal("expected error getting removed connection")
	}
}

func TestRemoveNonexistent(t *testing.T) {
	svc, _ := setup(t)

	err := svc.Remove("no-such-conn")
	if err == nil {
		t.Fatal("expected error removing nonexistent connection")
	}
}

func TestExists(t *testing.T) {
	svc, _ := setup(t)

	exists, err := svc.Exists("nope")
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if exists {
		t.Fatal("expected false for nonexistent connection")
	}

	if err := svc.Add("yes", "mock", "Yes", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}

	exists, err = svc.Exists("yes")
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if !exists {
		t.Fatal("expected true for existing connection")
	}
}

func TestUpdateConfig(t *testing.T) {
	svc, _ := setup(t)

	if err := svc.Add("upd", "mock", "Update Me", map[string]any{"a": "1"}); err != nil {
		t.Fatalf("add: %v", err)
	}

	newConfig := map[string]any{"a": "2", "b": "3"}
	if err := svc.UpdateConfig("upd", newConfig); err != nil {
		t.Fatalf("update config: %v", err)
	}

	conn, err := svc.GetWithConfig("upd")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if conn.Config["a"] != "2" {
		t.Fatalf("expected a=2, got %v", conn.Config["a"])
	}
	if conn.Config["b"] != "3" {
		t.Fatalf("expected b=3, got %v", conn.Config["b"])
	}
}

func TestGetConnector(t *testing.T) {
	svc, _ := setup(t)

	if err := svc.Add("live", "mock", "Live", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}

	conn, err := svc.GetConnector("live")
	if err != nil {
		t.Fatalf("get connector: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
	if conn.Type() != "mock" {
		t.Fatalf("expected type 'mock', got %q", conn.Type())
	}
}

func TestGetConnectorNonexistent(t *testing.T) {
	svc, _ := setup(t)

	_, err := svc.GetConnector("no-such")
	if err == nil {
		t.Fatal("expected error for nonexistent connection")
	}
}

func TestAddDuplicateConnectionID(t *testing.T) {
	svc, _ := setup(t)

	err := svc.Add("dup-conn", "mock", "First", map[string]any{})
	if err != nil {
		t.Fatalf("first add: %v", err)
	}

	err = svc.Add("dup-conn", "mock", "Second", map[string]any{})
	if err == nil {
		t.Fatal("expected error adding duplicate connection ID")
	}
}

func TestUpdateConfigNonexistent(t *testing.T) {
	svc, _ := setup(t)

	err := svc.UpdateConfig("no-such-conn", map[string]any{"key": "value"})
	if err == nil {
		t.Fatal("expected error updating config for nonexistent connection")
	}
}

// Story 6: Delete connection referenced by a role — GetConnector fails, role still exists with dangling binding.
func TestStory6_DeleteConnectionReferencedByRole(t *testing.T) {
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	registry := connector.NewRegistry()
	mock := mockconn.New("mock")
	registry.Register(mock.Meta(), mock.Factory())

	connSvc := connections.NewService(db, registry, testKeyring(t, db))
	roleSvc := roles.NewService(db)

	// Create a connection.
	if err := connSvc.Add("ref-conn", "mock", "Referenced Connection", map[string]any{}); err != nil {
		t.Fatalf("add connection: %v", err)
	}

	// Create a role that references this connection.
	role, err := roleSvc.Create("ref-role", []roles.Binding{
		{ConnectionID: "ref-conn", PolicyIDs: []string{"some-policy"}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	// Verify GetConnector works before deletion.
	_, err = connSvc.GetConnector("ref-conn")
	if err != nil {
		t.Fatalf("get connector before delete: %v", err)
	}

	// Delete the connection.
	if err := connSvc.Remove("ref-conn"); err != nil {
		t.Fatalf("remove connection: %v", err)
	}

	// GetConnector should now fail.
	_, err = connSvc.GetConnector("ref-conn")
	if err == nil {
		t.Fatal("story 6: GetConnector should fail after connection is deleted")
	}

	// The role should still exist with the dangling binding.
	got, err := roleSvc.Get(role.ID)
	if err != nil {
		t.Fatalf("story 6: role should still exist: %v", err)
	}
	if got.Name != "ref-role" {
		t.Fatalf("story 6: expected role name 'ref-role', got %q", got.Name)
	}
	if len(got.Bindings) != 1 {
		t.Fatalf("story 6: expected 1 binding (dangling), got %d", len(got.Bindings))
	}
	if got.Bindings[0].ConnectionID != "ref-conn" {
		t.Fatalf("story 6: expected dangling binding to 'ref-conn', got %q", got.Bindings[0].ConnectionID)
	}
}

// Story 254: Delete connection, verify live connector cache is cleared immediately.
func TestStory254_DeleteConnectionClearsCache(t *testing.T) {
	svc, _ := setup(t)

	// Add a connection and verify GetConnector works.
	if err := svc.Add("cache-conn", "mock", "Cache Test", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}
	conn, err := svc.GetConnector("cache-conn")
	if err != nil {
		t.Fatalf("get connector before delete: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}

	// Delete the connection.
	if err := svc.Remove("cache-conn"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	// GetConnector should fail immediately (cache cleared).
	_, err = svc.GetConnector("cache-conn")
	if err == nil {
		t.Fatal("story 254: GetConnector should fail immediately after delete — cache not cleared")
	}

	// Also verify Get (DB) fails.
	_, err = svc.Get("cache-conn")
	if err == nil {
		t.Fatal("story 254: Get should fail after delete")
	}
}

func TestInitAll(t *testing.T) {
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	registry := connector.NewRegistry()
	mock := mockconn.New("mock")
	registry.Register(mock.Meta(), mock.Factory())

	keyring := testKeyring(t, db)
	svc := connections.NewService(db, registry, keyring)

	// Add connections.
	for _, id := range []string{"a", "b"} {
		if err := svc.Add(id, "mock", "Conn "+id, map[string]any{}); err != nil {
			t.Fatalf("add %s: %v", id, err)
		}
	}

	// Create a fresh service (simulating restart) and init all. The keyring
	// stays loaded across "restart" since this simulates a running process
	// that reconstructed services after, e.g., reconfiguration.
	svc2 := connections.NewService(db, registry, keyring)
	if err := svc2.InitAll(); err != nil {
		t.Fatalf("init all: %v", err)
	}

	// Both connections should have live connectors.
	for _, id := range []string{"a", "b"} {
		conn, err := svc2.GetConnector(id)
		if err != nil {
			t.Fatalf("get connector %s: %v", id, err)
		}
		if conn == nil {
			t.Fatalf("expected non-nil connector for %s", id)
		}
	}
}
