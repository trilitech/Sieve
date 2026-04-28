package database_test

import (
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/database"
)

func TestNewCreatesDB(t *testing.T) {
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	defer db.Close()

	// Verify tables exist by querying them.
	tables := []string{"connections", "policies", "roles", "tokens", "approval_queue", "audit_log", "crypto_meta"}
	for _, table := range tables {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count)
		if err != nil {
			t.Fatalf("table %q should exist: %v", table, err)
		}
	}
}

func TestNewIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db1, err := database.New(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}

	// Insert data. Encrypted columns get filler bytes — this test only
	// exercises the schema and reopen behavior, not the encryption path.
	_, err = db1.Exec(`INSERT INTO connections (
		id, connector_type, display_name,
		config_ciphertext, config_nonce, dek_wrapped, dek_nonce, enc_version
	) VALUES ('c1', 'mock', 'Test', X'00', X'00', X'00', X'00', 1)`)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	db1.Close()

	// Reopen — should not wipe data.
	db2, err := database.New(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer db2.Close()

	var count int
	if err := db2.QueryRow("SELECT COUNT(*) FROM connections").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 connection after reopen, got %d", count)
	}
}

// Story 99: Create DB, insert data, close, reopen, verify data persists.
func TestStory99_DataPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "persist.db")

	// Open, insert data, close.
	db1, err := database.New(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	_, err = db1.Exec(
		`INSERT INTO connections (
			id, connector_type, display_name,
			config_ciphertext, config_nonce, dek_wrapped, dek_nonce, enc_version
		) VALUES ('persist-conn', 'mock', 'Persist Test', X'00', X'00', X'00', X'00', 1)`,
	)
	if err != nil {
		t.Fatalf("insert connection: %v", err)
	}
	_, err = db1.Exec(
		`INSERT INTO roles (id, name, bindings, created_at) VALUES ('persist-role', 'test-role', '[]', datetime('now'))`,
	)
	if err != nil {
		t.Fatalf("insert role: %v", err)
	}
	db1.Close()

	// Reopen and verify data persists.
	db2, err := database.New(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer db2.Close()

	var connCount int
	if err := db2.QueryRow("SELECT COUNT(*) FROM connections WHERE id = 'persist-conn'").Scan(&connCount); err != nil {
		t.Fatalf("count connections: %v", err)
	}
	if connCount != 1 {
		t.Fatalf("story 99: expected 1 connection after reopen, got %d", connCount)
	}

	var roleCount int
	if err := db2.QueryRow("SELECT COUNT(*) FROM roles WHERE id = 'persist-role'").Scan(&roleCount); err != nil {
		t.Fatalf("count roles: %v", err)
	}
	if roleCount != 1 {
		t.Fatalf("story 99: expected 1 role after reopen, got %d", roleCount)
	}

	// Verify the data is correct.
	var displayName string
	if err := db2.QueryRow("SELECT display_name FROM connections WHERE id = 'persist-conn'").Scan(&displayName); err != nil {
		t.Fatalf("query display name: %v", err)
	}
	if displayName != "Persist Test" {
		t.Fatalf("story 99: expected display_name 'Persist Test', got %q", displayName)
	}
}

func TestWALMode(t *testing.T) {
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("query journal mode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("expected WAL mode, got %q", mode)
	}
}

func TestForeignKeys(t *testing.T) {
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var fk int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatalf("query foreign keys: %v", err)
	}
	if fk != 1 {
		t.Fatalf("expected foreign_keys=1, got %d", fk)
	}
}
