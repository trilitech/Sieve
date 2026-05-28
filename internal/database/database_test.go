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

// TestMigrate_StatusColumn_FreshDB asserts the connections table is created
// with the `status` column on a fresh database and that the column has the
// expected DEFAULT 'active'.
func TestMigrate_StatusColumn_FreshDB(t *testing.T) {
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("PRAGMA table_info(connections)")
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()
	var found bool
	var dflt *string
	var notNull int
	for rows.Next() {
		var cid int
		var name, typ string
		var pk int
		var d *string
		if err := rows.Scan(&cid, &name, &typ, &notNull, &d, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == "status" {
			found = true
			dflt = d
			break
		}
	}
	if !found {
		t.Fatal("connections table should have status column on a fresh DB")
	}
	if dflt == nil || *dflt != "'active'" {
		t.Fatalf("expected DEFAULT 'active', got %v", dflt)
	}
}

// TestMigrate_StatusColumn_PreExistingRowsDefaultActive simulates an existing
// install whose connections table predates the status column: opens a DB and
// manually drops the column to mimic the pre-migration shape, inserts a row,
// reopens (which triggers the idempotent ALTER TABLE), and asserts the row
// has status='active' (existing connections migrate cleanly).
func TestMigrate_StatusColumn_PreExistingRowsDefaultActive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "preexisting.db")

	// First open: creates the table WITH status (since fresh DB).
	db1, err := database.New(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	// Mimic the pre-migration shape by rebuilding the table without status.
	steps := []string{
		`CREATE TABLE connections_old (
			id                TEXT PRIMARY KEY,
			connector_type    TEXT NOT NULL,
			display_name      TEXT NOT NULL,
			config_ciphertext BLOB NOT NULL,
			config_nonce      BLOB NOT NULL,
			dek_wrapped       BLOB NOT NULL,
			dek_nonce         BLOB NOT NULL,
			enc_version       INTEGER NOT NULL,
			created_at        DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO connections_old (id, connector_type, display_name,
			config_ciphertext, config_nonce, dek_wrapped, dek_nonce, enc_version)
			VALUES ('legacy', 'mock', 'Legacy', X'00', X'00', X'00', X'00', 1)`,
		`DROP TABLE connections`,
		`ALTER TABLE connections_old RENAME TO connections`,
	}
	for _, stmt := range steps {
		if _, err := db1.Exec(stmt); err != nil {
			t.Fatalf("rebuild legacy table (%q): %v", stmt, err)
		}
	}
	db1.Close()

	// Second open: should ALTER TABLE to add status with DEFAULT 'active',
	// and the legacy row should pick up the default.
	db2, err := database.New(path)
	if err != nil {
		t.Fatalf("second open (migration): %v", err)
	}
	defer db2.Close()

	var status string
	if err := db2.QueryRow(`SELECT status FROM connections WHERE id = 'legacy'`).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "active" {
		t.Fatalf("expected legacy row status='active', got %q", status)
	}

	// Migration must be idempotent: opening a third time should not fail.
	db2.Close()
	db3, err := database.New(path)
	if err != nil {
		t.Fatalf("third open (idempotency): %v", err)
	}
	db3.Close()
}
