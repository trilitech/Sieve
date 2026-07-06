package database_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/database"
)

// TestNewSecuresDBFilePerms asserts the credential DB file is created 0600
// (owner-only) — SQLite would otherwise create it under the process umask
// (commonly 0644), leaving the encrypted config blobs + crypto_meta
// group/world-readable.
func TestNewSecuresDBFilePerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "perms.db")
	db, err := database.New(path)
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	defer db.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat db file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("db file permissions = %o, want 600", perm)
	}
}

func TestNewCreatesDB(t *testing.T) {
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	defer db.Close()

	// Verify tables exist by querying them.
	tables := []string{
		"connections", "roles", "tokens", "approval_queue", "audit_log", "crypto_meta",
		"iam_policies", "iam_filters", "iam_guardrails", "iam_transforms",
		"iam_role_groups", "iam_role_group_members",
		"operator_credential", "operator_session",
	}
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

// TestRejectsLegacySchema asserts the fresh-schema build refuses to open a
// database created by an older build (here: one carrying the legacy `policies`
// table) rather than silently mis-operating on it. Pre-alpha has no migration
// path — the remedy is to delete the DB file.
func TestRejectsLegacySchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")

	db1, err := database.New(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	// Introduce a legacy marker the guard looks for.
	if _, err := db1.Exec(`CREATE TABLE policies (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatalf("seed legacy table: %v", err)
	}
	db1.Close()

	if _, err := database.New(path); err == nil {
		t.Fatal("expected New to refuse a legacy-schema database, got nil error")
	}
}

// TestRejectsLegacyTokensRoleID guards the mixed-state case: a database from
// the base cutover build has tokens.role_id (NOT NULL) alongside role_ids. A
// role_ids-only check would let it through, and the first tokens.Create()
// would then fail on the NOT NULL role_id constraint. The guard must reject it.
func TestRejectsLegacyTokensRoleID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.db")

	db1, err := database.New(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	// Reintroduce the legacy single-role column the cutover schema carried.
	if _, err := db1.Exec(`ALTER TABLE tokens ADD COLUMN role_id TEXT NOT NULL DEFAULT ''`); err != nil {
		t.Fatalf("seed legacy role_id column: %v", err)
	}
	db1.Close()

	if _, err := database.New(path); err == nil {
		t.Fatal("expected New to refuse a tokens table carrying the legacy role_id column, got nil error")
	}
}
