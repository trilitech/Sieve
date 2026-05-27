package database

// Regression test for the spec 002 FR-001..FR-003 migration: converges
// legacy (needs_reauth=1, status='active') rows to status='reauth_required'
// and then drops the needs_reauth column entirely (pre-launch, no
// deprecation window).
//
// To exercise the migration realistically, the test stands up a raw
// SQLite DB with the *old* schema shape (needs_reauth column present
// + populated), then calls migrateNeedsReauthToStatus directly.

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// newLegacyDB creates a SQLite file with the pre-spec-002 connections
// schema (needs_reauth column present). The caller seeds rows and then
// calls migrateNeedsReauthToStatus to observe convergence + drop.
func newLegacyDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	sqlDB, err := sql.Open("sqlite3", filepath.Join(dir, "legacy.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	if _, err := sqlDB.Exec(`
		CREATE TABLE connections (
			id                TEXT PRIMARY KEY,
			connector_type    TEXT NOT NULL,
			display_name      TEXT NOT NULL,
			config_ciphertext BLOB NOT NULL,
			config_nonce      BLOB NOT NULL,
			dek_wrapped       BLOB NOT NULL,
			dek_nonce         BLOB NOT NULL,
			enc_version       INTEGER NOT NULL,
			status            TEXT NOT NULL DEFAULT 'active',
			created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
			needs_reauth      INTEGER NOT NULL DEFAULT 0,
			reauth_reason     TEXT
		)
	`); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	return &DB{DB: sqlDB}
}

// seedLegacy inserts a row carrying the legacy two-column shape.
func seedLegacy(t *testing.T, db *DB, id, status string, needsReauth int, reason string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO connections (
			id, connector_type, display_name,
			config_ciphertext, config_nonce,
			dek_wrapped, dek_nonce, enc_version,
			status, created_at, needs_reauth, reauth_reason
		) VALUES (?, 'mock', 'm', x'', x'', x'', x'', 1, ?, datetime('now'), ?, ?)`,
		id, status, needsReauth, reason,
	)
	if err != nil {
		t.Fatalf("seed %q: %v", id, err)
	}
}

// readStatus returns (status, reauth_reason) for a row.
func readStatus(t *testing.T, db *DB, id string) (string, string) {
	t.Helper()
	var status string
	var reason *string
	if err := db.QueryRow(
		`SELECT status, reauth_reason FROM connections WHERE id = ?`, id,
	).Scan(&status, &reason); err != nil {
		t.Fatalf("read %q: %v", id, err)
	}
	if reason == nil {
		return status, ""
	}
	return status, *reason
}

// TestMigrateNeedsReauthToStatus_ConvergesDualSignal: a row seeded with
// (needs_reauth=1, status='active') becomes status='reauth_required'
// with the reauth_reason preserved verbatim.
func TestMigrateNeedsReauthToStatus_ConvergesDualSignal(t *testing.T) {
	db := newLegacyDB(t)
	seedLegacy(t, db, "legacy", "active", 1, "refresh failed: invalid_grant")

	if err := migrateNeedsReauthToStatus(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	status, reason := readStatus(t, db, "legacy")
	if status != "reauth_required" {
		t.Fatalf("status: got %q, want reauth_required", status)
	}
	if reason != "refresh failed: invalid_grant" {
		t.Fatalf("reason: got %q, want preserved", reason)
	}
}

// TestMigrateNeedsReauthToStatus_LeavesActiveRowsAlone: a row with
// needs_reauth=0 and status='active' is untouched by the migration.
func TestMigrateNeedsReauthToStatus_LeavesActiveRowsAlone(t *testing.T) {
	db := newLegacyDB(t)
	seedLegacy(t, db, "healthy", "active", 0, "")

	if err := migrateNeedsReauthToStatus(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	status, _ := readStatus(t, db, "healthy")
	if status != "active" {
		t.Fatalf("status: got %q, want active (untouched)", status)
	}
}

// TestMigrateNeedsReauthToStatus_LeavesAlreadyReauthRowsAlone: a row
// already at status='reauth_required' (e.g., from the FR-016 force-
// transition path before the unification) is left as-is.
func TestMigrateNeedsReauthToStatus_LeavesAlreadyReauthRowsAlone(t *testing.T) {
	db := newLegacyDB(t)
	seedLegacy(t, db, "already", "reauth_required", 0, "persist failed")

	if err := migrateNeedsReauthToStatus(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	status, reason := readStatus(t, db, "already")
	if status != "reauth_required" {
		t.Fatalf("status: got %q, want reauth_required (untouched)", status)
	}
	if reason != "persist failed" {
		t.Fatalf("reason: got %q, want preserved", reason)
	}
}

// TestMigrateNeedsReauthToStatus_DropsColumn: after the migration runs,
// the needs_reauth column MUST be gone (clean drop, no deprecation
// window per the pre-launch policy).
func TestMigrateNeedsReauthToStatus_DropsColumn(t *testing.T) {
	db := newLegacyDB(t)
	seedLegacy(t, db, "x", "active", 1, "first")

	if err := migrateNeedsReauthToStatus(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	hasCol, err := columnExists(db, "connections", "needs_reauth")
	if err != nil {
		t.Fatalf("columnExists: %v", err)
	}
	if hasCol {
		t.Fatal("needs_reauth column should be dropped after migration")
	}
}

// TestMigrateNeedsReauthToStatus_Idempotent: a second call after the
// column has been dropped is a clean no-op.
func TestMigrateNeedsReauthToStatus_Idempotent(t *testing.T) {
	db := newLegacyDB(t)
	seedLegacy(t, db, "x", "active", 1, "first")

	if err := migrateNeedsReauthToStatus(db); err != nil {
		t.Fatalf("migrate 1: %v", err)
	}
	// Second call: column is gone — must short-circuit cleanly.
	if err := migrateNeedsReauthToStatus(db); err != nil {
		t.Fatalf("migrate 2: %v", err)
	}
	status, reason := readStatus(t, db, "x")
	if status != "reauth_required" {
		t.Fatalf("status drifted across runs: %q", status)
	}
	if reason != "first" {
		t.Fatalf("reason drifted across runs: %q", reason)
	}
}
