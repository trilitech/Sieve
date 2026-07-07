package database_test

import (
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/database"
)

// TestSecurityFixesMigration asserts that the 2026-05-22 security-fixes
// migration (operator_credential / operator_session tables, audit
// actor_kind + operator_display_name columns) has been applied to a
// freshly-created database. Spec anchor: data-model.md. Pre-fix: this
// test fails because the new tables and columns don't exist. Post-fix:
// it passes against any database opened by database.New.
func TestSecurityFixesMigration(t *testing.T) {
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	defer db.Close()

	t.Run("operator_credential table exists with required columns", func(t *testing.T) {
		cols := tableColumns(t, db, "operator_credential")
		for _, col := range []string{
			"id", "display_name",
			"argon2_salt", "argon2_time", "argon2_memory_kib", "argon2_parallelism",
			"verifier",
			"created_at", "updated_at",
		} {
			if _, ok := cols[col]; !ok {
				t.Errorf("operator_credential.%s missing", col)
			}
		}
	})

	t.Run("operator_session table exists with required columns", func(t *testing.T) {
		cols := tableColumns(t, db, "operator_session")
		for _, col := range []string{
			"id", "created_at", "last_seen_at", "expires_at",
			"csrf_token_hash", "ip", "user_agent",
		} {
			if _, ok := cols[col]; !ok {
				t.Errorf("operator_session.%s missing", col)
			}
		}
	})

	t.Run("audit_log gains actor_kind and operator_display_name", func(t *testing.T) {
		cols := tableColumns(t, db, "audit_log")
		if _, ok := cols["actor_kind"]; !ok {
			t.Errorf("audit_log.actor_kind missing")
		}
		if _, ok := cols["operator_display_name"]; !ok {
			t.Errorf("audit_log.operator_display_name missing")
		}
	})

	t.Run("connections does NOT carry outbound_allowlist column", func(t *testing.T) {
		// The per-connection SSRF allowlist lives inside the envelope-
		// encrypted config blob, NOT in a plaintext column. The earlier
		// draft of this migration added a dead `outbound_allowlist` column
		// that no production code read or wrote — its presence misled
		// operators into thinking direct-SQL tweaks were taking effect.
		// The migration now drops it; a fresh database never had it.
		cols := tableColumns(t, db, "connections")
		if _, ok := cols["outbound_allowlist"]; ok {
			t.Errorf("connections.outbound_allowlist should not be present (lives in encrypted config blob)")
		}
	})

	t.Run("operator_credential is a singleton (CHECK id = 1)", func(t *testing.T) {
		// Insert one row at id=1 to confirm CHECK allows it.
		_, err := db.Exec(`INSERT INTO operator_credential
			(id, display_name, argon2_salt, argon2_time, argon2_memory_kib, argon2_parallelism, verifier, created_at, updated_at)
			VALUES (1, 'test', X'00', 1, 16384, 1, X'00', datetime('now'), datetime('now'))`)
		if err != nil {
			t.Fatalf("insert id=1 should succeed: %v", err)
		}
		// Insert one row at id=2 must fail.
		_, err = db.Exec(`INSERT INTO operator_credential
			(id, display_name, argon2_salt, argon2_time, argon2_memory_kib, argon2_parallelism, verifier, created_at, updated_at)
			VALUES (2, 'other', X'00', 1, 16384, 1, X'00', datetime('now'), datetime('now'))`)
		if err == nil {
			t.Fatalf("insert id=2 should violate singleton CHECK")
		}
	})

	t.Run("audit_log.actor_kind defaults to 'agent' (existing rows)", func(t *testing.T) {
		_, err := db.Exec(`INSERT INTO audit_log (token_id, token_name, connection_id, operation, policy_result)
			VALUES ('t1', 'name', 'c1', 'op', 'allow')`)
		if err != nil {
			t.Fatalf("insert audit row: %v", err)
		}
		var kind string
		err = db.QueryRow(`SELECT actor_kind FROM audit_log WHERE token_id = 't1'`).Scan(&kind)
		if err != nil {
			t.Fatalf("select actor_kind: %v", err)
		}
		if kind != "agent" {
			t.Errorf("actor_kind default = %q, want %q", kind, "agent")
		}
	})
}

// tableColumns returns the column set for a table. Helper for migration tests.
func tableColumns(t *testing.T, db *database.DB, table string) map[string]struct{} {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("PRAGMA table_info(%s): %v", table, err)
	}
	defer rows.Close()
	cols := make(map[string]struct{})
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt *string
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		cols[name] = struct{}{}
	}
	return cols
}
