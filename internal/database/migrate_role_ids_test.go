package database_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/database"
)

// TestMigrate_RoleIDsAfterLegacyTokenRebuild is the regression test for the P1
// migration-ordering bug: the tokens.role_ids add + `json_array(role_id)` backfill
// used to run BEFORE the legacy token rebuilds that create `role_id`, so opening a
// database on the legacy schema aborted startup with "no such column: role_id"
// (and the later rebuild silently dropped role_ids anyway). The add+backfill now
// runs AFTER those rebuilds.
func TestMigrate_RoleIDsAfterLegacyTokenRebuild(t *testing.T) {
	// The full legacy schema (connections + policy_id) is what triggers the
	// tokens_v3 rebuild that creates role_id. Opening it must NOT abort.
	t.Run("legacy connections+policy_id schema migrates without aborting", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "legacy.db")
		raw, err := sql.Open("sqlite3", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(`CREATE TABLE tokens (
			id           TEXT PRIMARY KEY,
			name         TEXT NOT NULL UNIQUE,
			token_hash   TEXT NOT NULL,
			connections  TEXT NOT NULL,
			policy_id    TEXT NOT NULL,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at   DATETIME,
			revoked      INTEGER DEFAULT 0
		)`); err != nil {
			t.Fatal(err)
		}
		// A realistic 16-hex token id: the legacy connections+policy_id→role rebuild
		// derives a role id from tokID[:8], so the id must be >= 8 chars (real token
		// ids are always 16 hex).
		if _, err := raw.Exec(`INSERT INTO tokens (id, name, token_hash, connections, policy_id, revoked)
			VALUES ('aabbccddeeff0011', 'tok1', 'h', '["c1"]', 'p1', 0)`); err != nil {
			t.Fatal(err)
		}
		raw.Close()

		db, err := database.New(path) // runs migrate() — must not abort on role_id
		if err != nil {
			t.Fatalf("migrate legacy tokens schema aborted startup: %v", err)
		}
		defer db.Close()

		cols := tableColumns(t, db, "tokens")
		for _, c := range []string{"role_id", "role_ids"} {
			if _, ok := cols[c]; !ok {
				t.Errorf("tokens.%s missing after migrate", c)
			}
		}
	})

	// A v2 database (already has role_id, lacks role_ids) exercises the add +
	// backfill directly: role_ids must be populated from role_id.
	t.Run("role_ids is backfilled from role_id", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "v2.db")
		raw, err := sql.Open("sqlite3", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(`CREATE TABLE tokens (
			id           TEXT PRIMARY KEY,
			name         TEXT NOT NULL UNIQUE,
			token_hash   TEXT NOT NULL,
			role_id      TEXT NOT NULL,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at   DATETIME,
			revoked      INTEGER DEFAULT 0
		)`); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(`INSERT INTO tokens (id, name, token_hash, role_id, revoked)
			VALUES ('t1', 'tok1', 'h', 'r1', 0)`); err != nil {
			t.Fatal(err)
		}
		raw.Close()

		db, err := database.New(path)
		if err != nil {
			t.Fatalf("migrate v2 tokens schema: %v", err)
		}
		defer db.Close()

		var roleIDs string
		if err := db.QueryRow(`SELECT role_ids FROM tokens WHERE id = 't1'`).Scan(&roleIDs); err != nil {
			t.Fatal(err)
		}
		if roleIDs != `["r1"]` {
			t.Errorf("role_ids backfill = %q, want [\"r1\"]", roleIDs)
		}
	})
}
