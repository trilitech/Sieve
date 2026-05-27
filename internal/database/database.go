package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps a *sql.DB connection to the Sieve SQLite database.
type DB struct {
	*sql.DB
}

// New opens (or creates) the SQLite database at path, enables WAL mode and
// foreign keys, and runs schema migrations. The returned DB is ready for use.
func New(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Restrict DB file permissions to owner only.
	os.Chmod(path, 0600)

	// Enable WAL mode for better concurrent read performance.
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("enable WAL mode: %w", err)
	}

	// Enable foreign key enforcement (off by default in SQLite).
	if _, err := sqlDB.Exec("PRAGMA foreign_keys=ON"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	db := &DB{DB: sqlDB}

	if err := db.migrate(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return db, nil
}

// Close closes the underlying database connection.
func (db *DB) Close() error {
	return db.DB.Close()
}

// migrateNeedsReauthToStatus performs the spec 002 FR-001..FR-003
// unification in one pass:
//   - converges (needs_reauth=1, status='active') rows to
//     status='reauth_required' (preserving reauth_reason).
//   - drops the now-unused needs_reauth column.
//
// Both steps are skipped if the needs_reauth column has already been
// dropped (idempotent across restarts). Safe with keyring unloaded —
// touches no encrypted data.
//
// Sieve is pre-launch, so there is no deprecation window: the column
// goes away in the same migration that converts data. SQLite 3.35+
// supports native ALTER TABLE DROP COLUMN; the mattn/go-sqlite3 driver
// bundles a recent SQLite that supports this syntax.
func migrateNeedsReauthToStatus(db *DB) error {
	hasCol, err := columnExists(db, "connections", "needs_reauth")
	if err != nil {
		return fmt.Errorf("check needs_reauth column: %w", err)
	}
	if !hasCol {
		// Already migrated and dropped on a prior run.
		return nil
	}

	rows, err := db.Query(
		`SELECT id, reauth_reason FROM connections
		 WHERE needs_reauth = 1 AND status = 'active'`,
	)
	if err != nil {
		return fmt.Errorf("scan candidates: %w", err)
	}
	for rows.Next() {
		var id string
		var reason *string
		if scanErr := rows.Scan(&id, &reason); scanErr != nil {
			rows.Close()
			return fmt.Errorf("scan candidate row: %w", scanErr)
		}
		r := ""
		if reason != nil {
			r = *reason
		}
		log.Printf("migration status_migration: connection %q needs_reauth=1 → status=reauth_required (reason=%q)", id, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate candidates: %w", err)
	}
	if _, err := db.Exec(
		`UPDATE connections SET status = 'reauth_required'
		 WHERE needs_reauth = 1 AND status = 'active'`,
	); err != nil {
		return fmt.Errorf("transition rows: %w", err)
	}
	// Drop the column — no consumer reads it after FR-002.
	if _, err := db.Exec(`ALTER TABLE connections DROP COLUMN needs_reauth`); err != nil {
		return fmt.Errorf("drop needs_reauth column: %w", err)
	}
	log.Printf("migration status_migration: dropped connections.needs_reauth column")
	return nil
}

// columnExists reports whether the named column is present on the table.
// SQLite-only; uses PRAGMA table_info.
func columnExists(db *DB, table, column string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt *string
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			continue
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// migrate runs all schema migrations in order.
func (db *DB) migrate() error {
	const schema = `
	CREATE TABLE IF NOT EXISTS connections (
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
		reauth_reason     TEXT
	);

	CREATE TABLE IF NOT EXISTS crypto_meta (
		id            INTEGER PRIMARY KEY CHECK (id = 1),
		argon2_salt   BLOB NOT NULL,
		argon2_params TEXT NOT NULL,
		kek_check     BLOB NOT NULL
	);

	CREATE TABLE IF NOT EXISTS policies (
		id              TEXT PRIMARY KEY,
		name            TEXT NOT NULL UNIQUE,
		policy_type     TEXT NOT NULL,
		policy_config   TEXT NOT NULL,
		created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS roles (
		id              TEXT PRIMARY KEY,
		name            TEXT NOT NULL UNIQUE,
		bindings        TEXT NOT NULL,
		created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS tokens (
		id               TEXT PRIMARY KEY,
		name             TEXT NOT NULL UNIQUE,
		token_hash       TEXT NOT NULL,
		role_id          TEXT NOT NULL,
		created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at       DATETIME,
		revoked          INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS approval_queue (
		id            TEXT PRIMARY KEY,
		token_id      TEXT NOT NULL,
		connection_id TEXT NOT NULL,
		operation     TEXT NOT NULL,
		request_data  TEXT NOT NULL,
		status        TEXT NOT NULL DEFAULT 'pending',
		created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
		resolved_at   DATETIME,
		resolved_by   TEXT
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp         DATETIME DEFAULT CURRENT_TIMESTAMP,
		token_id          TEXT NOT NULL,
		token_name        TEXT NOT NULL,
		connection_id     TEXT NOT NULL,
		operation         TEXT NOT NULL,
		params            TEXT,
		policy_result     TEXT NOT NULL,
		response_summary  TEXT,
		duration_ms       INTEGER
	);
	`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("execute schema: %w", err)
	}

	// Migration: drop the old plaintext `config` column on the connections
	// table when present. Sieve is pre-launch; rather than convert plaintext
	// credentials in place (which would require the operator's passphrase
	// inside this migration), we drop the table and force the operator to
	// re-add connections under the encrypted schema. Documented in README
	// under setup.
	hasOldConfig, err := columnExists(db, "connections", "config")
	if err != nil {
		return fmt.Errorf("check connections schema: %w", err)
	}
	if hasOldConfig {
		if _, err := db.Exec(`DROP TABLE connections`); err != nil {
			return fmt.Errorf("drop legacy connections table: %w", err)
		}
		if _, err := db.Exec(`
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
				reauth_reason     TEXT
			);
		`); err != nil {
			return fmt.Errorf("recreate connections table: %w", err)
		}
	}

	// Migration: add `status` column to connections table for installs that
	// created the encrypted schema before status existed. Idempotent —
	// CREATE TABLE above handles fresh DBs; this ALTER handles in-flight
	// upgrades. Pre-existing rows take the DEFAULT 'active'.
	hasStatus, err := columnExists(db, "connections", "status")
	if err != nil {
		return fmt.Errorf("check connections.status: %w", err)
	}
	if !hasStatus {
		if _, err := db.Exec(`ALTER TABLE connections ADD COLUMN status TEXT NOT NULL DEFAULT 'active'`); err != nil {
			return fmt.Errorf("add connections.status column: %w", err)
		}
	}

	// Migration: add reauth_reason column for tracking why a connection
	// is in status='reauth_required'. (The legacy needs_reauth column was
	// removed in spec 002 — see migrateNeedsReauthToStatus below.)
	hasReason, err := columnExists(db, "connections", "reauth_reason")
	if err != nil {
		return fmt.Errorf("check connections.reauth_reason: %w", err)
	}
	if !hasReason {
		if _, err := db.Exec(`ALTER TABLE connections ADD COLUMN reauth_reason TEXT`); err != nil {
			return fmt.Errorf("add reauth_reason column: %w", err)
		}
	}

	// Migration: rename policy_id -> policy_ids (JSON array) if the old column exists.
	// SQLite doesn't support ALTER COLUMN, so we check if the old column exists
	// and add the new one if needed, copying data as a single-element JSON array.
	var hasOldColumn bool
	rows, err := db.Query("PRAGMA table_info(tokens)")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var cid int
			var name, typ string
			var notNull, pk int
			var dflt *string
			if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
				continue
			}
			if name == "policy_id" {
				hasOldColumn = true
			}
		}
	}

	// Migrate existing Gmail connections to the new "google" connector type.
	db.Exec(`UPDATE connections SET connector_type = 'google' WHERE connector_type = 'gmail'`)

	// FR-001/FR-003 one-time migration: converge rows where the legacy
	// needs_reauth=1 signal was set without the status column being
	// updated (PR #5 → PR #10 overlap window). After this migration, the
	// status column is the canonical lifecycle signal and needs_reauth is
	// no longer read by any production code path. Idempotent — a second
	// run finds zero matching rows. Safe with keyring unloaded — this is
	// a plaintext-column update only.
	if err := migrateNeedsReauthToStatus(db); err != nil {
		return fmt.Errorf("migrate needs_reauth → status: %w", err)
	}

	if hasOldColumn {
		// SQLite doesn't support DROP COLUMN in older versions, so we rebuild
		// the table to replace policy_id (TEXT) with policy_ids (JSON array).
		// Each step is checked — if any fails, the migration stops and the
		// error propagates so the database isn't left in an inconsistent state.
		steps := []string{
			`CREATE TABLE tokens_new (
				id               TEXT PRIMARY KEY,
				name             TEXT NOT NULL UNIQUE,
				token_hash       TEXT NOT NULL,
				connections      TEXT NOT NULL,
				policy_ids       TEXT NOT NULL,
				created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
				expires_at       DATETIME,
				revoked          INTEGER DEFAULT 0
			)`,
			`INSERT INTO tokens_new (id, name, token_hash, connections, policy_ids, created_at, expires_at, revoked)
				SELECT id, name, token_hash, connections, '["' || policy_id || '"]', created_at, expires_at, revoked FROM tokens`,
			`DROP TABLE tokens`,
			`ALTER TABLE tokens_new RENAME TO tokens`,
		}
		for _, stmt := range steps {
			if _, err := db.Exec(stmt); err != nil {
				return fmt.Errorf("migrate tokens table: %w", err)
			}
		}
	}

	// Migrate tokens from connections+policy_ids to role_id.
	// Check if the old columns exist.
	var hasConnectionsCol bool
	rows2, err := db.Query("PRAGMA table_info(tokens)")
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var cid int
			var colName, typ string
			var notNull, pk int
			var dflt *string
			if err := rows2.Scan(&cid, &colName, &typ, &notNull, &dflt, &pk); err != nil {
				continue
			}
			if colName == "connections" {
				hasConnectionsCol = true
			}
		}
	}

	if hasConnectionsCol {
		// For each existing token, create a role that bundles its connections
		// and policies, then rebuild the tokens table with role_id.
		tokenRows, err := db.Query(`SELECT id, name, connections, policy_ids FROM tokens`)
		if err == nil {
			defer tokenRows.Close()
			for tokenRows.Next() {
				var tokID, tokName, connsJSON, polsJSON string
				if err := tokenRows.Scan(&tokID, &tokName, &connsJSON, &polsJSON); err != nil {
					continue
				}
				var conns []string
				var pols []string
				json.Unmarshal([]byte(connsJSON), &conns)
				json.Unmarshal([]byte(polsJSON), &pols)

				// Build bindings: all connections get all policies (best we can do
				// since old model didn't have per-connection policy mapping).
				var bindings []map[string]any
				for _, c := range conns {
					bindings = append(bindings, map[string]any{
						"connection_id": c,
						"policy_ids":    pols,
					})
				}
				bindingsJSON, _ := json.Marshal(bindings)

				roleName := "auto-" + tokName
				roleID := fmt.Sprintf("role_%s", tokID[:8])
				db.Exec(`INSERT OR IGNORE INTO roles (id, name, bindings, created_at) VALUES (?, ?, ?, datetime('now'))`,
					roleID, roleName, string(bindingsJSON))
			}
		}

		// Rebuild tokens table with role_id instead of connections+policy_ids.
		steps := []string{
			`CREATE TABLE tokens_v3 (
				id               TEXT PRIMARY KEY,
				name             TEXT NOT NULL UNIQUE,
				token_hash       TEXT NOT NULL,
				role_id          TEXT NOT NULL,
				created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
				expires_at       DATETIME,
				revoked          INTEGER DEFAULT 0
			)`,
			`INSERT INTO tokens_v3 (id, name, token_hash, role_id, created_at, expires_at, revoked)
				SELECT t.id, t.name, t.token_hash,
					COALESCE((SELECT r.id FROM roles r WHERE r.name = 'auto-' || t.name LIMIT 1), ''),
					t.created_at, t.expires_at, t.revoked
				FROM tokens t`,
			`DROP TABLE tokens`,
			`ALTER TABLE tokens_v3 RENAME TO tokens`,
		}
		for _, stmt := range steps {
			if _, err := db.Exec(stmt); err != nil {
				return fmt.Errorf("migrate tokens to roles: %w", err)
			}
		}
	}

	return nil
}
