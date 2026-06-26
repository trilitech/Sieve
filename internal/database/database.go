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

// migrateNeedsReauthToStatus performs the needs_reauth → status
// unification in one pass:
// - converges (needs_reauth=1, status='active') rows to
// status='reauth_required' (preserving reauth_reason).
// - drops the now-unused needs_reauth column.
// Both steps are skipped if the needs_reauth column has already been
// dropped (idempotent across restarts). Safe with keyring unloaded —
// touches no encrypted data.
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
	// Drop the column — no consumer reads it after this migration.
	if _, err := db.Exec(`ALTER TABLE connections DROP COLUMN needs_reauth`); err != nil {
		return fmt.Errorf("drop needs_reauth column: %w", err)
	}
	log.Printf("migration status_migration: dropped connections.needs_reauth column")
	return nil
}

// addColumnIfMissing runs the supplied ALTER TABLE if the column is not
// already present. Lets the security-fixes migration stay idempotent without
// duplicating the columnExists boilerplate at every call site.
func addColumnIfMissing(db *DB, table, column, alterSQL string) error {
	has, err := columnExists(db, table, column)
	if err != nil {
		return fmt.Errorf("check %s.%s: %w", table, column, err)
	}
	if has {
		return nil
	}
	if _, err := db.Exec(alterSQL); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
}

// dropColumnIfPresent runs ALTER TABLE... DROP COLUMN when the column
// exists. SQLite 3.35+ supports DROP COLUMN natively; this project's
// modern-go-sqlite driver bundles a sufficiently recent SQLite. The drop
// is idempotent — fresh databases never have the column and skip the
// statement; databases that had it earlier (the security-fixes draft
// landed a dead `outbound_allowlist` column) get it removed.
func dropColumnIfPresent(db *DB, table, column string) error {
	has, err := columnExists(db, table, column)
	if err != nil {
		return fmt.Errorf("check %s.%s: %w", table, column, err)
	}
	if !has {
		return nil
	}
	if _, err := db.Exec(fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", table, column)); err != nil {
		return fmt.Errorf("drop %s.%s: %w", table, column, err)
	}
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
		role_ids         TEXT NOT NULL DEFAULT '[]',
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

	-- IAM (internal/iam) — additive, coexists with legacy policies/roles while
	-- iam_enabled is off. See docs/architecture/iam/. The connections + tokens
	-- tables are untouched (credentials preserved). Roles reuse the existing
	-- roles table for identity (id, name); iam_role_groups add the principal
	-- grouping the IAM model uses.
	CREATE TABLE IF NOT EXISTS iam_policies (
		id           TEXT PRIMARY KEY,
		name         TEXT NOT NULL UNIQUE,
		description  TEXT NOT NULL DEFAULT '',
		cedar_text   TEXT NOT NULL,
		spec_json    TEXT NOT NULL DEFAULT '',
		enabled      INTEGER NOT NULL DEFAULT 1,
		created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS iam_filters (
		id           TEXT PRIMARY KEY,
		name         TEXT NOT NULL UNIQUE,
		description  TEXT NOT NULL DEFAULT '',
		kind         TEXT NOT NULL,
		sort_order   INTEGER NOT NULL DEFAULT 0,
		config       TEXT NOT NULL DEFAULT '{}',
		created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS iam_guardrails (
		id           TEXT PRIMARY KEY,
		name         TEXT NOT NULL UNIQUE,
		description  TEXT NOT NULL DEFAULT '',
		cedar_text   TEXT NOT NULL,
		spec_json    TEXT NOT NULL DEFAULT '',
		enabled      INTEGER NOT NULL DEFAULT 1,
		created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- A scoped Transform (spec §7): a permit-only Cedar overlay carrying an INLINE
	-- response transform (@transform_kind/@transform_config/@transform_rank), scoped
	-- global or to a role. The self-contained successor to the guardrail+filter-
	-- library split (a transform IS a scoped object, no attach-from-library step).
	CREATE TABLE IF NOT EXISTS iam_transforms (
		id           TEXT PRIMARY KEY,
		name         TEXT NOT NULL UNIQUE,
		description  TEXT NOT NULL DEFAULT '',
		cedar_text   TEXT NOT NULL,
		spec_json    TEXT NOT NULL DEFAULT '',
		enabled      INTEGER NOT NULL DEFAULT 1,
		created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS iam_role_groups (
		id           TEXT PRIMARY KEY,
		name         TEXT NOT NULL UNIQUE,
		created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS iam_role_group_members (
		group_id     TEXT NOT NULL,
		role_id      TEXT NOT NULL,
		PRIMARY KEY (group_id, role_id)
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
	// is in status='reauth_required'. (The legacy needs_reauth column is
	// dropped by migrateNeedsReauthToStatus below.)
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

	// One-time migration: converge rows where the legacy needs_reauth=1
	// signal was set without the status column being updated. After this
	// migration, the status column is the canonical lifecycle signal and
	// needs_reauth is no longer read by any production code path.
	// Idempotent — a second run finds zero matching rows. Safe with
	// keyring unloaded — this is a plaintext-column update only.
	if err := migrateNeedsReauthToStatus(db); err != nil {
		return fmt.Errorf("migrate needs_reauth → status: %w", err)
	}

	// iam_policies.spec_json stores the structured builder rule (for edit-in-place
	// reload) alongside the compiled Cedar. Additive; older IAM DBs get it here.
	if err := addColumnIfMissing(db, "iam_policies", "spec_json",
		`ALTER TABLE iam_policies ADD COLUMN spec_json TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("add iam_policies.spec_json: %w", err)
	}

	// tokens.role_ids: a token is now assigned a SET of roles (RBAC, spec §5.1).
	// Additive; backfill the JSON array from the legacy single role_id so existing
	// tokens keep working (the IAM engine composes the union of role_ids).
	if err := addColumnIfMissing(db, "tokens", "role_ids",
		`ALTER TABLE tokens ADD COLUMN role_ids TEXT NOT NULL DEFAULT '[]'`); err != nil {
		return fmt.Errorf("add tokens.role_ids: %w", err)
	}
	if _, err := db.Exec(
		`UPDATE tokens SET role_ids = json_array(role_id)
		 WHERE (role_ids IS NULL OR role_ids = '' OR role_ids = '[]') AND role_id != ''`,
	); err != nil {
		return fmt.Errorf("backfill tokens.role_ids: %w", err)
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

	// Security-hardening migration.
	// Additive steps:
	//   - operator_credential (singleton row holding Argon2id verifier + display name)
	//   - operator_session (one row per active admin browser session)
	//   - audit_log.actor_kind, audit_log.operator_display_name
	//   - policies.lint_ack (sticky numeric-ceiling lint acknowledgement)
	// Destructive step (idempotent):
	//   - connections.outbound_allowlist DROP COLUMN — see dropColumnIfPresent
	//     call below. Safe because the column was never read or written by
	//     any code path; the live SSRF allowlist sits inside the envelope-
	//     encrypted config blob (see internal/connectors/{http,mcp}proxy and
	//     internal/connectors/slack). Dropping it removes a misleading
	//     plaintext shadow that an operator could think was authoritative,
	//     and prevents a future PR from wiring reads to it and silently
	//     bypassing the encrypted source of truth. New databases never see
	//     the column; the DROP is a no-op when the column is absent.
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS operator_credential (
			id                  INTEGER PRIMARY KEY CHECK (id = 1),
			display_name        TEXT    NOT NULL,
			argon2_salt         BLOB    NOT NULL,
			argon2_time         INTEGER NOT NULL,
			argon2_memory_kib   INTEGER NOT NULL,
			argon2_parallelism  INTEGER NOT NULL,
			verifier            BLOB    NOT NULL,
			created_at          TEXT    NOT NULL,
			updated_at          TEXT    NOT NULL
		);
		CREATE TABLE IF NOT EXISTS operator_session (
			id              TEXT PRIMARY KEY,
			created_at      TEXT NOT NULL,
			last_seen_at    TEXT NOT NULL,
			expires_at      TEXT NOT NULL,
			csrf_token_hash BLOB NOT NULL,
			ip              TEXT NOT NULL,
			user_agent      TEXT NOT NULL
		);
	`); err != nil {
		return fmt.Errorf("create operator_credential/operator_session: %w", err)
	}
	if err := addColumnIfMissing(db, "audit_log", "actor_kind",
		`ALTER TABLE audit_log ADD COLUMN actor_kind TEXT NOT NULL DEFAULT 'agent'`); err != nil {
		return err
	}
	if err := addColumnIfMissing(db, "audit_log", "operator_display_name",
		`ALTER TABLE audit_log ADD COLUMN operator_display_name TEXT`); err != nil {
		return err
	}
	if err := addColumnIfMissing(db, "policies", "lint_ack",
		`ALTER TABLE policies ADD COLUMN lint_ack TEXT NOT NULL DEFAULT '{}'`); err != nil {
		return err
	}
	// connections.outbound_allowlist was added in an earlier draft of this
	// migration but never read or written by any code path — the live
	// allowlist is carried inside the encrypted config blob. Drop the dead
	// column on existing dev databases so an operator who tightens it via
	// direct SQL doesn't believe it took effect (it wouldn't), and so a
	// future PR can't accidentally wire reads to the plaintext column and
	// silently bypass the encrypted source of truth. New databases never
	// see the column; this drop is idempotent.
	if err := dropColumnIfPresent(db, "connections", "outbound_allowlist"); err != nil {
		return err
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
