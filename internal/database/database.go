package database

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps a *sql.DB connection to the Sieve SQLite database.
type DB struct {
	*sql.DB
}

// New opens (or creates) the SQLite database at path, enables WAL mode and
// foreign keys, and creates the schema. The returned DB is ready for use.
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

// migrate creates the canonical schema.
//
// Sieve is pre-alpha with no released builds and no databases to preserve, so
// there is no incremental migration path: the schema below is the single source
// of truth, applied with CREATE TABLE IF NOT EXISTS. A database created by an
// older build has an incompatible shape (legacy policy store, plaintext
// connection config, single-role tokens); rather than silently mis-operate on
// it, rejectLegacySchema detects it and refuses to start with a clear message.
// The fix is to delete data/sieve.db and re-add connections under this schema.
func (db *DB) migrate() error {
	if err := db.rejectLegacySchema(); err != nil {
		return err
	}

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

	-- A role is a named identity (id, name) plus its connection bindings. Rules,
	-- guardrails, and transforms scope to a role by referencing its id in Cedar;
	-- a token references a SET of roles (see tokens.role_ids).
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
		id                    INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp             DATETIME DEFAULT CURRENT_TIMESTAMP,
		token_id              TEXT NOT NULL,
		token_name            TEXT NOT NULL,
		connection_id         TEXT NOT NULL,
		operation             TEXT NOT NULL,
		params                TEXT,
		policy_result         TEXT NOT NULL,
		response_summary      TEXT,
		duration_ms           INTEGER,
		actor_kind            TEXT NOT NULL DEFAULT 'agent',
		operator_display_name TEXT
	);

	-- IAM (internal/iam). A rule (iam_policies) and a guardrail (iam_guardrails)
	-- each store compiled Cedar plus the declarative builder spec (for edit-in-
	-- place reload). A transform ATTACHMENT (iam_transforms) is a permit-only
	-- Cedar overlay that references a reusable transform DEFINITION (an
	-- iam_filters row) by name via @filters, scoped global or to a role — the
	-- same definition can be attached many times, so its name is NOT unique on
	-- iam_transforms (rows are addressed by id). See docs/architecture/iam/.
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

	CREATE TABLE IF NOT EXISTS iam_transforms (
		id           TEXT PRIMARY KEY,
		name         TEXT NOT NULL,
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

	-- Admin (human) auth: a singleton operator credential (Argon2id verifier)
	-- and one row per active admin browser session.
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
	`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("execute schema: %w", err)
	}
	return nil
}

// rejectLegacySchema refuses to start on a database created by a pre-fresh-
// schema build. Markers of an old shape: the legacy `policies` policy store, a
// plaintext `connections.config` column (pre-envelope-encryption), or a
// single-role `tokens` table lacking `role_ids`. Pre-alpha has no data to
// preserve, so the remedy is to delete the DB file and start clean.
func (db *DB) rejectLegacySchema() error {
	const remedy = "this build uses a fresh, non-migratable schema (pre-alpha); back up and delete the SQLite DB file (default ./data/sieve.db), then restart"

	if ok, err := tableExists(db, "policies"); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("incompatible database: legacy `policies` table present — %s", remedy)
	}
	if ok, err := columnExists(db, "connections", "config"); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("incompatible database: plaintext `connections.config` column present — %s", remedy)
	}
	// A tokens table that exists but predates role_ids is the single-role legacy shape.
	if ok, err := tableExists(db, "tokens"); err != nil {
		return err
	} else if ok {
		if has, err := columnExists(db, "tokens", "role_ids"); err != nil {
			return err
		} else if !has {
			return fmt.Errorf("incompatible database: legacy single-role `tokens` table (no role_ids) — %s", remedy)
		}
	}
	return nil
}

// tableExists reports whether a table of the given name exists.
func tableExists(db *DB, table string) (bool, error) {
	var name string
	err := db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table,
	).Scan(&name)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check table %q: %w", table, err)
	}
	return true, nil
}

// columnExists reports whether a column is present on a table (false if the
// table itself doesn't exist).
func columnExists(db *DB, table, column string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, fmt.Errorf("inspect %q: %w", table, err)
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
