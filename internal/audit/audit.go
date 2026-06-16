package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/trilitech/Sieve/internal/database"
)

// Entry represents a single row in the audit_log table.
type Entry struct {
	ID              int64     `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	TokenID         string    `json:"token_id"`
	TokenName       string    `json:"token_name"`
	ConnectionID    string    `json:"connection_id"`
	Operation       string    `json:"operation"`
	Params          string    `json:"params,omitempty"`
	PolicyResult    string    `json:"policy_result"`
	ResponseSummary string    `json:"response_summary,omitempty"`
	DurationMs      int64     `json:"duration_ms"`

	// Actor attribution: every admin mutation produces a row
	// identifying the operator. Agent rows keep actor_kind="agent" +
	// empty OperatorDisplayName; operator rows set actor_kind="operator"
	// and populate the display name captured at credential setup
	// (operator.Service.DisplayName).
	ActorKind           string `json:"actor_kind,omitempty"`
	OperatorDisplayName string `json:"operator_display_name,omitempty"`
}

// LogRequest contains the fields needed to create an audit log entry.
type LogRequest struct {
	TokenID         string
	TokenName       string
	ConnectionID    string
	Operation       string
	Params          map[string]any
	PolicyResult    string
	ResponseSummary string
	DurationMs      int64

	// ActorKind / OperatorDisplayName populate the columns added by
	// the 2026-05-22 security-fixes migration. Leaving them empty
	// preserves the legacy "agent" default for all existing producers.
	ActorKind           string
	OperatorDisplayName string
}

// ListFilter specifies optional filters for querying the audit log.
type ListFilter struct {
	TokenID      string
	ConnectionID string
	Operation    string
	After        *time.Time
	Before       *time.Time
	Limit        int
	Offset       int
}

// Logger provides methods for writing to and querying the audit log.
type Logger struct {
	db *database.DB
}

// NewLogger creates a new Logger backed by the given database.
func NewLogger(db *database.DB) *Logger {
	return &Logger{db: db}
}

// execer is the subset of *sql.DB / *sql.Tx that audit log inserts use.
// Both *sql.DB and *sql.Tx satisfy it — Log uses the embedded *sql.DB
// while LogTx uses an externally-managed *sql.Tx so the audit row commits
// or rolls back atomically with the caller's other writes (e.g., a
// passphrase rotation).
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// doInsert is the shared insert path used by both Log and LogTx.
func (l *Logger) doInsert(e execer, req *LogRequest) error {
	var paramsJSON sql.NullString
	if req.Params != nil {
		b, err := json.Marshal(req.Params)
		if err != nil {
			return fmt.Errorf("marshal params: %w", err)
		}
		paramsJSON = sql.NullString{String: string(b), Valid: true}
	}

	respSummary := sql.NullString{String: req.ResponseSummary, Valid: req.ResponseSummary != ""}

	actorKind := req.ActorKind
	if actorKind == "" {
		actorKind = "agent" // legacy default; matches the migration column default
	}
	opName := sql.NullString{String: req.OperatorDisplayName, Valid: req.OperatorDisplayName != ""}

	_, err := e.Exec(`
		INSERT INTO audit_log (token_id, token_name, connection_id, operation, params, policy_result, response_summary, duration_ms, actor_kind, operator_display_name)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.TokenID,
		req.TokenName,
		req.ConnectionID,
		req.Operation,
		paramsJSON,
		req.PolicyResult,
		respSummary,
		req.DurationMs,
		actorKind,
		opName,
	)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

// Log inserts a new entry into the audit log using a fresh implicit
// transaction.
func (l *Logger) Log(req *LogRequest) error {
	return l.doInsert(l.db, req)
}

// LogTx inserts a new entry into the audit log using the supplied
// transaction. Used when the audit row must commit or rollback atomically
// with other writes — e.g., the keyring.rotate row written inside the
// rotation transaction in secrets.Keyring.Rotate.
func (l *Logger) LogTx(tx *sql.Tx, req *LogRequest) error {
	return l.doInsert(tx, req)
}

// RotationAuditor adapts a Logger to the secrets.RotationAuditor interface
// so that secrets.Keyring.Rotate can write its audit row inside the
// rotation transaction without internal/secrets importing internal/audit.
// The surface ("ui" or "cli") is recorded on every successful rotation row
// so audit consumers can distinguish operator-initiated UI rotations from
// scripted CLI rotations.
type RotationAuditor struct {
	logger  *Logger
	surface string
}

// AsRotationAuditor returns an adapter satisfying the
// secrets.RotationAuditor interface (declared in internal/secrets) via
// Go's structural typing — internal/audit does not import internal/secrets.
func (l *Logger) AsRotationAuditor(surface string) *RotationAuditor {
	return &RotationAuditor{logger: l, surface: surface}
}

// LogRotation writes a keyring.rotate audit row using the supplied
// transaction. Sentinel actor values (token_id="system", connection_id="-")
// match data-model.md. Method signature matches secrets.RotationAuditor.
func (a *RotationAuditor) LogRotation(tx *sql.Tx, recordsRewrapped int, durationMs int64) error {
	return a.logger.LogTx(tx, &LogRequest{
		TokenID:      "system",
		TokenName:    "system",
		ConnectionID: "-",
		Operation:    "keyring.rotate",
		Params: map[string]any{
			"surface":           a.surface,
			"records_rewrapped": recordsRewrapped,
		},
		PolicyResult: "success",
		DurationMs:   durationMs,
	})
}

// LogRotationLockout writes one keyring.rotate_lockout audit row using a
// fresh transaction. Called outside any rotation transaction at the moment
// the consecutive-failure counter triggers a lockout. surface is "ui"
// for the admin-form lockout (the only surface with a lockout today).
// threshold is the consecutive-failure count that triggered the lockout.
func (l *Logger) LogRotationLockout(surface string, threshold int) error {
	return l.Log(&LogRequest{
		TokenID:      "system",
		TokenName:    "system",
		ConnectionID: "-",
		Operation:    "keyring.rotate_lockout",
		Params: map[string]any{
			"surface":   surface,
			"threshold": threshold,
		},
		PolicyResult: "lockout_trigger",
	})
}

// LogOperator is a convenience wrapper around Log for admin
// mutations: pre-fills actor_kind="operator", redacts sensitive
// keys from params via RedactSensitive, and tolerates an empty
// connection ID (entity-level audit rows aren't tied to a
// connection)...
func (l *Logger) LogOperator(operatorDisplayName, operation, entityID string, params map[string]any, outcome string) error {
	if params != nil {
		params = RedactSensitive(params)
	}
	return l.Log(&LogRequest{
		TokenID:             "operator",
		TokenName:           operatorDisplayName,
		ConnectionID:        entityID, // entity_id by convention for admin rows
		Operation:           operation,
		Params:              params,
		PolicyResult:        outcome,
		ActorKind:           "operator",
		OperatorDisplayName: operatorDisplayName,
	})
}

// sensitiveKeys is the set of param keys whose values are stripped
// before being written to the audit log. Plaintext bearer
// tokens, OAuth secrets, installation keys, and the like never reach
// the audit row.
var sensitiveKeys = map[string]struct{}{
	"token":             {},
	"plaintext_token":   {},
	"bearer_token":      {},
	"bot_token":         {},
	"client_secret":     {},
	"slack_client_secret": {},
	"oauth_secret":      {},
	"installation_key":  {},
	"private_key":       {},
	"private_key_pem":   {},
	"credential":        {},
	"confirm_credential": {},
	"current_passphrase": {},
	"new_passphrase":    {},
	"new_passphrase_confirm": {},
	"password":          {},
}

// RedactSensitive returns a shallow copy of params with values for
// known sensitive keys replaced by "<redacted>". Other keys pass
// through unchanged. Idempotent; safe to apply repeatedly.
func RedactSensitive(params map[string]any) map[string]any {
	if params == nil {
		return nil
	}
	out := make(map[string]any, len(params))
	for k, v := range params {
		if _, sensitive := sensitiveKeys[k]; sensitive {
			out[k] = "<redacted>"
			continue
		}
		out[k] = v
	}
	return out
}

// List returns audit log entries matching the given filter.
func (l *Logger) List(filter *ListFilter) ([]Entry, error) {
	query, args := buildFilterQuery("SELECT id, timestamp, token_id, token_name, connection_id, operation, params, policy_result, response_summary, duration_ms, actor_kind, operator_display_name FROM audit_log", filter)
	query += " ORDER BY timestamp DESC"

	limit := 100
	if filter != nil && filter.Limit > 0 {
		limit = filter.Limit
	}
	if limit > 1000 {
		limit = 1000
	}
	query += " LIMIT ?"
	args = append(args, limit)

	if filter != nil && filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := l.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var ts string
		var params, respSummary, operatorName sql.NullString
		var durationMs sql.NullInt64

		if err := rows.Scan(
			&e.ID, &ts, &e.TokenID, &e.TokenName, &e.ConnectionID,
			&e.Operation, &params, &e.PolicyResult, &respSummary, &durationMs,
			&e.ActorKind, &operatorName,
		); err != nil {
			return nil, fmt.Errorf("scan audit log row: %w", err)
		}
		if operatorName.Valid {
			e.OperatorDisplayName = operatorName.String
		}

		if parsed, err := time.Parse("2006-01-02 15:04:05", ts); err == nil {
			e.Timestamp = parsed
		} else if parsed, err := time.Parse("2006-01-02T15:04:05Z", ts); err == nil {
			e.Timestamp = parsed
		} else if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
			e.Timestamp = parsed
		} else {
			e.Timestamp = time.Now()
		}
		if params.Valid {
			e.Params = params.String
		}
		if respSummary.Valid {
			e.ResponseSummary = respSummary.String
		}
		if durationMs.Valid {
			e.DurationMs = durationMs.Int64
		}

		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Count returns the number of audit log entries matching the given filter.
func (l *Logger) Count(filter *ListFilter) (int, error) {
	query, args := buildFilterQuery("SELECT COUNT(*) FROM audit_log", filter)
	var count int
	if err := l.db.QueryRow(query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count audit log: %w", err)
	}
	return count, nil
}

// Cleanup deletes audit log entries older than retentionDays.
func (l *Logger) Cleanup(retentionDays int) (int64, error) {
	result, err := l.db.Exec(
		"DELETE FROM audit_log WHERE timestamp < datetime('now', ?)",
		fmt.Sprintf("-%d days", retentionDays),
	)
	if err != nil {
		return 0, fmt.Errorf("cleanup audit log: %w", err)
	}
	return result.RowsAffected()
}

func buildFilterQuery(baseQuery string, filter *ListFilter) (string, []any) {
	if filter == nil {
		return baseQuery, nil
	}

	var conditions []string
	var args []any

	if filter.TokenID != "" {
		conditions = append(conditions, "token_id = ?")
		args = append(args, filter.TokenID)
	}
	if filter.ConnectionID != "" {
		conditions = append(conditions, "connection_id = ?")
		args = append(args, filter.ConnectionID)
	}
	if filter.Operation != "" {
		conditions = append(conditions, "operation = ?")
		args = append(args, filter.Operation)
	}
	if filter.After != nil {
		conditions = append(conditions, "timestamp > ?")
		args = append(args, filter.After.Format("2006-01-02 15:04:05"))
	}
	if filter.Before != nil {
		conditions = append(conditions, "timestamp < ?")
		args = append(args, filter.Before.Format("2006-01-02 15:04:05"))
	}

	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	return baseQuery, args
}
