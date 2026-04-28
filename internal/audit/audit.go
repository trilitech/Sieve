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

// Log inserts a new entry into the audit log.
func (l *Logger) Log(req *LogRequest) error {
	var paramsJSON sql.NullString
	if req.Params != nil {
		b, err := json.Marshal(req.Params)
		if err != nil {
			return fmt.Errorf("marshal params: %w", err)
		}
		paramsJSON = sql.NullString{String: string(b), Valid: true}
	}

	respSummary := sql.NullString{String: req.ResponseSummary, Valid: req.ResponseSummary != ""}

	_, err := l.db.Exec(`
		INSERT INTO audit_log (token_id, token_name, connection_id, operation, params, policy_result, response_summary, duration_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		req.TokenID,
		req.TokenName,
		req.ConnectionID,
		req.Operation,
		paramsJSON,
		req.PolicyResult,
		respSummary,
		req.DurationMs,
	)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

// List returns audit log entries matching the given filter.
func (l *Logger) List(filter *ListFilter) ([]Entry, error) {
	query, args := buildFilterQuery("SELECT id, timestamp, token_id, token_name, connection_id, operation, params, policy_result, response_summary, duration_ms FROM audit_log", filter)
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
		var params, respSummary sql.NullString
		var durationMs sql.NullInt64

		if err := rows.Scan(
			&e.ID, &ts, &e.TokenID, &e.TokenName, &e.ConnectionID,
			&e.Operation, &params, &e.PolicyResult, &respSummary, &durationMs,
		); err != nil {
			return nil, fmt.Errorf("scan audit log row: %w", err)
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
