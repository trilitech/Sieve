// Package approval implements a human-in-the-loop approval queue for Sieve.
//
// When a policy evaluates to "approval_required", the operation is submitted
// to this queue and waits for a human to approve or reject it via the web UI.
//
// The queue uses a listener pattern for blocking waits: callers (like the REST
// API's executeOperation) call WaitForResolution which blocks on a channel.
// When a human approves/rejects via the web UI, resolve() updates the database
// and sends the resolved item through the channel, unblocking the caller.
//
// Key design decisions:
//   - Channels are buffered with capacity 1 so the notify side never blocks
//     even if the waiting goroutine has already timed out and stopped listening.
//   - Listeners are cleaned up in a defer in WaitForResolution, so timeout
//     always removes the channel from the map — no leaked goroutines or channels.
//   - The MCP server does NOT use WaitForResolution (it returns immediately
//     with an approval ID). Only the synchronous REST API blocks. This avoids
//     tying up MCP connections while waiting for human action.
//   - The resolve() method uses a conditional UPDATE (WHERE status = 'pending')
//     to prevent double-resolution races.
package approval

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/trilitech/Sieve/internal/database"
)

// Status represents the resolution state of an approval queue item.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

// Item represents a single entry in the approval queue.
type Item struct {
	ID          string         `json:"id"`
	TokenID     string         `json:"token_id"`
	ConnectionID string        `json:"connection_id"`
	Operation   string         `json:"operation"`
	RequestData map[string]any `json:"request_data"`
	Status      Status         `json:"status"`
	CreatedAt   time.Time      `json:"created_at"`
	ResolvedAt  *time.Time     `json:"resolved_at,omitempty"`
	ResolvedBy  string         `json:"resolved_by,omitempty"`
}

// SubmitRequest contains the fields needed to create a new approval queue item.
type SubmitRequest struct {
	TokenID     string
	ConnectionID string
	Operation   string
	RequestData map[string]any
}

// Queue manages the approval queue, combining database persistence with
// in-memory listener channels. The listeners map enables the blocking
// WaitForResolution pattern: a goroutine registers a channel, and the
// channel receives the resolved item when a human acts on it.
type Queue struct {
	db        *database.DB
	listeners map[string]chan *Item // keyed by approval item ID; buffered(1)
	mu        sync.Mutex           // guards listeners map only, not DB operations
}

// NewQueue creates a new Queue backed by the given database.
func NewQueue(db *database.DB) *Queue {
	return &Queue{
		db:        db,
		listeners: make(map[string]chan *Item),
	}
}

// generateSecureID returns 32 bytes of cryptographic randomness encoded as
// hex (64 hex chars). This gives 256 bits of entropy — far more than UUIDv4's
// 122 bits — and makes enumeration infeasible.
func generateSecureID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Submit creates a new pending approval item and inserts it into the database.
func (q *Queue) Submit(req *SubmitRequest) (*Item, error) {
	id, err := generateSecureID()
	if err != nil {
		return nil, fmt.Errorf("generate approval ID: %w", err)
	}
	dataJSON, err := json.Marshal(req.RequestData)
	if err != nil {
		return nil, fmt.Errorf("marshal request_data: %w", err)
	}

	now := time.Now().UTC()

	_, err = q.db.Exec(
		`INSERT INTO approval_queue (id, token_id, connection_id, operation, request_data, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, req.TokenID, req.ConnectionID, req.Operation, string(dataJSON), string(StatusPending), now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert approval item: %w", err)
	}

	item := &Item{
		ID:          id,
		TokenID:     req.TokenID,
		ConnectionID: req.ConnectionID,
		Operation:   req.Operation,
		RequestData: req.RequestData,
		Status:      StatusPending,
		CreatedAt:   now,
	}

	return item, nil
}

// WaitForResolution blocks until the approval item with the given ID is
// resolved (approved or rejected) or the timeout elapses. Returns an error on
// timeout.
func (q *Queue) WaitForResolution(id string, timeout time.Duration) (*Item, error) {
	// Check if already resolved BEFORE registering the listener. This closes
	// the race where Approve/Reject is called between Submit and WaitForResolution.
	item, err := q.Get(id)
	if err == nil && item.Status != StatusPending {
		return item, nil
	}

	// Buffered channel (cap 1): if the item is resolved after timeout but
	// before GC, the notify() send won't block or panic.
	ch := make(chan *Item, 1)

	q.mu.Lock()
	q.listeners[id] = ch
	q.mu.Unlock()

	// Check again after registering, in case it was resolved between the
	// first check and the listener registration (double-check pattern).
	item, err = q.Get(id)
	if err == nil && item.Status != StatusPending {
		return item, nil
	}

	// Cleanup on all exit paths (success or timeout) to prevent listener
	// map from growing unboundedly with stale entries.
	defer func() {
		q.mu.Lock()
		delete(q.listeners, id)
		q.mu.Unlock()
	}()

	select {
	case item := <-ch:
		return item, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timed out waiting for resolution of approval item %s", id)
	}
}

// Approve marks the approval item as approved and notifies any waiting listener.
func (q *Queue) Approve(id string) error {
	return q.resolve(id, StatusApproved)
}

// Reject marks the approval item as rejected and notifies any waiting listener.
func (q *Queue) Reject(id string) error {
	return q.resolve(id, StatusRejected)
}

// resolve sets the status, resolved_at, and resolved_by for the given item,
// then notifies any listener.
func (q *Queue) resolve(id string, status Status) error {
	now := time.Now().UTC()

	// Conditional update: AND status = 'pending' prevents double-resolution.
	// If two admins click approve/reject simultaneously, only the first
	// succeeds; the second gets a "not found or already resolved" error.
	result, err := q.db.Exec(
		`UPDATE approval_queue SET status = ?, resolved_at = ?, resolved_by = ? WHERE id = ? AND status = ?`,
		string(status), now, "user", id, string(StatusPending),
	)
	if err != nil {
		return fmt.Errorf("update approval item: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("approval item %s not found or already resolved", id)
	}

	q.notify(id)
	return nil
}

// ListPending returns all pending approval items ordered by created_at ASC.
func (q *Queue) ListPending() ([]Item, error) {
	rows, err := q.db.Query(
		`SELECT id, token_id, connection_id, operation, request_data, status, created_at, resolved_at, resolved_by
		 FROM approval_queue WHERE status = ? ORDER BY created_at ASC`,
		string(StatusPending),
	)
	if err != nil {
		return nil, fmt.Errorf("query pending items: %w", err)
	}
	defer rows.Close()

	return scanItems(rows)
}

// ListAll returns all approval items with pagination, ordered by created_at DESC.
func (q *Queue) ListAll(limit, offset int) ([]Item, error) {
	rows, err := q.db.Query(
		`SELECT id, token_id, connection_id, operation, request_data, status, created_at, resolved_at, resolved_by
		 FROM approval_queue ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("query all items: %w", err)
	}
	defer rows.Close()

	return scanItems(rows)
}

// Get returns a single approval item by ID.
func (q *Queue) Get(id string) (*Item, error) {
	row := q.db.QueryRow(
		`SELECT id, token_id, connection_id, operation, request_data, status, created_at, resolved_at, resolved_by
		 FROM approval_queue WHERE id = ?`,
		id,
	)

	item, err := scanItem(row)
	if err != nil {
		return nil, fmt.Errorf("get approval item %s: %w", id, err)
	}
	return item, nil
}

// notify fetches the resolved item from the database and sends it to the
// waiting listener channel, if one exists.
func (q *Queue) notify(id string) {
	q.mu.Lock()
	ch, ok := q.listeners[id]
	q.mu.Unlock()

	if !ok {
		return
	}

	item, err := q.Get(id)
	if err != nil {
		return
	}

	// Non-blocking send; the channel is buffered with capacity 1.
	select {
	case ch <- item:
	default:
	}
}

// scanItems reads all rows from a query result into a slice of Item.
func scanItems(rows *sql.Rows) ([]Item, error) {
	var items []Item
	for rows.Next() {
		var (
			item       Item
			dataJSON   string
			status     string
			resolvedAt sql.NullTime
			resolvedBy sql.NullString
		)

		if err := rows.Scan(
			&item.ID, &item.TokenID, &item.ConnectionID, &item.Operation,
			&dataJSON, &status, &item.CreatedAt, &resolvedAt, &resolvedBy,
		); err != nil {
			return nil, fmt.Errorf("scan approval item: %w", err)
		}

		item.Status = Status(status)

		if resolvedAt.Valid {
			item.ResolvedAt = &resolvedAt.Time
		}
		if resolvedBy.Valid {
			item.ResolvedBy = resolvedBy.String
		}

		if err := json.Unmarshal([]byte(dataJSON), &item.RequestData); err != nil {
			return nil, fmt.Errorf("unmarshal request_data: %w", err)
		}

		items = append(items, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate approval items: %w", err)
	}

	return items, nil
}

// scanItem reads a single row into an Item.
func scanItem(row *sql.Row) (*Item, error) {
	var (
		item       Item
		dataJSON   string
		status     string
		resolvedAt sql.NullTime
		resolvedBy sql.NullString
	)

	if err := row.Scan(
		&item.ID, &item.TokenID, &item.ConnectionID, &item.Operation,
		&dataJSON, &status, &item.CreatedAt, &resolvedAt, &resolvedBy,
	); err != nil {
		return nil, err
	}

	item.Status = Status(status)

	if resolvedAt.Valid {
		item.ResolvedAt = &resolvedAt.Time
	}
	if resolvedBy.Valid {
		item.ResolvedBy = resolvedBy.String
	}

	if err := json.Unmarshal([]byte(dataJSON), &item.RequestData); err != nil {
		return nil, fmt.Errorf("unmarshal request_data: %w", err)
	}

	return &item, nil
}
