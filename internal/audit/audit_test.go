package audit_test

import (
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

func logEntry(t *testing.T, logger *audit.Logger, tokenID, connID, op, result string) {
	t.Helper()
	err := logger.Log(&audit.LogRequest{
		TokenID:      tokenID,
		TokenName:    tokenID + "-name",
		ConnectionID: connID,
		Operation:    op,
		Params:       map[string]any{"key": "value"},
		PolicyResult: result,
		DurationMs:   42,
	})
	if err != nil {
		t.Fatalf("log entry: %v", err)
	}
}

func TestLogAndList(t *testing.T) {
	env := testenv.New(t)

	logEntry(t, env.Audit, "tok-1", "conn-1", "list_emails", "allow")
	logEntry(t, env.Audit, "tok-1", "conn-1", "send_email", "deny")

	entries, err := env.Audit.List(nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Check both entries exist (order may vary when timestamps are identical).
	ops := map[string]bool{entries[0].Operation: true, entries[1].Operation: true}
	if !ops["list_emails"] || !ops["send_email"] {
		t.Fatalf("expected list_emails and send_email, got %v", ops)
	}
}

func TestLogWithNilParams(t *testing.T) {
	env := testenv.New(t)

	err := env.Audit.Log(&audit.LogRequest{
		TokenID:      "tok-1",
		TokenName:    "tok-1-name",
		ConnectionID: "conn-1",
		Operation:    "list_emails",
		PolicyResult: "allow",
	})
	if err != nil {
		t.Fatalf("log: %v", err)
	}

	entries, err := env.Audit.List(nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	if entries[0].Params != "" {
		t.Fatalf("expected empty params, got %q", entries[0].Params)
	}
}

func TestFilterByTokenID(t *testing.T) {
	env := testenv.New(t)

	logEntry(t, env.Audit, "tok-1", "conn-1", "list_emails", "allow")
	logEntry(t, env.Audit, "tok-2", "conn-1", "send_email", "deny")
	logEntry(t, env.Audit, "tok-1", "conn-1", "read_email", "allow")

	entries, err := env.Audit.List(&audit.ListFilter{TokenID: "tok-1"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2, got %d", len(entries))
	}
	for _, e := range entries {
		if e.TokenID != "tok-1" {
			t.Fatalf("expected tok-1, got %q", e.TokenID)
		}
	}
}

func TestFilterByConnectionID(t *testing.T) {
	env := testenv.New(t)

	logEntry(t, env.Audit, "tok-1", "conn-1", "list_emails", "allow")
	logEntry(t, env.Audit, "tok-1", "conn-2", "send_email", "deny")

	entries, err := env.Audit.List(&audit.ListFilter{ConnectionID: "conn-2"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	if entries[0].ConnectionID != "conn-2" {
		t.Fatalf("expected conn-2, got %q", entries[0].ConnectionID)
	}
}

func TestFilterByOperation(t *testing.T) {
	env := testenv.New(t)

	logEntry(t, env.Audit, "tok-1", "conn-1", "list_emails", "allow")
	logEntry(t, env.Audit, "tok-1", "conn-1", "send_email", "deny")

	entries, err := env.Audit.List(&audit.ListFilter{Operation: "send_email"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	if entries[0].Operation != "send_email" {
		t.Fatalf("expected send_email, got %q", entries[0].Operation)
	}
}

func TestFilterLimit(t *testing.T) {
	env := testenv.New(t)

	for i := 0; i < 5; i++ {
		logEntry(t, env.Audit, "tok-1", "conn-1", "list_emails", "allow")
	}

	entries, err := env.Audit.List(&audit.ListFilter{Limit: 2})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2, got %d", len(entries))
	}
}

func TestFilterOffset(t *testing.T) {
	env := testenv.New(t)

	for i := 0; i < 5; i++ {
		logEntry(t, env.Audit, "tok-1", "conn-1", "list_emails", "allow")
	}

	entries, err := env.Audit.List(&audit.ListFilter{Limit: 10, Offset: 3})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 (5 - offset 3), got %d", len(entries))
	}
}

func TestCount(t *testing.T) {
	env := testenv.New(t)

	logEntry(t, env.Audit, "tok-1", "conn-1", "list_emails", "allow")
	logEntry(t, env.Audit, "tok-1", "conn-1", "send_email", "deny")
	logEntry(t, env.Audit, "tok-2", "conn-1", "list_emails", "allow")

	count, err := env.Audit.Count(nil)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3, got %d", count)
	}

	count, err = env.Audit.Count(&audit.ListFilter{TokenID: "tok-1"})
	if err != nil {
		t.Fatalf("count filtered: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2, got %d", count)
	}
}

func TestCleanup(t *testing.T) {
	env := testenv.New(t)

	// Insert an entry with an old timestamp directly to guarantee it's in the past.
	_, err := env.DB.Exec(`
		INSERT INTO audit_log (token_id, token_name, connection_id, operation, policy_result, timestamp)
		VALUES ('tok-1', 'tok-1-name', 'conn-1', 'list_emails', 'allow', datetime('now', '-2 days'))`)
	if err != nil {
		t.Fatalf("insert old entry: %v", err)
	}

	// Cleanup with 1-day retention should remove the 2-day-old entry.
	deleted, err := env.Audit.Cleanup(1)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted, got %d", deleted)
	}

	count, err := env.Audit.Count(nil)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 after cleanup, got %d", count)
	}
}

func TestResponseSummary(t *testing.T) {
	env := testenv.New(t)

	err := env.Audit.Log(&audit.LogRequest{
		TokenID:         "tok-1",
		TokenName:       "tok-1-name",
		ConnectionID:    "conn-1",
		Operation:       "list_emails",
		PolicyResult:    "allow",
		ResponseSummary: "2 emails returned",
		DurationMs:      100,
	})
	if err != nil {
		t.Fatalf("log: %v", err)
	}

	entries, err := env.Audit.List(nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if entries[0].ResponseSummary != "2 emails returned" {
		t.Fatalf("expected response summary, got %q", entries[0].ResponseSummary)
	}
	if entries[0].DurationMs != 100 {
		t.Fatalf("expected 100ms, got %d", entries[0].DurationMs)
	}
}

func TestFilterByTimeRange(t *testing.T) {
	env := testenv.New(t)

	logEntry(t, env.Audit, "tok-1", "conn-1", "list_emails", "allow")

	// Filter for entries after now should return nothing.
	future := time.Now().Add(1 * time.Hour)
	entries, err := env.Audit.List(&audit.ListFilter{After: &future})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0, got %d", len(entries))
	}

	// Filter for entries before now+1h should return 1.
	entries, err = env.Audit.List(&audit.ListFilter{Before: &future})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
}
