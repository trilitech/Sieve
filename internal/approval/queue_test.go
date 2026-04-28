package approval_test

import (
	"strings"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/approval"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

func submitTestItem(t *testing.T, q *approval.Queue, op string) *approval.Item {
	t.Helper()
	item, err := q.Submit(&approval.SubmitRequest{
		TokenID:      "tok-1",
		ConnectionID: "conn-1",
		Operation:    op,
		RequestData:  map[string]any{"key": "value"},
	})
	if err != nil {
		t.Fatalf("submit item: %v", err)
	}
	return item
}

func TestSubmitAndGet(t *testing.T) {
	env := testenv.New(t)

	item, err := env.Approval.Submit(&approval.SubmitRequest{
		TokenID:      "tok-1",
		ConnectionID: "conn-1",
		Operation:    "send_email",
		RequestData:  map[string]any{"to": "user@example.com"},
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if item.ID == "" {
		t.Fatal("expected non-empty item ID")
	}
	if item.Status != approval.StatusPending {
		t.Fatalf("expected status pending, got %s", item.Status)
	}
	if item.Operation != "send_email" {
		t.Fatalf("expected operation 'send_email', got %q", item.Operation)
	}
	if item.TokenID != "tok-1" {
		t.Fatalf("expected token_id 'tok-1', got %q", item.TokenID)
	}
	if item.ConnectionID != "conn-1" {
		t.Fatalf("expected connection_id 'conn-1', got %q", item.ConnectionID)
	}

	got, err := env.Approval.Get(item.ID)
	if err != nil {
		t.Fatalf("get item: %v", err)
	}
	if got.ID != item.ID {
		t.Fatalf("expected ID %q, got %q", item.ID, got.ID)
	}
	if got.Status != approval.StatusPending {
		t.Fatalf("expected status pending, got %s", got.Status)
	}
	to, ok := got.RequestData["to"].(string)
	if !ok || to != "user@example.com" {
		t.Fatalf("expected request_data.to='user@example.com', got %v", got.RequestData["to"])
	}
}

func TestApprove(t *testing.T) {
	env := testenv.New(t)

	item := submitTestItem(t, env.Approval, "send_email")

	if err := env.Approval.Approve(item.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	got, err := env.Approval.Get(item.ID)
	if err != nil {
		t.Fatalf("get approved item: %v", err)
	}
	if got.Status != approval.StatusApproved {
		t.Fatalf("expected status approved, got %s", got.Status)
	}
	if got.ResolvedAt == nil {
		t.Fatal("expected resolved_at to be set")
	}
}

func TestReject(t *testing.T) {
	env := testenv.New(t)

	item := submitTestItem(t, env.Approval, "send_email")

	if err := env.Approval.Reject(item.ID); err != nil {
		t.Fatalf("reject: %v", err)
	}

	got, err := env.Approval.Get(item.ID)
	if err != nil {
		t.Fatalf("get rejected item: %v", err)
	}
	if got.Status != approval.StatusRejected {
		t.Fatalf("expected status rejected, got %s", got.Status)
	}
	if got.ResolvedAt == nil {
		t.Fatal("expected resolved_at to be set")
	}
}

func TestDoubleApprove(t *testing.T) {
	env := testenv.New(t)

	item := submitTestItem(t, env.Approval, "send_email")

	if err := env.Approval.Approve(item.ID); err != nil {
		t.Fatalf("first approve: %v", err)
	}

	err := env.Approval.Approve(item.ID)
	if err == nil {
		t.Fatal("expected error on double approve")
	}
	if !strings.Contains(err.Error(), "already resolved") {
		t.Fatalf("expected 'already resolved' error, got: %v", err)
	}
}

func TestListPending(t *testing.T) {
	env := testenv.New(t)

	// Submit 3 items.
	for i := 0; i < 3; i++ {
		submitTestItem(t, env.Approval, "send_email")
	}

	// Approve 1.
	pending, err := env.Approval.ListPending()
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 3 {
		t.Fatalf("expected 3 pending, got %d", len(pending))
	}

	if err := env.Approval.Approve(pending[0].ID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	pending, err = env.Approval.ListPending()
	if err != nil {
		t.Fatalf("list pending after approve: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending after approve, got %d", len(pending))
	}
}

func TestWaitForResolution(t *testing.T) {
	env := testenv.New(t)

	item := submitTestItem(t, env.Approval, "send_email")

	// Approve in a goroutine after a short delay.
	go func() {
		time.Sleep(100 * time.Millisecond)
		env.Approval.Approve(item.ID)
	}()

	resolved, err := env.Approval.WaitForResolution(item.ID, 5*time.Second)
	if err != nil {
		t.Fatalf("wait for resolution: %v", err)
	}
	if resolved.Status != approval.StatusApproved {
		t.Fatalf("expected approved, got %s", resolved.Status)
	}
}

func TestWaitTimeout(t *testing.T) {
	env := testenv.New(t)

	item := submitTestItem(t, env.Approval, "send_email")

	// Do not approve; wait should time out.
	_, err := env.Approval.WaitForResolution(item.ID, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected 'timed out' error, got: %v", err)
	}
}

// Story 62: Two admins approve the same item — second gets "already resolved".
func TestStory62_DoubleApproveAlreadyResolved(t *testing.T) {
	env := testenv.New(t)

	item := submitTestItem(t, env.Approval, "send_email")

	// First admin approves.
	if err := env.Approval.Approve(item.ID); err != nil {
		t.Fatalf("first approve should succeed: %v", err)
	}

	// Verify item is approved.
	got, err := env.Approval.Get(item.ID)
	if err != nil {
		t.Fatalf("get item: %v", err)
	}
	if got.Status != approval.StatusApproved {
		t.Fatalf("expected approved, got %s", got.Status)
	}

	// Second admin tries to approve the same item.
	err = env.Approval.Approve(item.ID)
	if err == nil {
		t.Fatal("story 62: second approve should fail")
	}
	if !strings.Contains(err.Error(), "already resolved") {
		t.Fatalf("story 62: expected 'already resolved', got: %v", err)
	}

	// Also verify a reject after approve fails the same way.
	err = env.Approval.Reject(item.ID)
	if err == nil {
		t.Fatal("story 62: reject after approve should fail")
	}
	if !strings.Contains(err.Error(), "already resolved") {
		t.Fatalf("story 62: expected 'already resolved' on reject, got: %v", err)
	}
}

// Story 263: Approval times out, item remains pending in DB after timeout.
func TestStory263_ApprovalTimeoutItemRemainsPending(t *testing.T) {
	env := testenv.New(t)

	item := submitTestItem(t, env.Approval, "send_email")

	// Wait with a very short timeout — no one approves.
	_, err := env.Approval.WaitForResolution(item.ID, 50*time.Millisecond)
	if err == nil {
		t.Fatal("story 263: expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("story 263: expected 'timed out', got: %v", err)
	}

	// Verify the item is still pending in the DB.
	got, err := env.Approval.Get(item.ID)
	if err != nil {
		t.Fatalf("story 263: get item after timeout: %v", err)
	}
	if got.Status != approval.StatusPending {
		t.Fatalf("story 263: expected status pending after timeout, got %s", got.Status)
	}
	if got.ResolvedAt != nil {
		t.Fatal("story 263: resolved_at should be nil for timed-out item")
	}

	// Verify the item still appears in the pending list.
	pending, err := env.Approval.ListPending()
	if err != nil {
		t.Fatalf("story 263: list pending: %v", err)
	}
	found := false
	for _, p := range pending {
		if p.ID == item.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("story 263: timed-out item should still be in pending list")
	}

	// Verify the item can still be approved after timeout.
	if err := env.Approval.Approve(item.ID); err != nil {
		t.Fatalf("story 263: approve after timeout should succeed: %v", err)
	}
	got, err = env.Approval.Get(item.ID)
	if err != nil {
		t.Fatalf("story 263: get after late approve: %v", err)
	}
	if got.Status != approval.StatusApproved {
		t.Fatalf("story 263: expected approved after late approve, got %s", got.Status)
	}
}

// Audit issue 2: Approve called BEFORE WaitForResolution registers listener.
// Before fix: notification was lost, WaitForResolution would timeout.
// After fix: WaitForResolution checks DB before waiting.
func TestAudit_ApproveBeforeWaitForResolution(t *testing.T) {
	env := testenv.New(t)

	item := submitTestItem(t, env.Approval, "send_email")

	// Approve BEFORE anyone calls WaitForResolution.
	if err := env.Approval.Approve(item.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Now call WaitForResolution — should return immediately (not timeout).
	resolved, err := env.Approval.WaitForResolution(item.ID, 2*time.Second)
	if err != nil {
		t.Fatalf("WaitForResolution should have returned immediately for already-approved item, got error: %v", err)
	}
	if resolved.Status != approval.StatusApproved {
		t.Fatalf("expected approved, got %s", resolved.Status)
	}
}
