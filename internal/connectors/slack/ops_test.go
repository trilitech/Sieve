package slack

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/testing/mockslack"
)

// Contract tests asserting the param/result shapes documented in
// contracts/slack.md. Driven against the mockslack server — no
// network access, deterministic fixtures.

func TestOps_ListChannels_NormalizedShape(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)

	c, _ := newConnectorForTest(t, mock)
	got, err := c.Execute(context.Background(), "list_channels", map[string]any{})
	if err != nil {
		t.Fatalf("list_channels: %v", err)
	}
	m := got.(map[string]any)
	items, ok := m["items"].([]any)
	if !ok {
		t.Fatalf("expected items array, got %+v", m["items"])
	}
	if len(items) == 0 {
		t.Fatal("expected at least one channel from default fixture")
	}
	if _, ok := m["next_cursor"]; !ok {
		t.Fatal("expected next_cursor key in response")
	}
}

// TestOps_ListChannels_PaginationCursor walks past the first page
// using next_cursor and asserts both pages are well-formed and the
// cursor is empty when the result set is exhausted. Verifies the
// normalized pagination pass-through end to end.
func TestOps_ListChannels_PaginationCursor(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)
	mock.SetChannels(mockslack.LargeChannelSet(150))

	c, _ := newConnectorForTest(t, mock)
	page1, err := c.Execute(context.Background(), "list_channels", map[string]any{"page_size": 50})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	m1 := page1.(map[string]any)
	if items, _ := m1["items"].([]any); len(items) != 50 {
		t.Fatalf("page 1 size: got %d, want 50", len(items))
	}
	cursor1, _ := m1["next_cursor"].(string)
	if cursor1 == "" {
		t.Fatal("expected non-empty next_cursor on page 1")
	}

	page2, err := c.Execute(context.Background(), "list_channels", map[string]any{
		"page_size": 50,
		"cursor":    cursor1,
	})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	m2 := page2.(map[string]any)
	if items, _ := m2["items"].([]any); len(items) != 50 {
		t.Fatalf("page 2 size: got %d, want 50", len(items))
	}

	// Page 3 should be the last partial page with empty next_cursor.
	cursor2, _ := m2["next_cursor"].(string)
	page3, err := c.Execute(context.Background(), "list_channels", map[string]any{
		"page_size": 50,
		"cursor":    cursor2,
	})
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	m3 := page3.(map[string]any)
	if items, _ := m3["items"].([]any); len(items) != 50 {
		t.Fatalf("page 3 size: got %d, want 50", len(items))
	}
	if last, _ := m3["next_cursor"].(string); last != "" {
		t.Fatalf("expected empty next_cursor on last page, got %q", last)
	}
}

func TestOps_ListUsers_NormalizedShape(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)
	c, _ := newConnectorForTest(t, mock)

	got, err := c.Execute(context.Background(), "list_users", map[string]any{})
	if err != nil {
		t.Fatalf("list_users: %v", err)
	}
	m := got.(map[string]any)
	items, ok := m["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected items array, got %+v", m["items"])
	}
}

func TestOps_ReadUserProfile(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)
	c, _ := newConnectorForTest(t, mock)

	got, err := c.Execute(context.Background(), "read_user_profile", map[string]any{"user": "U0001"})
	if err != nil {
		t.Fatalf("read_user_profile: %v", err)
	}
	prof := got.(map[string]any)
	if prof["real_name"] == nil {
		t.Fatalf("expected real_name in profile, got %+v", prof)
	}
}

func TestOps_ReadUserProfile_RequiresUser(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)
	c, _ := newConnectorForTest(t, mock)

	_, err := c.Execute(context.Background(), "read_user_profile", map[string]any{})
	if err == nil {
		t.Fatal("expected error when user param missing")
	}
}

func TestOps_ReadChannelHistory(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)
	c, _ := newConnectorForTest(t, mock)

	got, err := c.Execute(context.Background(), "read_channel_history", map[string]any{"channel": "C0000001"})
	if err != nil {
		t.Fatalf("read_channel_history: %v", err)
	}
	m := got.(map[string]any)
	items, ok := m["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected message items, got %+v", m["items"])
	}
}

func TestOps_ReadThread(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)
	c, _ := newConnectorForTest(t, mock)

	got, err := c.Execute(context.Background(), "read_thread", map[string]any{
		"channel": "C0000001",
		"ts":      "1700000001.000100",
	})
	if err != nil {
		t.Fatalf("read_thread: %v", err)
	}
	m := got.(map[string]any)
	items, ok := m["items"].([]any)
	if !ok || len(items) < 2 {
		t.Fatalf("expected at least 2 messages in thread, got %+v", m["items"])
	}
}

// TestOps_SearchMessages_NotEnabled — the gated operation returns the
// typed connector.ErrOperationNotEnabled sentinel from Execute. The API
// layer maps the sentinel to HTTP 501 and the MCP layer to a tool error
// with the "operation_not_enabled:" text prefix; agent SDKs branch on
// the status code / prefix without reading the response body. The
// legacy phantom-success shape (200 OK
// with `{"error": "operation_not_enabled"}`) was retired here.
func TestOps_SearchMessages_NotEnabled(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)
	c, _ := newConnectorForTest(t, mock)

	got, err := c.Execute(context.Background(), "search_messages", map[string]any{"query": "foo"})
	if err == nil {
		t.Fatalf("expected typed error, got success with value %+v", got)
	}
	if !errors.Is(err, connector.ErrOperationNotEnabled) {
		t.Fatalf("error does not wrap ErrOperationNotEnabled: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil result on gated op, got %+v", got)
	}
}

func TestOps_PostMessage(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)
	c, _ := newConnectorForTest(t, mock)

	got, err := c.Execute(context.Background(), "post_message", map[string]any{
		"channel": "#bot-test",
		"text":    "hello from sieve",
	})
	if err != nil {
		t.Fatalf("post_message: %v", err)
	}
	m := got.(map[string]any)
	if m["ok"] != true {
		t.Fatalf("expected ok=true, got %+v", m)
	}
	// Verify the leading '#' was trimmed before sending.
	calls := mock.Calls()
	var posted bool
	for _, call := range calls {
		if call.Path == "/api/chat.postMessage" {
			posted = true
			vals := call.Form["channel"]
			if len(vals) == 0 || vals[0] != "bot-test" {
				t.Fatalf("expected channel=bot-test (trimmed), got %v", vals)
			}
		}
	}
	if !posted {
		t.Fatal("chat.postMessage was not invoked")
	}
}

func TestOps_PostMessage_RequiresFields(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)
	c, _ := newConnectorForTest(t, mock)

	_, err := c.Execute(context.Background(), "post_message", map[string]any{"channel": "x"})
	if err == nil {
		t.Fatal("expected error when text missing")
	}
	_, err = c.Execute(context.Background(), "post_message", map[string]any{"text": "x"})
	if err == nil {
		t.Fatal("expected error when channel missing")
	}
}

func TestOps_UnknownOperation(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)
	c, _ := newConnectorForTest(t, mock)

	_, err := c.Execute(context.Background(), "fly_to_the_moon", map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "unknown operation") {
		t.Fatalf("expected unknown-operation error, got %v", err)
	}
}

// TestOps_TerminalAuthFiresCallback asserts the terminal-auth path
// integrates end to end through ops: a Slack-side invalid_auth on a
// list_* call fires the connector's onTerminalAuth callback (which
// the factory wires to SetStatus(reauth_required) — verified at the
// integration level in the next commit's web-handler tests).
func TestOps_TerminalAuthFiresCallback(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)
	mock.SetForceError("token_revoked")

	c, terminalFired := newConnectorForTest(t, mock)
	_, err := c.Execute(context.Background(), "list_channels", map[string]any{})
	if err == nil {
		t.Fatal("expected error on terminal-auth response")
	}
	if !*terminalFired {
		t.Fatal("expected terminalAuth callback to fire on token_revoked")
	}
}

// TestOps_TableMatchesContract — defensive: the curated set must
// exactly match the seven operations listed in contracts/slack.md so a
// reorder or rename is caught at unit-test time before policies break.
func TestOps_TableMatchesContract(t *testing.T) {
	want := map[string]bool{
		"list_channels":        false,
		"list_users":           false,
		"read_user_profile":    false,
		"read_channel_history": false,
		"read_thread":          false,
		"search_messages":      false,
		"post_message":         false,
	}
	mock := mockslack.New()
	t.Cleanup(mock.Close)
	c, _ := newConnectorForTest(t, mock)
	for _, op := range c.Operations() {
		if _, expected := want[op.Name]; !expected {
			t.Errorf("unexpected operation %q in curated set", op.Name)
		}
		want[op.Name] = true
	}
	for name, present := range want {
		if !present {
			t.Errorf("missing curated operation %q", name)
		}
	}
}
