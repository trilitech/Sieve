package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// TestBridge_ForwardsAuthAndBody verifies the bridge sets the Authorization
// header and forwards request bytes verbatim to the upstream MCP endpoint.
func TestBridge_ForwardsAuthAndBody(t *testing.T) {
	const wantBody = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization=%q, want %q", got, "Bearer tok")
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type=%q, want application/json", got)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != wantBody {
			t.Errorf("upstream body=%q, want %q", body, wantBody)
		}
		fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer srv.Close()

	in := strings.NewReader(wantBody + "\n")
	var out bytes.Buffer
	if err := bridge(srv.URL, "tok", in, &out, io.Discard); err != nil {
		t.Fatalf("bridge: %v", err)
	}
	if !strings.Contains(out.String(), `"result":{}`) {
		t.Errorf("response not written to out: %q", out.String())
	}
}

// TestBridge_NotificationDropsResponse verifies that JSON-RPC notifications
// (messages without an `id` field) have their upstream responses suppressed,
// per the JSON-RPC 2.0 spec.
func TestBridge_NotificationDropsResponse(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		// Upstream replies to everything; bridge must drop the reply for the
		// notification.
		fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer srv.Close()

	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" +
			`{"jsonrpc":"2.0","method":"notifications/cancelled"}` + "\n",
	)
	var out bytes.Buffer
	if err := bridge(srv.URL, "tok", in, &out, io.Discard); err != nil {
		t.Fatalf("bridge: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("upstream hits=%d, want 2 (both messages forwarded)", got)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("got %d response lines, want 1 (notification reply must be dropped); out=%q",
			len(lines), out.String())
	}
}

// TestBridge_NonOKUpstreamWrapsAsJSONRPCError verifies that a non-2xx
// upstream response (e.g. plain-text 401 from the auth middleware) is
// translated into a synthesized JSON-RPC error response keyed to the
// original request id, instead of being forwarded verbatim — which would
// desync Claude Desktop's protocol parser.
func TestBridge_NonOKUpstreamWrapsAsJSONRPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "invalid token")
	}))
	defer srv.Close()

	in := strings.NewReader(`{"jsonrpc":"2.0","id":42,"method":"tools/list"}` + "\n")
	var out, errOut bytes.Buffer
	if err := bridge(srv.URL, "tok", in, &out, &errOut); err != nil {
		t.Fatalf("bridge: %v", err)
	}

	var got struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v; out=%q", err, out.String())
	}
	if got.JSONRPC != "2.0" {
		t.Errorf("jsonrpc=%q, want 2.0", got.JSONRPC)
	}
	if string(got.ID) != "42" {
		t.Errorf("id=%s, want 42", got.ID)
	}
	if got.Error.Code != -32000 {
		t.Errorf("error.code=%d, want -32000", got.Error.Code)
	}
	if !strings.Contains(got.Error.Message, "401") || !strings.Contains(got.Error.Message, "invalid token") {
		t.Errorf("error.message=%q, want it to mention status + body", got.Error.Message)
	}
	if !strings.Contains(errOut.String(), "401") {
		t.Errorf("errOut should log the upstream status, got %q", errOut.String())
	}
}

// TestBridge_NonOKNotificationDropsResponse verifies that a non-2xx
// upstream response to a notification produces NO stdout write — JSON-RPC
// forbids any reply (including errors) for notifications.
func TestBridge_NonOKNotificationDropsResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "invalid token")
	}))
	defer srv.Close()

	in := strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/cancelled"}` + "\n")
	var out, errOut bytes.Buffer
	if err := bridge(srv.URL, "tok", in, &out, &errOut); err != nil {
		t.Fatalf("bridge: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("stdout must be empty for a notification, got %q", out.String())
	}
	if !strings.Contains(errOut.String(), "401") {
		t.Errorf("errOut should still log the upstream failure, got %q", errOut.String())
	}
}

// TestLoadToken_NoSourceErrors verifies loadToken returns a helpful error
// when no token source is available (no Keychain entry, no token file).
func TestLoadToken_NoSourceErrors(t *testing.T) {
	// Pass empty keychain service to skip the darwin lookup, and an empty
	// token-file. This exercises the "no token" branch on every platform.
	_, err := loadToken("", "")
	if err == nil {
		t.Fatal("loadToken with no sources should error, got nil")
	}
	if !strings.Contains(err.Error(), "no token") {
		t.Errorf("error=%q, want it to mention 'no token'", err)
	}
}

// TestLoadToken_FileFallback verifies the token-file path works when
// Keychain is unavailable (empty service name forces fall-through).
func TestLoadToken_FileFallback(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/tok"
	if err := os.WriteFile(path, []byte("  sieve_tok_abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadToken("", path)
	if err != nil {
		t.Fatalf("loadToken: %v", err)
	}
	if got != "sieve_tok_abc" {
		t.Errorf("got=%q, want sieve_tok_abc", got)
	}
}

// TestLoadToken_EmptyFileErrors verifies an empty token file produces a
// clear error rather than returning an empty bearer.
func TestLoadToken_EmptyFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/tok"
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadToken("", path)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("err=%v, want non-nil mentioning 'empty'", err)
	}
}

// TestBridge_SkipsBlankLines ensures empty/whitespace-only lines from stdin
// don't generate spurious upstream POSTs.
func TestBridge_SkipsBlankLines(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer srv.Close()

	in := strings.NewReader("\n   \n" + `{"jsonrpc":"2.0","id":1,"method":"x"}` + "\n\n")
	var out bytes.Buffer
	if err := bridge(srv.URL, "tok", in, &out, io.Discard); err != nil {
		t.Fatalf("bridge: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("upstream hits=%d, want 1", got)
	}
}
