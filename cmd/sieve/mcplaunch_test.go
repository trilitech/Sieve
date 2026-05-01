package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
	if err := bridge(srv.URL, "tok", in, &out); err != nil {
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
	if err := bridge(srv.URL, "tok", in, &out); err != nil {
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
	if err := bridge(srv.URL, "tok", in, &out); err != nil {
		t.Fatalf("bridge: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("upstream hits=%d, want 1", got)
	}
}
