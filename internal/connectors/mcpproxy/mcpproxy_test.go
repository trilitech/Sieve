package mcpproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// jsonRPCInitOK responds successfully to "initialize" so callUpstream's
// internal handshake doesn't trip before the test gets a chance to push
// a tools/list or tools/call response. Subsequent requests delegate to
// the supplied handler.
func mockMCP(t *testing.T, after func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCRequest
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		if req.Method == "initialize" || req.Method == "tools/list" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"tools":[{"name":"echo","description":"echo","inputSchema":{}}]}}`, req.ID)
			return
		}
		after(w, r)
	}))
}

func makeMCP(t *testing.T, ts *httptest.Server, capBytes int64) *MCPProxyConnector {
	t.Helper()
	cfg := map[string]any{"url": ts.URL}
	if capBytes > 0 {
		cfg["response_body_cap_bytes"] = capBytes
	}
	c, err := Factory(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*MCPProxyConnector)
}

func TestCallUpstreamRespectsDefaultCap(t *testing.T) {
	// Default cap = 5 MiB. A 4 MiB body succeeds; a 6 MiB body trips ErrResponseOversized.
	const fourMiB = 4 << 20
	const sixMiB = 6 << 20

	t.Run("under cap", func(t *testing.T) {
		ts := mockMCP(t, func(w http.ResponseWriter, r *http.Request) {
			payload := strings.Repeat("x", fourMiB)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"content":%q}}`, payload)
		})
		defer ts.Close()
		mc := makeMCP(t, ts, 0)
		_, err := mc.callUpstream(context.Background(), "tools/call", map[string]any{"name": "echo"})
		if err != nil {
			t.Fatalf("4 MiB response should succeed under default 5 MiB cap; got %v", err)
		}
	})

	t.Run("over cap", func(t *testing.T) {
		ts := mockMCP(t, func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"`)
			io.WriteString(w, strings.Repeat("y", sixMiB))
			io.WriteString(w, `"}`)
		})
		defer ts.Close()
		mc := makeMCP(t, ts, 0)
		_, err := mc.callUpstream(context.Background(), "tools/call", map[string]any{"name": "echo"})
		if !errors.Is(err, ErrResponseOversized) {
			t.Errorf("expected ErrResponseOversized for 6 MiB response, got %v", err)
		}
	})
}

func TestCallUpstreamHonoursPerConnectionCap(t *testing.T) {
	const oneMiB = 1 << 20
	const twoMiB = 2 << 20

	ts := mockMCP(t, func(w http.ResponseWriter, r *http.Request) {
		// Push 2 MiB.
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"`)
		io.WriteString(w, strings.Repeat("z", twoMiB))
		io.WriteString(w, `"}`)
	})
	defer ts.Close()
	mc := makeMCP(t, ts, oneMiB)
	_, err := mc.callUpstream(context.Background(), "tools/call", map[string]any{"name": "echo"})
	if !errors.Is(err, ErrResponseOversized) {
		t.Errorf("expected ErrResponseOversized when 2 MiB exceeds 1 MiB cap, got %v", err)
	}
}

func TestCallUpstreamHonoursLargerCap(t *testing.T) {
	const eightMiB = 8 << 20
	const sixteenMiB = 16 << 20

	ts := mockMCP(t, func(w http.ResponseWriter, r *http.Request) {
		// Push 8 MiB; default cap (5 MiB) would reject this, but the
		// per-connection 16 MiB cap should allow it.
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"`)
		io.WriteString(w, strings.Repeat("w", eightMiB))
		io.WriteString(w, `"}`)
	})
	defer ts.Close()
	mc := makeMCP(t, ts, sixteenMiB)
	_, err := mc.callUpstream(context.Background(), "tools/call", map[string]any{"name": "echo"})
	if err != nil {
		t.Errorf("8 MiB response should succeed under 16 MiB cap, got %v", err)
	}
}

func TestNegativeCapRejected(t *testing.T) {
	_, err := Factory(map[string]any{
		"url":                     "http://localhost:9999",
		"response_body_cap_bytes": -1,
	})
	if err == nil {
		t.Fatal("Factory must reject negative response_body_cap_bytes")
	}
	if !strings.Contains(err.Error(), "must be positive") {
		t.Errorf("error must clearly indicate positive-only constraint; got %q", err.Error())
	}
}

func TestZeroCapUsesDefault(t *testing.T) {
	c, err := Factory(map[string]any{
		"url":                     "http://localhost:9999",
		"response_body_cap_bytes": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	mc := c.(*MCPProxyConnector)
	if mc.responseBodyCap != defaultMCPResponseCap {
		t.Errorf("zero cap should fall back to default %d, got %d", defaultMCPResponseCap, mc.responseBodyCap)
	}
}

func TestMissingCapUsesDefault(t *testing.T) {
	c, err := Factory(map[string]any{"url": "http://localhost:9999"})
	if err != nil {
		t.Fatal(err)
	}
	mc := c.(*MCPProxyConnector)
	if mc.responseBodyCap != defaultMCPResponseCap {
		t.Errorf("missing cap should fall back to default %d, got %d", defaultMCPResponseCap, mc.responseBodyCap)
	}
}
