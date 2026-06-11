package anthropic

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestConnector spins up an httptest.Server with the given handler
// and returns a Connector wired to it via the base_url override.
func newTestConnector(t *testing.T, handler http.HandlerFunc) *Connector {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	c, err := Factory()(map[string]any{
		"api_key":  "sk-ant-test-key-not-real",
		"base_url": srv.URL,
	})
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	return c.(*Connector)
}

// TestParseConfig_RejectsMissingAPIKey ensures we don't silently boot
// a connector that has no auth.
func TestParseConfig_RejectsMissingAPIKey(t *testing.T) {
	_, err := parseConfig(map[string]any{"base_url": "https://api.anthropic.com"})
	if err == nil {
		t.Fatal("parseConfig(no api_key): expected error")
	}
	if !strings.Contains(err.Error(), "api_key") {
		t.Errorf("expected error to mention api_key, got %v", err)
	}
}

// TestParseConfig_RejectsWrongPrefix catches the common operator
// mistake of pasting an OpenAI / generic key into the Anthropic form.
func TestParseConfig_RejectsWrongPrefix(t *testing.T) {
	_, err := parseConfig(map[string]any{"api_key": "sk-openai-not-anthropic"})
	if err == nil {
		t.Fatal("parseConfig(wrong prefix): expected error")
	}
	if !strings.Contains(err.Error(), "sk-ant-") {
		t.Errorf("expected error to name the required prefix, got %v", err)
	}
}

// TestParseConfig_DefaultsBaseURLAndVersion confirms operators can omit
// optional fields and get sensible defaults.
func TestParseConfig_DefaultsBaseURLAndVersion(t *testing.T) {
	cfg, err := parseConfig(map[string]any{"api_key": "sk-ant-abc"})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.BaseURL != defaultBaseURL {
		t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, defaultBaseURL)
	}
	if cfg.AnthropicVersion != defaultAnthropicVersion {
		t.Errorf("AnthropicVersion = %q, want %q", cfg.AnthropicVersion, defaultAnthropicVersion)
	}
}

// TestParseConfig_RejectsBareHost catches operators who paste
// "api.anthropic.com" without a scheme — that would yield a request URL
// like "api.anthropic.com/v1/messages" which is silently broken.
func TestParseConfig_RejectsBareHost(t *testing.T) {
	_, err := parseConfig(map[string]any{
		"api_key":  "sk-ant-abc",
		"base_url": "api.anthropic.com",
	})
	if err == nil {
		t.Fatal("parseConfig(bare host): expected error")
	}
}

// TestParseConfig_StripsTrailingSlash normalises a common URL nit so
// the connector's path concatenation doesn't produce //v1/messages.
func TestParseConfig_StripsTrailingSlash(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"api_key":  "sk-ant-abc",
		"base_url": "https://api.anthropic.com/",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.BaseURL != "https://api.anthropic.com" {
		t.Errorf("BaseURL = %q, want trailing slash stripped", cfg.BaseURL)
	}
}

// TestMessagesCreate_SendsAuthAndVersionHeaders verifies the connector
// attaches the headers Anthropic's API requires — without these, every
// real call would return 401.
func TestMessagesCreate_SendsAuthAndVersionHeaders(t *testing.T) {
	var gotAPIKey, gotVersion, gotContentType string
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		gotContentType = r.Header.Get("content-type")
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_01","type":"message","content":[]}`))
	})

	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":      "claude-sonnet-4-5",
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"max_tokens": 16,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotAPIKey != "sk-ant-test-key-not-real" {
		t.Errorf("x-api-key header = %q, want sk-ant-test-key-not-real", gotAPIKey)
	}
	if gotVersion != defaultAnthropicVersion {
		t.Errorf("anthropic-version header = %q, want %q", gotVersion, defaultAnthropicVersion)
	}
	if gotContentType != "application/json" {
		t.Errorf("content-type = %q, want application/json", gotContentType)
	}
}

// TestMessagesCreate_StripsMaxCostFromOutboundBody pins the contract:
// max_cost is a Sieve-internal field used for policy gating, never sent
// to Anthropic. Forwarding it would either be silently ignored (fine but
// wasteful) or rejected by Anthropic in some future stricter API rev.
func TestMessagesCreate_StripsMaxCostFromOutboundBody(t *testing.T) {
	var receivedBody map[string]any
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_01","type":"message","content":[]}`))
	})

	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":      "claude-sonnet-4-5",
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"max_tokens": 16,
		"max_cost":   "0.50",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, present := receivedBody["max_cost"]; present {
		t.Errorf("max_cost leaked to upstream Anthropic body: %v", receivedBody)
	}
	if receivedBody["model"] != "claude-sonnet-4-5" {
		t.Errorf("model = %v, want claude-sonnet-4-5", receivedBody["model"])
	}
}

// TestMessagesCreate_RejectsStreamingFlag pins the streaming-not-here
// boundary. Operators who pass stream=true should get a clear error, not
// a server-sent-events response that the connector can't parse.
func TestMessagesCreate_RejectsStreamingFlag(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called when stream=true")
	})
	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":      "claude-sonnet-4-5",
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"max_tokens": 16,
		"stream":     true,
	})
	if err == nil {
		t.Fatal("expected error for stream=true on messages_create")
	}
	if !strings.Contains(err.Error(), "streaming") {
		t.Errorf("error should mention streaming, got %v", err)
	}
}

// TestMessagesCreate_PropagatesUpstreamErrorEnvelope confirms that
// Anthropic's structured {"type":"error","error":{...}} response is
// surfaced to the caller — without this, audit logs would just see a
// generic "non-2xx response".
func TestMessagesCreate_PropagatesUpstreamErrorEnvelope(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error","message":"model not found: claude-bogus"}}`))
	})
	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":      "claude-bogus",
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"max_tokens": 16,
	})
	if err == nil {
		t.Fatal("expected error on 400 response")
	}
	if !strings.Contains(err.Error(), "invalid_request_error") || !strings.Contains(err.Error(), "model not found") {
		t.Errorf("expected upstream error type + message in error, got %v", err)
	}
}

// TestMessagesCreate_RequiresMaxTokens guards against the most common
// caller mistake — Anthropic's API requires max_tokens, but agents
// frequently omit it. Failing locally before the HTTP call gives a
// clearer error than the upstream 400.
func TestMessagesCreate_RequiresMaxTokens(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called when required param missing")
	})
	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":    "claude-sonnet-4-5",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	})
	if err == nil {
		t.Fatal("expected error for missing max_tokens")
	}
	if !strings.Contains(err.Error(), "max_tokens") {
		t.Errorf("error should mention max_tokens, got %v", err)
	}
}

// TestMessagesCountTokens_NoMaxTokensRequired confirms the count-tokens
// op does NOT require max_tokens (Anthropic's API doesn't either, since
// no generation happens).
func TestMessagesCountTokens_NoMaxTokensRequired(t *testing.T) {
	var gotPath string
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"input_tokens":42}`))
	})

	res, err := conn.Execute(context.Background(), "messages_count_tokens", map[string]any{
		"model":    "claude-sonnet-4-5",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotPath != "/v1/messages/count_tokens" {
		t.Errorf("upstream path = %q, want /v1/messages/count_tokens", gotPath)
	}
	resMap, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("result is not a map: %T", res)
	}
	if resMap["input_tokens"] != float64(42) {
		t.Errorf("input_tokens = %v, want 42", resMap["input_tokens"])
	}
}

// TestExecute_UnknownOperationFailsCleanly is the regression for the
// "unknown op silently 500s" bug class — explicit error, not panic.
func TestExecute_UnknownOperationFailsCleanly(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for unknown op")
	})
	_, err := conn.Execute(context.Background(), "messages_create_streaming", nil)
	if err == nil {
		t.Fatal("expected error for unknown op")
	}
	if !strings.Contains(err.Error(), "unknown operation") {
		t.Errorf("expected 'unknown operation' in error, got %v", err)
	}
}

// TestValidate_ProbesCountTokens confirms Validate() hits count_tokens
// (the cheapest verifiable endpoint) and considers the connection
// healthy iff the response carries input_tokens.
func TestValidate_ProbesCountTokens(t *testing.T) {
	var gotPath string
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"input_tokens":3}`))
	})

	if err := conn.Validate(context.Background()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if gotPath != "/v1/messages/count_tokens" {
		t.Errorf("Validate hit %q, want /v1/messages/count_tokens", gotPath)
	}
}

// TestValidate_FailsOnMissingInputTokens guards against a server that
// 200s with an empty body or wrong shape — Sieve should treat that as
// an unhealthy connection, not a healthy one.
func TestValidate_FailsOnMissingInputTokens(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})

	err := conn.Validate(context.Background())
	if err == nil {
		t.Fatal("Validate should fail when response lacks input_tokens")
	}
}

// TestOperations_CatalogShape catches accidental rename / removal of
// the v1 operations. If we ever drop messages_create from the catalog,
// every bound policy fails at execute time; this surfaces the breakage
// at compile-of-tests time.
func TestOperations_CatalogShape(t *testing.T) {
	c, err := Factory()(map[string]any{"api_key": "sk-ant-abc"})
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	want := map[string]bool{
		"messages_create":       false,
		"messages_count_tokens": true, // ReadOnly
	}
	got := make(map[string]bool)
	for _, op := range c.Operations() {
		got[op.Name] = op.ReadOnly
	}
	for name, ro := range want {
		actual, present := got[name]
		if !present {
			t.Errorf("operation %q missing from catalog", name)
			continue
		}
		if actual != ro {
			t.Errorf("operation %q: ReadOnly = %v, want %v", name, actual, ro)
		}
	}
}
