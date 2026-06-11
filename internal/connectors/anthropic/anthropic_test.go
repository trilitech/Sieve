package anthropic

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
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
		"max_cost":   0.50, // catalog declares max_cost as float; matches the wire shape clients will send
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

// TestValidate_FailsOnlyOnReauth pins the narrowed contract: Validate
// only refuses to save the connection when the upstream rejects the
// key. A non-401 4xx (e.g., model_not_found on a gateway that
// restricts which Anthropic models the operator can call) means the
// key was accepted far enough to elicit a structured rejection —
// that's evidence enough that Validate should succeed.
//
// Three scenarios cover the contract:
//   - 401 / authentication_error → Validate fails
//   - 4xx with model_not_found    → Validate succeeds (key works)
//   - 5xx                         → Validate succeeds (can't tell;
//                                   error will repeat on first agent call)
func TestValidate_FailsOnlyOnReauth(t *testing.T) {
	t.Run("401 fails", func(t *testing.T) {
		conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`))
		})
		err := conn.Validate(context.Background())
		if !errors.Is(err, connector.ErrNeedsReauth) {
			t.Errorf("401 → want ErrNeedsReauth, got %v", err)
		}
	})

	t.Run("model_not_found succeeds", func(t *testing.T) {
		conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"not_found_error","message":"model not enabled for this account"}}`))
		})
		err := conn.Validate(context.Background())
		if err != nil {
			t.Errorf("model_not_found should leave Validate succeeding (key works); got %v", err)
		}
	})

	t.Run("5xx succeeds", func(t *testing.T) {
		conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"api_error","message":"overloaded"}}`))
		})
		err := conn.Validate(context.Background())
		if err != nil {
			t.Errorf("transient 5xx should not block save; got %v", err)
		}
	})
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

// TestMessagesCreate_401MapsToErrNeedsReauth pins the contract that an
// auth-class upstream failure becomes a typed ErrNeedsReauth at the
// connector boundary. The API and MCP layers branch on
// errors.Is(err, connector.ErrNeedsReauth) to return a structured 403
// pointing the operator at the reauth flow — without this mapping a
// revoked API key would surface as a generic 500.
func TestMessagesCreate_401MapsToErrNeedsReauth(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`))
	})
	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":      "claude-sonnet-4-5",
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"max_tokens": 16,
	})
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf("error must wrap connector.ErrNeedsReauth on 401; got %v", err)
	}
	if !strings.Contains(err.Error(), "authentication_error") || !strings.Contains(err.Error(), "invalid x-api-key") {
		t.Errorf("expected upstream type + message preserved in error; got %v", err)
	}
}

// TestMessagesCreate_AuthErrorTypeWithout401Maps confirms the
// belt-and-suspenders cover: if a future upstream rev returns errType
// "authentication_error" with a non-401 status (rare but observed in
// proxy frontends), we still treat it as a reauth signal.
func TestMessagesCreate_AuthErrorTypeWithout401Maps(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"authentication_error","message":"key revoked"}}`))
	})
	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":      "claude-sonnet-4-5",
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"max_tokens": 16,
	})
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf("authentication_error must map to ErrNeedsReauth regardless of status; got %v", err)
	}
}

// TestMessagesCreate_401WithoutStructuredBodyStillMaps covers the
// case where the upstream returns a bare 401 with no error envelope
// (e.g. an upstream proxy returning text/plain "Unauthorized"). The
// status code alone is sufficient to flag a reauth need.
func TestMessagesCreate_401WithoutStructuredBodyStillMaps(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{}`))
	})
	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":      "claude-sonnet-4-5",
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"max_tokens": 16,
	})
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf("bare 401 must map to ErrNeedsReauth; got %v", err)
	}
}

// TestMessagesCreate_5xxIsNotReauthError pins the negative side of the
// contract — transient server errors must NOT trip the reauth flow.
// Otherwise a Bedrock outage would cause every operator to be told
// their API key is bad.
func TestMessagesCreate_5xxIsNotReauthError(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"api_error","message":"backend overloaded"}}`))
	})
	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":      "claude-sonnet-4-5",
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"max_tokens": 16,
	})
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf("5xx must NOT trip ErrNeedsReauth; got %v", err)
	}
}

// TestMessagesCreate_RejectsEmptyMessages ensures the local pre-flight
// catches []any{} for the messages param. Previously ensureNonEmpty
// only checked string types, so an empty array fell through.
func TestMessagesCreate_RejectsEmptyMessages(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called when messages is empty")
	})
	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":      "claude-sonnet-4-5",
		"messages":   []any{},
		"max_tokens": 16,
	})
	if err == nil {
		t.Fatal("expected error for empty messages")
	}
	if !strings.Contains(err.Error(), "messages") {
		t.Errorf("error should mention messages; got %v", err)
	}
}

// TestMessagesCreate_RejectsZeroMaxTokens covers the numeric-zero case
// that JSON-decoded params expose: a missing max_tokens field decodes
// to float64(0), which Anthropic would reject upstream with a
// confusing 400. Catch it locally.
func TestMessagesCreate_RejectsZeroMaxTokens(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called when max_tokens is 0")
	})
	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":      "claude-sonnet-4-5",
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"max_tokens": float64(0),
	})
	if err == nil {
		t.Fatal("expected error for max_tokens=0")
	}
	if !strings.Contains(err.Error(), "max_tokens") {
		t.Errorf("error should mention max_tokens; got %v", err)
	}
}

// TestMessagesCreate_StripsStreamFalseFromOutboundBody pins the
// contract that this connector NEVER sends a stream field upstream,
// regardless of what callers pass. stream=true is rejected; stream=false
// is dropped silently so the outbound body shape is deterministic.
func TestMessagesCreate_StripsStreamFalseFromOutboundBody(t *testing.T) {
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
		"stream":     false,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, present := receivedBody["stream"]; present {
		t.Errorf("stream=false leaked to upstream body: %v", receivedBody)
	}
}

// TestMessagesCountTokens_RejectsEmptyMessages covers the same
// empty-array guard on the count_tokens path.
func TestMessagesCountTokens_RejectsEmptyMessages(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called when messages is empty")
	})
	_, err := conn.Execute(context.Background(), "messages_count_tokens", map[string]any{
		"model":    "claude-sonnet-4-5",
		"messages": []any{},
	})
	if err == nil {
		t.Fatal("expected error for empty messages")
	}
}

// TestOperationsParamTypes_MatchAnthropicSchema pins the param types
// against the wire shapes Anthropic actually expects. Drift here would
// cause the MCP tool catalog to advertise wrong types and clients to
// send malformed requests that fail upstream with confusing errors.
func TestOperationsParamTypes_MatchAnthropicSchema(t *testing.T) {
	want := map[string]map[string]string{
		"messages_create": {
			"model":          "string",
			"messages":       "[]object",
			"max_tokens":     "int",
			"temperature":    "float",
			"top_p":          "float",
			"top_k":          "int",
			"stop_sequences": "[]string",
			"metadata":       "object",
			"tools":          "[]object",
			"tool_choice":    "object",
			"max_cost":       "float",
		},
		"messages_count_tokens": {
			"model":       "string",
			"messages":    "[]object",
			"tools":       "[]object",
			"tool_choice": "object",
		},
	}
	for _, op := range operations {
		wantParams, ok := want[op.Name]
		if !ok {
			continue
		}
		for name, expectedType := range wantParams {
			got, present := op.Params[name]
			if !present {
				t.Errorf("%s: param %q missing", op.Name, name)
				continue
			}
			if got.Type != expectedType {
				t.Errorf("%s: param %q type = %q, want %q", op.Name, name, got.Type, expectedType)
			}
		}
	}
}

// TestDoRequest_PlainText401MapsToReauth covers the proxy-frontend
// shape: a 401 with no JSON envelope (e.g. text/plain "Unauthorized"
// from a corporate LLM gateway). Even though the body can't be
// decoded, the status code alone must drive the reauth mapping.
func TestDoRequest_PlainText401MapsToReauth(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized"))
	})
	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":      "claude-sonnet-4-5",
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"max_tokens": 16,
	})
	if err == nil {
		t.Fatal("expected error on plain-text 401")
	}
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf("plain-text 401 must wrap ErrNeedsReauth; got %v", err)
	}
}

// TestDoRequest_PlainText500NotReauth pins the negative side for the
// non-JSON case — a plain-text 502 from a flaky proxy must not be
// mistaken for an auth problem.
func TestDoRequest_PlainText500NotReauth(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("502 Bad Gateway"))
	})
	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":      "claude-sonnet-4-5",
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"max_tokens": 16,
	})
	if err == nil {
		t.Fatal("expected error on 502")
	}
	if errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf("plain-text 5xx must NOT trip ErrNeedsReauth; got %v", err)
	}
	if !strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Errorf("error should preserve upstream body excerpt; got %v", err)
	}
}

// TestDoRequest_401EmptyEnvelopeNoPlaceholderColons confirms the
// formatting fix for the {"error": null} / {} case: the rendered
// message must not contain dangling ": :" placeholders where errType
// and errMsg would have gone.
func TestDoRequest_401EmptyEnvelopeNoPlaceholderColons(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{}`))
	})
	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":      "claude-sonnet-4-5",
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"max_tokens": 16,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf("must still wrap ErrNeedsReauth; got %v", err)
	}
	if strings.Contains(err.Error(), ": :") {
		t.Errorf("error must not contain empty \": :\" placeholders; got %q", err.Error())
	}
}

// TestDoRequest_OversizedResponseCappedCleanly verifies that a
// massively oversized upstream response is rejected with a clean
// error rather than consuming unbounded memory. The 16 MiB cap is
// chosen far above any legitimate Messages API response.
func TestDoRequest_OversizedResponseCappedCleanly(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		// 20 MiB of garbage — exceeds the 16 MiB cap. Writing in
		// 64-KiB chunks keeps the test fast.
		chunk := make([]byte, 64*1024)
		for i := 0; i < 320; i++ {
			_, _ = w.Write(chunk)
		}
	})
	_, err := conn.Execute(context.Background(), "messages_create", map[string]any{
		"model":      "claude-sonnet-4-5",
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"max_tokens": 16,
	})
	if err == nil {
		t.Fatal("expected error on oversized response")
	}
	if !strings.Contains(err.Error(), "byte cap") {
		t.Errorf("error should mention the cap; got %v", err)
	}
}

// TestParseConfig_RejectsWrongPrefixWithoutEchoingKey verifies the
// secret-hygiene fix: the rejection error must not contain any portion
// of the supplied key (since errors land in logs and audit rows).
func TestParseConfig_RejectsWrongPrefixWithoutEchoingKey(t *testing.T) {
	bogus := "sk-openai-abcdef-do-not-log-this"
	_, err := parseConfig(map[string]any{"api_key": bogus})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), bogus) ||
		strings.Contains(err.Error(), bogus[:7]) ||
		strings.Contains(err.Error(), bogus[:5]) {
		t.Errorf("error must not echo any portion of the supplied key; got %q", err.Error())
	}
}

// TestDoRequest_NullJSON2xxFailsLoudly catches the json.Unmarshal-of-
// literal-null edge case: json decodes `null` into a map by setting it
// to nil, which used to "successfully" propagate as a nil response.
// Downstream callers would nil-deref. We now treat null as no
// structured body and fail with a clear message.
func TestDoRequest_NullJSON2xxFailsLoudly(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`null`))
	})
	_, err := conn.Execute(context.Background(), "messages_count_tokens", map[string]any{
		"model":    "claude-sonnet-4-5",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	})
	if err == nil {
		t.Fatal("expected error on JSON null 2xx response")
	}
	if !strings.Contains(err.Error(), "not a valid JSON object") {
		t.Errorf("error should explain the bad shape; got %v", err)
	}
}

// TestDoRequest_ErrorEnvelopeTypeOnlyNoDanglingColon covers the
// envelope with type but no message. The previous formatter rendered
// "<status> <type>: " with a dangling colon-space; the new
// formatUpstreamError emits "<status> <type>" with no trailing
// punctuation.
func TestDoRequest_ErrorEnvelopeTypeOnlyNoDanglingColon(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error"}}`))
	})
	_, err := conn.Execute(context.Background(), "messages_count_tokens", map[string]any{
		"model":    "claude-sonnet-4-5",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "invalid_request_error") {
		t.Errorf("error should preserve type; got %q", msg)
	}
	// Reject any of the dangling-separator shapes the formatter
	// could regress to.
	for _, bad := range []string{": :", ": ,", ": \n", "invalid_request_error: "} {
		if strings.Contains(msg, bad) {
			t.Errorf("error contains dangling separator %q; full: %q", bad, msg)
		}
	}
	// And specifically — the message must NOT end on "type:" with
	// trailing whitespace where errMsg would have been.
	if strings.HasSuffix(msg, ": ") {
		t.Errorf("error ends with trailing \": \"; got %q", msg)
	}
}

// TestDoRequest_ReauthErrorEnvelopeTypeOnly covers the same shape on
// the auth path: 401 with a type but no message must still wrap
// ErrNeedsReauth with no dangling ": :" pattern.
func TestDoRequest_ReauthErrorEnvelopeTypeOnly(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"authentication_error"}}`))
	})
	_, err := conn.Execute(context.Background(), "messages_count_tokens", map[string]any{
		"model":    "claude-sonnet-4-5",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	})
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Fatalf("expected ErrNeedsReauth; got %v", err)
	}
	if strings.Contains(err.Error(), ": :") {
		t.Errorf("must not contain \": :\"; got %q", err.Error())
	}
}
