// Package anthropic implements a typed Sieve connector for Anthropic's
// Messages API.
//
// Why this exists alongside http_proxy: http_proxy works for any HTTP API,
// but it forces every Anthropic call through a single proxy_request
// operation, which collapses the policy surface. With this typed
// connector, each Anthropic capability gets its own operation name
// (messages_create, messages_count_tokens), so policies can bind to them
// individually — an archival role can grant only messages_count_tokens,
// or a budget-conscious role can deny messages_create but allow the
// cheaper count_tokens call.
//
// Auth model: simple. Anthropic uses an API key in the `x-api-key`
// header. The key lives in the connection config (envelope-encrypted at
// rest via Sieve's keyring path). No OAuth, no token refresh.
//
// Streaming + Batches are deliberately not in v1 — streaming requires a
// different return shape than (any, error), and Batches add async
// lifecycle complexity. Filed as follow-ups.
package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/trilitech/Sieve/internal/connector"
)

// ConnectorType is the registry type string for this connector.
const ConnectorType = "anthropic"

// defaultBaseURL is the production Anthropic API root. Operators
// override via `base_url` config (e.g., for the Anthropic Bedrock
// integration, a Vertex AI gateway, or a local mock).
const defaultBaseURL = "https://api.anthropic.com"

// defaultAnthropicVersion is the API version header value. Anthropic
// requires this header on every request; the operator may override per
// connection if a future stable rev requires a bump.
const defaultAnthropicVersion = "2023-06-01"

// Connector implements connector.Connector for Anthropic's Messages API.
type Connector struct {
	cfg        *Config
	httpClient *http.Client
}

// Meta returns the registry metadata.
func Meta() connector.ConnectorMeta {
	return connector.ConnectorMeta{
		Type:        ConnectorType,
		Name:        "Anthropic (Claude)",
		Description: "Call Claude models via Anthropic's Messages API with per-operation policy gating.",
		Category:    "LLM",
		SetupFields: []connector.Field{
			{
				Name:        "api_key",
				Label:       "API Key",
				Type:        "password",
				Required:    true,
				Placeholder: "sk-ant-api03-...",
				HelpText:    "Your Anthropic API key. Generated at console.anthropic.com.",
			},
			{
				Name:        "base_url",
				Label:       "Base URL",
				Type:        "text",
				Required:    false,
				Placeholder: defaultBaseURL,
				HelpText:    "Override to point at a Vertex AI gateway or a local mock. Defaults to the public Anthropic API.",
			},
			{
				Name:        "anthropic_version",
				Label:       "API Version",
				Type:        "text",
				Required:    false,
				Placeholder: defaultAnthropicVersion,
				HelpText:    "anthropic-version header. Leave blank for the current default.",
			},
		},
	}
}

// Factory returns a connector.Factory that builds Anthropic Connectors
// from operator-supplied config.
func Factory() connector.Factory {
	return func(raw map[string]any) (connector.Connector, error) {
		cfg, err := parseConfig(raw)
		if err != nil {
			return nil, err
		}
		// Outbound HTTP client with conservative timeouts. When the
		// internal/httpguard package lands (PR #11) this should swap to
		// httpguard.Client so operator-overridable base_url inherits the
		// project's SSRF defense.
		client := &http.Client{Timeout: 60 * time.Second}
		return &Connector{cfg: cfg, httpClient: client}, nil
	}
}

// Type returns the connector type string.
func (a *Connector) Type() string { return ConnectorType }

// Operations returns the catalog of operations this connector exposes.
func (a *Connector) Operations() []connector.OperationDef { return operations }

// Validate confirms the API key works by calling /v1/messages/count_tokens
// with a minimal payload. count_tokens is the cheapest verifiable endpoint
// — it doesn't bill against the model's request quota and returns a
// structured response we can sanity-check.
func (a *Connector) Validate(ctx context.Context) error {
	payload := map[string]any{
		"model":    "claude-haiku-4-5",
		"messages": []map[string]any{{"role": "user", "content": "ping"}},
	}
	resp, err := a.doRequest(ctx, "POST", "/v1/messages/count_tokens", payload)
	if err != nil {
		return err
	}
	if _, ok := resp["input_tokens"]; !ok {
		return fmt.Errorf("anthropic: validate: response missing input_tokens, got %v", resp)
	}
	return nil
}

// doRequest sends a JSON POST/GET to Anthropic with the configured
// headers and returns the decoded JSON body. Non-2xx responses are
// returned as errors carrying the upstream error envelope so policies +
// audit see a useful message.
func (a *Connector) doRequest(ctx context.Context, method, path string, body any) (map[string]any, error) {
	url := a.cfg.BaseURL + path

	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("anthropic: marshal request: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("anthropic: build request: %w", err)
	}
	req.Header.Set("x-api-key", a.cfg.APIKey)
	req.Header.Set("anthropic-version", a.cfg.AnthropicVersion)
	if reqBody != nil {
		req.Header.Set("content-type", "application/json")
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anthropic: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	// Cap the response body so a misbehaving (or hostile) upstream
	// can't drive us out of memory. 16 MiB is far above any legitimate
	// Anthropic response — count_tokens returns a few bytes, and a
	// completion at max_tokens=8192 with full content blocks is well
	// under a megabyte.
	const maxResponseBytes = 16 << 20
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("anthropic: read response: %w", err)
	}
	if int64(len(respBytes)) > maxResponseBytes {
		return nil, fmt.Errorf("anthropic: %s %s: upstream response exceeded %d byte cap",
			method, path, maxResponseBytes)
	}

	// JSON-decode opportunistically. Failure here is treated as
	// "no structured body" rather than fatal, because non-2xx
	// responses from proxy frontends are often plain text ("502 Bad
	// Gateway") and we still need to surface those — especially 401,
	// which must map to ErrNeedsReauth regardless of body shape.
	var out map[string]any
	jsonOK := json.Unmarshal(respBytes, &out) == nil

	if resp.StatusCode/100 != 2 {
		var errType, errMsg string
		if jsonOK {
			if errObj, ok := out["error"].(map[string]any); ok {
				errType, _ = errObj["type"].(string)
				errMsg, _ = errObj["message"].(string)
			}
		}
		// Auth-class failures must wrap connector.ErrNeedsReauth so the
		// API + MCP layers map them to a structured 403 + reauth_url
		// rather than an opaque 500. Status 401 alone is sufficient —
		// errType is the belt-and-suspenders cover for upstream shape
		// drift (e.g. a proxy frontend returning 403 with an
		// authentication_error envelope).
		if resp.StatusCode == http.StatusUnauthorized || errType == "authentication_error" {
			if errType == "" && errMsg == "" {
				// No structured body; surface a clean message without
				// empty ": :" placeholders.
				return nil, fmt.Errorf("anthropic: %s %s: status %d: %w",
					method, path, resp.StatusCode, connector.ErrNeedsReauth)
			}
			return nil, fmt.Errorf("anthropic: %s %s: %d %s: %s: %w",
				method, path, resp.StatusCode, errType, errMsg, connector.ErrNeedsReauth)
		}
		if errType != "" {
			return nil, fmt.Errorf("anthropic: %s %s: %d %s: %s",
				method, path, resp.StatusCode, errType, errMsg)
		}
		return nil, fmt.Errorf("anthropic: %s %s: status %d, body: %s",
			method, path, resp.StatusCode, truncate(respBytes, 256))
	}

	// 2xx without a parseable body shouldn't happen against the real
	// Anthropic API, but a proxy frontend (or a future content-type
	// negotiation gone wrong) could produce it. Fail loudly rather
	// than returning nil out, which downstream callers would
	// nil-dereference.
	if !jsonOK {
		return nil, fmt.Errorf("anthropic: %s %s: 2xx response was not valid JSON; body: %s",
			method, path, truncate(respBytes, 256))
	}

	return out, nil
}

// truncate caps a byte slice for inclusion in error strings so we don't
// dump multi-KB responses into the audit log.
func truncate(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "...(truncated)"
}

// ensureNonEmpty surfaces a clearer error than "key not found" when a
// required param is missing, present-but-nil, present-but-empty, or
// present-but-zero (for numeric counts).
//
// It covers the three shapes a required Messages API param can take:
//
//   - strings (model, system) — empty string treated as missing
//   - slices ([]any "messages") — empty array treated as missing
//   - numbers (max_tokens) — zero treated as missing, since Anthropic
//     requires max_tokens > 0 and JSON decoding turns missing keys
//     into the default zero value
//
// Without this, the connector would happily POST `{"messages": [],
// "max_tokens": 0}` to Anthropic and surface a confusing upstream 400
// instead of catching the obvious mistake locally.
func ensureNonEmpty(params map[string]any, key string) error {
	v, ok := params[key]
	if !ok || v == nil {
		return fmt.Errorf("anthropic: missing required param %q", key)
	}
	switch x := v.(type) {
	case string:
		if x == "" {
			return errors.New("anthropic: param " + key + " is empty")
		}
	case []any:
		if len(x) == 0 {
			return errors.New("anthropic: param " + key + " is empty")
		}
	case []map[string]any:
		if len(x) == 0 {
			return errors.New("anthropic: param " + key + " is empty")
		}
	case []string:
		if len(x) == 0 {
			return errors.New("anthropic: param " + key + " is empty")
		}
	case float64:
		// JSON numbers decode to float64. max_tokens=0 is the relevant
		// "missing-shaped" case — Anthropic rejects it anyway.
		if x == 0 {
			return errors.New("anthropic: param " + key + " must be > 0")
		}
	case int:
		if x == 0 {
			return errors.New("anthropic: param " + key + " must be > 0")
		}
	case int64:
		if x == 0 {
			return errors.New("anthropic: param " + key + " must be > 0")
		}
	}
	return nil
}
