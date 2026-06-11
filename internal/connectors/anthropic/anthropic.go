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
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("anthropic: read response: %w", err)
	}

	var out map[string]any
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("anthropic: decode response (status %d): %w; body: %s",
			resp.StatusCode, err, truncate(respBytes, 256))
	}

	if resp.StatusCode/100 != 2 {
		// Anthropic returns {"type":"error","error":{"type":"...", "message":"..."}}.
		// Surface that to callers so audit + agents see the upstream reason.
		if errObj, ok := out["error"].(map[string]any); ok {
			errType, _ := errObj["type"].(string)
			errMsg, _ := errObj["message"].(string)
			return nil, fmt.Errorf("anthropic: %s %s: %d %s: %s",
				method, path, resp.StatusCode, errType, errMsg)
		}
		return nil, fmt.Errorf("anthropic: %s %s: status %d, body: %s",
			method, path, resp.StatusCode, truncate(respBytes, 256))
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

// ensureNonEmpty is a small helper to surface a clearer error than
// "key not found" when a required param is missing.
func ensureNonEmpty(params map[string]any, key string) error {
	v, ok := params[key]
	if !ok {
		return fmt.Errorf("anthropic: missing required param %q", key)
	}
	if s, ok := v.(string); ok && s == "" {
		return errors.New("anthropic: param " + key + " is empty")
	}
	return nil
}
