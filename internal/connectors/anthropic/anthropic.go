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
	"net/netip"
	"time"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/httpguard"
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
		Operations:  operations,
		// messages_create takes `model` (string) and a required numeric
		// max_tokens — expose both as rule conditions so operators can gate which
		// models an agent may call and cap output length per request.
		RuleConditions: []connector.RuleCondition{
			{
				Key:     "model",
				Label:   "Model",
				Kind:    "one_of",
				CtxPath: "context.param.model",
				Help:    "Allow (or, on a deny rule, block) specific models — comma-separated, e.g. claude-opus-4-8, claude-sonnet-4-6",
				Ops:     []string{"messages_create"},
			},
			{
				Key:     "max_tokens",
				Label:   "Max tokens",
				Kind:    "number",
				CtxPath: "context.param.max_tokens",
				Help:    "Cap max_tokens per request",
				Ops:     []string{"messages_create"},
			},
		},
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
			{
				Name:     "outbound_allowlist",
				Label:    "Outbound allow-list (CIDRs)",
				Type:     "textarea",
				EditOnly: true,
				Editable: true,
				HelpText: "Opt CIDRs into httpguard's outbound-host allow-list. Empty = block private / loopback / link-local. Set to 127.0.0.0/8 for a local mock; the operator's actual production allow-list otherwise. One entry per line.",
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
		// Outbound HTTP client guarded by httpguard so the
		// operator-overridable base_url cannot point at cloud-metadata
		// or intranet hosts. The per-connection outbound_allowlist
		// (parsed from raw config) opts specific CIDRs in — needed for
		// integration tests that point base_url at a 127.0.0.1
		// httptest.Server, and for Vertex/Bedrock gateways that live on
		// private VPC ranges in operator deployments.
		allowlistStrings, _ := raw["outbound_allowlist"].([]string)
		if allowlistStrings == nil {
			if rs, ok := raw["outbound_allowlist"].([]any); ok {
				for _, v := range rs {
					if s, ok := v.(string); ok {
						allowlistStrings = append(allowlistStrings, s)
					}
				}
			}
		}
		var allowlist []netip.Prefix
		if len(allowlistStrings) > 0 {
			var err error
			allowlist, err = httpguard.ParseCIDRs(allowlistStrings)
			if err != nil {
				return nil, fmt.Errorf("anthropic: outbound_allowlist: %w", err)
			}
		}
		client := httpguard.Client(httpguard.ClientOptions{
			Timeout:   60 * time.Second,
			Allowlist: allowlist,
		})
		return &Connector{cfg: cfg, httpClient: client}, nil
	}
}

// Type returns the connector type string.
func (a *Connector) Type() string { return ConnectorType }

// ConfigSchemaKeys implements connector.ConfigSchemaProvider. The Anthropic
// Config struct uses Go field names without json tags (raw config map is
// indexed by string literals in parseConfig), so the persisted key set is
// declared explicitly here. Architecture test verifies these are covered
// by Meta().SetupFields.
//
// outbound_allowlist is read by Factory (NOT by parseConfig / Config struct)
// for the httpguard CIDR opt-in. It's persisted alongside the typed
// fields and must be declared.
func (a *Connector) ConfigSchemaKeys() []string {
	return []string{"api_key", "base_url", "anthropic_version", "outbound_allowlist"}
}

// Operations returns the catalog of operations this connector exposes.
func (a *Connector) Operations() []connector.OperationDef { return operations }

// validateModel is the model name Validate uses to probe the API. Picked
// because count_tokens with haiku is the cheapest call that exercises
// the auth + transport path. If a specific account or gateway has this
// model disabled, the probe will return a non-401 4xx — Validate treats
// that as success (see comment below) rather than blocking the
// connection from being saved.
const validateModel = "claude-haiku-4-5"

// Validate confirms the API key is accepted by the upstream by calling
// /v1/messages/count_tokens.
//
// The semantics are deliberately narrow: Validate returns an error ONLY
// when the upstream rejects the API key (ErrNeedsReauth). Any other
// outcome — model not enabled on the operator's account, gateway
// allow-list rejection, a transient 5xx, a network blip — leaves
// Validate succeeding. Two reasons:
//
//  1. Failing Validate prevents the connection from being saved at
//     all. Refusing to save because the operator's gateway disabled
//     claude-haiku-4-5 would be a UX regression with no security
//     benefit; the operator can switch to a working model at runtime.
//
//  2. The thing Validate is actually checking is whether the API key
//     is live. A non-401 upstream response (structured or otherwise)
//     means the key was accepted far enough for the upstream to give
//     us a specific answer, which is sufficient evidence.
//
// Transport errors fall through to "OK" too — they'd repeat on first
// agent call, and refusing to save during a transient outage is bad
// UX. The operator will see the real error in the audit log on first
// use.
func (a *Connector) Validate(ctx context.Context) error {
	_, err := a.doRequest(ctx, "POST", "/v1/messages/count_tokens", map[string]any{
		"model":    validateModel,
		"messages": []map[string]any{{"role": "user", "content": "ping"}},
	})
	if errors.Is(err, connector.ErrNeedsReauth) {
		return err
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
	//
	// json.Unmarshal of the literal `null` into a map succeeds with
	// out == nil; treat that as "no structured body" because returning
	// a nil map on 2xx would silently confuse downstream callers.
	var out map[string]any
	jsonOK := json.Unmarshal(respBytes, &out) == nil && out != nil

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
			return formatUpstreamError(method, path, resp.StatusCode, errType, errMsg, connector.ErrNeedsReauth)
		}
		return formatUpstreamError(method, path, resp.StatusCode, errType, errMsg, nil, respBytes)
	}

	// 2xx without a parseable body shouldn't happen against the real
	// Anthropic API, but a proxy frontend (or a future content-type
	// negotiation gone wrong) could produce it. Fail loudly rather
	// than returning nil out, which downstream callers would
	// nil-dereference. (Includes the JSON-literal-null case, which
	// json.Unmarshal "successfully" decodes to a nil map.)
	if !jsonOK {
		return nil, fmt.Errorf("anthropic: %s %s: 2xx response was not a valid JSON object; body: %s",
			method, path, truncate(respBytes, 256))
	}

	return out, nil
}

// formatUpstreamError renders a clean error message regardless of
// which combination of envelope fields the upstream populated. The
// four shapes we observe in the wild:
//
//   - errType + errMsg both set         → "<status> <type>: <message>"
//   - errType set, errMsg empty         → "<status> <type>"
//   - errType empty, errMsg set         → "<status>: <message>"
//   - both empty (plain text / null)    → "status <code>" (+ body excerpt
//     if no wrap target)
//
// Without this consolidation we'd get dangling ": " or ": :"
// substrings in audit rows and agent-visible error responses.
//
// The trailing body excerpt is included only when there's no envelope
// AND no wrap target (i.e. plain 5xx). Reauth path always wraps
// ErrNeedsReauth and omits the excerpt.
func formatUpstreamError(method, path string, status int, errType, errMsg string, wrap error, body ...[]byte) (map[string]any, error) {
	var typeAndMsg string
	switch {
	case errType != "" && errMsg != "":
		typeAndMsg = errType + ": " + errMsg
	case errType != "":
		typeAndMsg = errType
	case errMsg != "":
		typeAndMsg = errMsg
	}

	if wrap != nil {
		if typeAndMsg == "" {
			return nil, fmt.Errorf("anthropic: %s %s: status %d: %w",
				method, path, status, wrap)
		}
		return nil, fmt.Errorf("anthropic: %s %s: %d %s: %w",
			method, path, status, typeAndMsg, wrap)
	}

	if typeAndMsg != "" {
		return nil, fmt.Errorf("anthropic: %s %s: %d %s",
			method, path, status, typeAndMsg)
	}
	// No envelope, no wrap target — include the body excerpt so
	// audit + agent see something actionable.
	if len(body) > 0 && len(body[0]) > 0 {
		return nil, fmt.Errorf("anthropic: %s %s: status %d, body: %s",
			method, path, status, truncate(body[0], 256))
	}
	return nil, fmt.Errorf("anthropic: %s %s: status %d", method, path, status)
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
// present-but-non-positive (for numeric counts).
//
// It covers the three shapes a required Messages API param can take:
//
//   - strings (model, system) — empty string treated as missing
//   - slices ([]any "messages") — empty array treated as missing
//   - numbers (max_tokens) — non-positive treated as missing.
//     Anthropic requires max_tokens > 0; the connector enforces the
//     same contract locally. JSON-decoded missing keys come through
//     as float64(0), so zero is the natural sentinel — but a caller
//     who explicitly passes max_tokens=-1 would also slip through if
//     we only rejected zero, and Anthropic would respond with a
//     confusing 400. Reject the whole non-positive half-line.
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
		if x <= 0 {
			return errors.New("anthropic: param " + key + " must be > 0")
		}
	case int:
		if x <= 0 {
			return errors.New("anthropic: param " + key + " must be > 0")
		}
	case int64:
		if x <= 0 {
			return errors.New("anthropic: param " + key + " must be > 0")
		}
	}
	return nil
}
