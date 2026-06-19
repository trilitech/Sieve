// Package mcpproxy implements an MCP proxy connector for Sieve. It connects
// to an upstream MCP server (via SSE or Streamable HTTP transport), discovers
// its tools, and exposes them as connector operations. Each tool call goes
// through Sieve's policy pipeline before being forwarded upstream.
// This enables Sieve to sit in front of any MCP server (database tools,
// filesystem tools, third-party integrations) and enforce fine-grained
// policies on tool calls — the agent doesn't know it's not talking directly
// to the upstream server.
// Connection config:
//
//	{
//	  "url": "http://localhost:3000/mcp",
//	  "auth_header": "Authorization",   // optional
//	  "auth_value": "Bearer sk-xxx",    // optional
//	  "name": "my-mcp-server"           // display name for the server
//	}
package mcpproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/httpguard"
)

// ErrResponseOversized indicates the upstream tools/call response body
// exceeded the connection's response_body_cap_bytes setting. Callers map
// this to audit policy_result "mcp_proxy.response_oversized".
var ErrResponseOversized = errors.New("mcp_proxy: upstream response oversized")

// defaultMCPResponseCap is the default upstream response body size cap.
// Mirrors internal/connectors/github/client.go::maxResponseBytes (5 MiB).
// Operators MAY override per-connection via response_body_cap_bytes.
const defaultMCPResponseCap int64 = 5 << 20

var Meta = connector.ConnectorMeta{
	Type:        "mcp_proxy",
	Name:        "MCP Proxy",
	Description: "Proxy to an upstream MCP server — apply Sieve policies to any MCP tool",
	Category:    "Proxy",
	SetupFields: []connector.Field{
		{Name: "url", Label: "MCP Server URL", Type: "text", Required: true, Editable: true, Placeholder: "http://localhost:3000/mcp"},
		{Name: "target_url", Label: "Target URL (legacy alias)", Type: "text", Editable: false, EditOnly: true,
			HelpText: "Legacy/compatibility alias for url. Factory reads target_url as a fallback when url is absent (older rows persisted via the web form handler used this name). Declared here so the architecture test sees the full persisted shape; new configs should set url instead."},
		{Name: "auth_header", Label: "Auth Header (optional)", Type: "text", Required: false, Editable: true, Placeholder: "Authorization"},
		{Name: "auth_value", Label: "Auth Value (optional)", Type: "password", Required: false, Editable: true, Secret: true, Placeholder: "Bearer sk-...",
			HelpText: "Leave blank on edit to keep the stored value."},
		{Name: "name", Label: "Server Name", Type: "text", Required: false, Editable: true, Placeholder: "my-mcp-server"},
		{Name: "response_body_cap_bytes", Label: "Upstream response body cap (bytes)", Type: "number", EditOnly: true, Editable: true, Placeholder: "5242880",
			HelpText: "Maximum bytes Sieve reads from a tools/call upstream response. 0 or empty = 5 MiB default."},
		{Name: "outbound_allowlist", Label: "Outbound allow-list (CIDRs)", Type: "textarea", EditOnly: true, Editable: true,
			HelpText: "Opt CIDRs into httpguard's outbound-host allow-list. Empty = block private / loopback / link-local. Set to 127.0.0.0/8 for a local mock. One entry per line."},
	},
}

// jsonRPCRequest is a JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// jsonRPCResponse is a JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// upstreamTool describes a tool from the upstream MCP server.
type upstreamTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// MCPProxyConnector proxies to an upstream MCP server.
type MCPProxyConnector struct {
	url             string
	authHeader      string
	authValue       string
	serverName      string
	responseBodyCap int64 // bytes; 0 means use defaultMCPResponseCap
	client          *http.Client
	tools           []upstreamTool
	toolsByName     map[string]upstreamTool
	mu              sync.RWMutex
	initialized     bool
}

func Factory(config map[string]any) (connector.Connector, error) {
	url, _ := config["url"].(string)
	if url == "" {
		// Also check target_url for compatibility with the web form handler.
		url, _ = config["target_url"].(string)
	}
	if url == "" {
		return nil, fmt.Errorf("mcp_proxy: missing url")
	}

	authHeader, _ := config["auth_header"].(string)
	authValue, _ := config["auth_value"].(string)
	serverName, _ := config["name"].(string)
	if serverName == "" {
		serverName = "upstream"
	}

	// response_body_cap_bytes: positive integer overrides the default;
	// missing or zero falls back to defaultMCPResponseCap (5 MiB);
	// negative is rejected as a config-load error so operators don't
	// silently get an effectively-unbounded behaviour.
	bodyCap := defaultMCPResponseCap
	if raw, ok := config["response_body_cap_bytes"]; ok {
		switch v := raw.(type) {
		case int:
			if v < 0 {
				return nil, fmt.Errorf("mcp_proxy: response_body_cap_bytes must be positive, got %d", v)
			}
			if v > 0 {
				bodyCap = int64(v)
			}
		case int64:
			if v < 0 {
				return nil, fmt.Errorf("mcp_proxy: response_body_cap_bytes must be positive, got %d", v)
			}
			if v > 0 {
				bodyCap = v
			}
		case float64:
			if v < 0 {
				return nil, fmt.Errorf("mcp_proxy: response_body_cap_bytes must be positive, got %g", v)
			}
			if v > 0 {
				bodyCap = int64(v)
			}
		}
	}

	// Outbound SSRF guard: the underlying HTTP client is httpguard.Client,
	// which replaces the previous default http.Client — that one allowed
	// redirects with no destination check. httpguard.Client enforces
	// scheme/IP-range deny rules on the first request and on every
	// redirect, including DNS-rebinding protection at dial time. The
	// per-connection outbound_allowlist field lets the operator opt in
	// to private/intranet destinations.
	allowlistStrings, _ := config["outbound_allowlist"].([]string)
	if allowlistStrings == nil {
		// JSON-decoded form may arrive as []any.
		if raw, ok := config["outbound_allowlist"].([]any); ok {
			for _, v := range raw {
				if s, ok := v.(string); ok {
					allowlistStrings = append(allowlistStrings, s)
				}
			}
		}
	}
	allowlist, err := httpguard.ParseCIDRs(allowlistStrings)
	if err != nil {
		return nil, fmt.Errorf("mcp_proxy: outbound_allowlist: %w", err)
	}

	return &MCPProxyConnector{
		url:             url,
		authHeader:      authHeader,
		authValue:       authValue,
		serverName:      serverName,
		responseBodyCap: bodyCap,
		client: httpguard.Client(httpguard.ClientOptions{
			Allowlist: allowlist,
			Timeout:   2 * time.Minute,
		}),
		toolsByName: make(map[string]upstreamTool),
	}, nil
}

func (m *MCPProxyConnector) Type() string { return "mcp_proxy" }

// ConfigSchemaKeys implements connector.ConfigSchemaProvider. mcp_proxy
// reads from a free-form map (no typed Config struct), so the persisted-key
// list is declared explicitly. The architecture test verifies these are
// covered by Meta().SetupFields.
func (m *MCPProxyConnector) ConfigSchemaKeys() []string {
	return []string{
		"url",
		"target_url", // legacy alias Factory reads as fallback when url is absent
		"auth_header",
		"auth_value",
		"name",
		"response_body_cap_bytes",
		"outbound_allowlist",
	}
}

// NormalizeForEdit implements connector.EditConfigNormalizer. Promotes the
// legacy target_url alias to url so the edit form's required url field is
// pre-filled for older rows; deletes the alias unconditionally so the
// next save persists only the canonical key. Idempotent — running it on
// an already-canonical config is a no-op.
func (m *MCPProxyConnector) NormalizeForEdit(cfg map[string]any) map[string]any {
	if u, _ := cfg["url"].(string); u == "" {
		if alias, _ := cfg["target_url"].(string); alias != "" {
			cfg["url"] = alias
		}
	}
	delete(cfg, "target_url")
	return cfg
}

// discoverTools calls tools/list on the upstream server to discover available tools.
func (m *MCPProxyConnector) discoverTools(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.initialized {
		return nil
	}

	// First initialize the upstream server.
	initResp, err := m.callUpstream(ctx, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "sieve-proxy", "version": "0.1.0"},
	})
	if err != nil {
		return fmt.Errorf("mcp_proxy: initialize upstream: %w", err)
	}
	_ = initResp // We don't need the server capabilities for proxying.

	// Discover tools.
	resp, err := m.callUpstream(ctx, "tools/list", nil)
	if err != nil {
		return fmt.Errorf("mcp_proxy: discover tools: %w", err)
	}

	var result struct {
		Tools []upstreamTool `json:"tools"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("mcp_proxy: parse tools list: %w", err)
	}

	m.tools = result.Tools
	m.toolsByName = make(map[string]upstreamTool, len(result.Tools))
	for _, t := range result.Tools {
		m.toolsByName[t.Name] = t
	}
	m.initialized = true

	return nil
}

// Operations returns the tools discovered from the upstream server.
// Tools are discovered lazily on first call.
func (m *MCPProxyConnector) Operations() []connector.OperationDef {
	m.mu.RLock()
	initialized := m.initialized
	m.mu.RUnlock()

	if !initialized {
		if err := m.discoverTools(context.Background()); err != nil {
			// Return empty if we can't reach the upstream server.
			return nil
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	ops := make([]connector.OperationDef, 0, len(m.tools))
	for _, t := range m.tools {
		// Convert the upstream tool's inputSchema into ParamDefs.
		params := make(map[string]connector.ParamDef)
		if props, ok := t.InputSchema["properties"].(map[string]any); ok {
			required := make(map[string]bool)
			if reqList, ok := t.InputSchema["required"].([]any); ok {
				for _, r := range reqList {
					if s, ok := r.(string); ok {
						required[s] = true
					}
				}
			}
			for name, schema := range props {
				desc := ""
				typ := "string"
				if schemaMap, ok := schema.(map[string]any); ok {
					if d, ok := schemaMap["description"].(string); ok {
						desc = d
					}
					if t, ok := schemaMap["type"].(string); ok {
						typ = t
					}
				}
				params[name] = connector.ParamDef{
					Type:        typ,
					Description: desc,
					Required:    required[name],
				}
			}
		}

		ops = append(ops, connector.OperationDef{
			Name:        t.Name,
			Description: t.Description,
			Params:      params,
		})
	}

	return ops
}

// Execute forwards a tool call to the upstream MCP server.
func (m *MCPProxyConnector) Execute(ctx context.Context, op string, params map[string]any) (any, error) {
	if !m.initialized {
		if err := m.discoverTools(ctx); err != nil {
			return nil, err
		}
	}

	m.mu.RLock()
	_, exists := m.toolsByName[op]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("mcp_proxy: unknown tool %q", op)
	}

	// Forward the tool call to the upstream server.
	resp, err := m.callUpstream(ctx, "tools/call", map[string]any{
		"name":      op,
		"arguments": params,
	})
	if err != nil {
		return nil, fmt.Errorf("mcp_proxy: call tool %q: %w", op, err)
	}

	// Parse the upstream response.
	var result any
	if err := json.Unmarshal(resp, &result); err != nil {
		// Return raw JSON string if parsing fails.
		return string(resp), nil
	}

	return result, nil
}

// Validate checks connectivity to the upstream server.
func (m *MCPProxyConnector) Validate(ctx context.Context) error {
	return m.discoverTools(ctx)
}

// callUpstream sends a JSON-RPC request to the upstream MCP server and
// returns the result field from the response.
func (m *MCPProxyConnector) callUpstream(ctx context.Context, method string, params any) (json.RawMessage, error) {
	reqBody := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  method,
		Params:  params,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", m.url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Inject auth if configured.
	if m.authHeader != "" && m.authValue != "" {
		httpReq.Header.Set(m.authHeader, m.authValue)
	}

	resp, err := m.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	// Cap upstream response body at responseBodyCap bytes (default 5 MiB)
	// to defend against malicious or compromised upstreams that stream
	// unbounded responses and exhaust connector memory. Pattern mirrors
	// internal/connectors/github/client.go::doRequest. Reads bodyCap+1 so
	// "exactly bodyCap" is allowed and "bodyCap+1 or more" trips the overflow check.
	bodyCap := m.responseBodyCap
	if bodyCap <= 0 {
		bodyCap = defaultMCPResponseCap
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, bodyCap+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(respBody)) > bodyCap {
		return nil, fmt.Errorf("%w: response exceeded %d byte cap", ErrResponseOversized, bodyCap)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("upstream error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}
