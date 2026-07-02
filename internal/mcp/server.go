// Package mcp implements the Model Context Protocol (MCP) server for Sieve.
// MCP is the protocol AI agents (e.g., Claude) use to discover and invoke tools.
// This server exposes connector operations as MCP tools, with every tool call
// passing through the policy pipeline:
// 1. Pre-execution check: Before the connector runs, the policy evaluator
// decides whether the operation is allowed, denied, or requires human
// approval. This is the primary access-control gate.
// 2. Response filtering: After the connector returns data, any ResponseFilter
// objects collected during evaluation are applied to the response. This
// enables content filtering and redaction without a second evaluation pass.
// The approval flow is non-blocking for MCP clients: when approval is required,
// the server returns immediately with an approval ID and URL. The agent can
// poll for resolution. This differs from the REST API which blocks with
// WaitForResolution (suitable for synchronous HTTP clients).
// Tool naming handles multi-connection scenarios by prefixing tool names with
// the connector type (e.g., "google_list_emails") when a token has access to
// multiple connections. Single-connection tokens get unprefixed names.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/trilitech/Sieve/internal/approval"
	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/policy"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/secrets"
	"github.com/trilitech/Sieve/internal/tokens"
)

// JSON-RPC 2.0 types

// JSONRPCRequest represents an incoming JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents an outgoing JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCP tool types

// ToolDef describes a tool exposed via MCP.
type ToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ToolCallParams holds the parameters for a tools/call request.
type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// ToolCallResult is the result returned from a tools/call invocation.
type ToolCallResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

// ContentBlock is a single content item in a tool call result.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Server implements the MCP protocol over Streamable HTTP. Policy evaluators
// are cached per token ID to avoid reconstructing them on every request.
type Server struct {
	tokens      *tokens.Service
	connections *connections.Service
	iam         *iampolicies.Service
	registry    *connector.Registry
	roles       *roles.Service
	approval    *approval.Queue
	audit       *audit.Logger
}

// decide is the MCP decision source: IAM is the sole engine. The non-blocking
// MCP approval shape is unchanged.
func (s *Server) decide(ctx context.Context, tok *tokens.Token, connType, connID, connStatus, op string, params map[string]any) (*policy.PolicyDecision, error) {
	// RBAC: the token's whole role set composes (spec §5.1).
	return s.iam.Decide(ctx, s.registry, tok.ID, tok.RoleIDs, connType, connID, connStatus, op, params)
}

// NewServer creates a new MCP Server.
func NewServer(
	tokensSvc *tokens.Service,
	connsSvc *connections.Service,
	iamSvc *iampolicies.Service,
	registry *connector.Registry,
	rolesSvc *roles.Service,
	approvalQ *approval.Queue,
	auditLog *audit.Logger,
) *Server {
	return &Server{
		tokens:      tokensSvc,
		connections: connsSvc,
		iam:         iamSvc,
		registry:    registry,
		roles:       rolesSvc,
		approval:    approvalQ,
		audit:       auditLog,
	}
}

// Handler returns an http.Handler that serves the MCP endpoint.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			s.writeError(w, nil, -32600, "only POST is supported")
			return
		}

		// Extract and validate bearer token.
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			s.writeError(w, nil, -32000, "missing or invalid Authorization header")
			return
		}
		bearerToken := strings.TrimPrefix(authHeader, "Bearer ")

		tok, err := s.tokens.Validate(bearerToken)
		if err != nil {
			s.writeError(w, nil, -32000, "invalid token: "+err.Error())
			return
		}

		// Parse JSON-RPC request.
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, nil, -32700, "parse error: "+err.Error())
			return
		}

		if req.JSONRPC != "2.0" {
			s.writeError(w, req.ID, -32600, "invalid jsonrpc version")
			return
		}

		// Dispatch by method.
		var resp *JSONRPCResponse
		switch req.Method {
		case "initialize":
			resp = s.handleInitialize(req.ID)
		case "tools/list":
			resp = s.handleToolsList(req.ID, tok)
		case "tools/call":
			resp = s.handleToolsCall(r.Context(), req.ID, tok, req.Params)
		default:
			resp = &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32601, Message: "method not found: " + req.Method},
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
}

// handleInitialize returns server info and capabilities.
func (s *Server) handleInitialize(id any) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]any{
				"name":    "sieve",
				"version": "0.1.0",
			},
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
		},
	}
}

// handleToolsList builds and returns tool definitions based on the token's connections.
func (s *Server) handleToolsList(id any, tok *tokens.Token) *JSONRPCResponse {
	var tools []ToolDef

	connIDs := s.tokenConnectionIDs(tok)
	// Determine if there are multiple connections (affects tool naming).
	multiConn := len(connIDs) > 1

	for _, connID := range connIDs {
		_, err := s.connections.Get(connID)
		if err != nil {
			continue // skip connections we can't load
		}

		c, err := s.connections.GetConnector(connID)
		if err != nil {
			continue
		}

		for _, op := range c.Operations() {
			// Normalize dots to underscores in tool names. Operations like
			// "drive.list_files" become "drive_list_files" since dots in
			// tool names can confuse LLM tool callers.
			toolName := strings.ReplaceAll(op.Name, ".", "_")
			if multiConn {
				toolName = connID + "_" + toolName
			}

			schema := buildInputSchema(op, multiConn)

			tools = append(tools, ToolDef{
				Name:        toolName,
				Description: op.Description,
				InputSchema: schema,
			})
		}
	}

	// Built-in tools
	tools = append(tools, ToolDef{
		Name:        "list_connections",
		Description: "List the available service connections and their IDs.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	})

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: map[string]any{
			"tools": tools,
		},
	}
}

// handleToolsCall executes a tool through the policy pipeline.
func (s *Server) handleToolsCall(ctx context.Context, id any, tok *tokens.Token, params json.RawMessage) *JSONRPCResponse {
	var call ToolCallParams
	if err := json.Unmarshal(params, &call); err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32602, Message: "invalid params: " + err.Error()},
		}
	}

	start := time.Now()

	// Handle built-in tools.
	switch call.Name {
	case "list_connections":
		return s.handleListConnections(id, tok, start)
	}

	// Resolve connection and operation from the tool name.
	connID, opName, err := s.resolveToolCall(tok, call)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32602, Message: err.Error()},
		}
	}

	// Security: verify the resolved connection is reachable by this token.
	// This prevents an agent from accessing connections it wasn't granted,
	// even if it crafts a tool name or "connection" argument manually.
	if !s.tokenHasConnection(tok, connID) {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "connection not allowed for this token"},
		}
	}

	conn, err := s.connections.Get(connID)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "connection not found: " + err.Error()},
		}
	}

	// Pre-flight reauth check — skip policy and Execute if the connection's
	// credentials are already known to be dead. The text content uses the
	// canonical "reauth_required:" prefix so agent SDKs branch on the
	// prefix without parsing the prose.
	if conn.Status == connections.StatusReauthRequired {
		durationMs := time.Since(start).Milliseconds()
		s.logAudit(tok, connID, opName, call.Arguments, "reauth_required", conn.ReauthReason, durationMs)
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: ToolCallResult{
				Content: []ContentBlock{{Type: "text", Text: mcpReauthRequiredText(connID, conn.ReauthReason)}},
				IsError: true,
			},
		}
	}

	// Pre-execution policy check — the primary access-control gate. The
	// decision SOURCE is the IAM engine when enabled, else the legacy
	// evaluator; both return a *policy.PolicyDecision so deny/approval_required
	// handling below is identical.
	decision, err := s.decide(ctx, tok, conn.ConnectorType, connID, conn.Status, opName, call.Arguments)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "policy evaluation error: " + err.Error()},
		}
	}

	switch decision.Action {
	case "deny":
		durationMs := time.Since(start).Milliseconds()
		s.logAudit(tok, connID, opName, call.Arguments, "deny", decision.Reason, durationMs)
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: ToolCallResult{
				Content: []ContentBlock{{Type: "text", Text: "Policy denied: " + decision.Reason}},
				IsError: true,
			},
		}

	case "approval_required":
		item, err := s.approval.Submit(&approval.SubmitRequest{
			TokenID:      tok.ID,
			ConnectionID: connID,
			Operation:    opName,
			RequestData:  call.Arguments,
		})
		if err != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      id,
				Error:   &JSONRPCError{Code: -32000, Message: "failed to submit for approval: " + err.Error()},
			}
		}

		durationMs := time.Since(start).Milliseconds()
		s.logAudit(tok, connID, opName, call.Arguments, "approval_required", "", durationMs)

		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: ToolCallResult{
				Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf(
					"This action requires human approval.\n\nApproval ID: %s\nApprove at: the Sieve admin UI (/approvals)\nPoll status: /api/v1/approvals/%s/status\n\nThe request has been submitted and is waiting for review.",
					item.ID, item.ID,
				)}},
			},
		}

	case "allow":
		// Proceed to execute.

	default:
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "unexpected policy action: " + decision.Action},
		}
	}

	// Execute via connector. Map connection-state sentinels to structured
	// IsError tool-call results so agents see a stable, non-secret error
	// code rather than the raw error text.
	c, err := s.connections.GetConnector(connID)
	if err != nil {
		// Surface keyring-state errors as transient JSON-RPC errors so
		// MCP hosts can choose to retry (mirrors the HTTP 503 +
		// Retry-After: 5 contract on the REST surface). The MCP wire
		// has no Retry-After equivalent; the message is the signal.
		if errors.Is(err, secrets.ErrKeyringNotLoaded) {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      id,
				Error:   &JSONRPCError{Code: -32000, Message: "service locked: passphrase required"},
			}
		}
		if errors.Is(err, secrets.ErrKeyringRotating) {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      id,
				Error:   &JSONRPCError{Code: -32000, Message: "rotation in progress, retry shortly"},
			}
		}
		// Look up reauth_reason so the structured tool error matches the
		// post-execution path byte-for-byte.
		reauthReason := ""
		if errors.Is(err, connections.ErrReauthRequired) {
			if c, e := s.connections.Get(connID); e == nil {
				reauthReason = c.ReauthReason
			}
		}
		if resp := connectionStateError(id, connID, reauthReason, err); resp != nil {
			s.logAudit(tok, connID, opName, call.Arguments, "deny("+errorCode(err)+")", "", time.Since(start).Milliseconds())
			return resp
		}
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "connector error: " + err.Error()},
		}
	}

	result, err := c.Execute(ctx, opName, call.Arguments)
	durationMs := time.Since(start).Milliseconds()

	if err != nil {
		// Gated operation surfaces as a tool error with the canonical
		// "operation_not_enabled:" prefix so agent SDKs branch on it
		// without parsing prose. Audit category distinct from "error"
		// and "allow" so analytics can count gated calls.
		if errors.Is(err, connector.ErrOperationNotEnabled) {
			reason := strings.TrimPrefix(err.Error(), connector.ErrOperationNotEnabled.Error()+": ")
			s.logAudit(tok, connID, opName, call.Arguments, "operation_not_enabled", reason, durationMs)
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      id,
				Result: ToolCallResult{
					Content: []ContentBlock{{Type: "text", Text: "operation_not_enabled: " + reason}},
					IsError: true,
				},
			}
		}
		// Translate the reauth sentinel into a human-actionable tool error
		// pointing at the re-auth URL. The status was set in DB by the
		// connector's onRefreshFailure callback by the time this error
		// surfaces, so future calls will hit the pre-flight path above
		// without re-running policy and Execute. Same content shape as
		// the pre-flight branch — byte-equal by construction.
		if errors.Is(err, connector.ErrNeedsReauth) {
			reason := err.Error()
			if c2, e := s.connections.Get(connID); e == nil && c2.ReauthReason != "" {
				reason = c2.ReauthReason
			}
			s.logAudit(tok, connID, opName, call.Arguments, "reauth_required", reason, durationMs)
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      id,
				Result: ToolCallResult{
					Content: []ContentBlock{{Type: "text", Text: mcpReauthRequiredText(connID, reason)}},
					IsError: true,
				},
			}
		}
		s.logAudit(tok, connID, opName, call.Arguments, "error", err.Error(), durationMs)
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: ToolCallResult{
				Content: []ContentBlock{{Type: "text", Text: "Execution error: " + err.Error()}},
				IsError: true,
			},
		}
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		resultJSON = []byte(fmt.Sprintf("%v", result))
	}

	// Apply response filters collected during pre-execution evaluation.
	// A filter that fails to construct (e.g. its script_command no longer
	// passes the allowlist) must fail closed — the un-redacted result MUST
	// NOT reach the agent.
	var reason string
	if len(decision.Filters) > 0 {
		filtered, summary, ferr := policy.ApplyResponseFilters(resultJSON, decision.Filters, s.registry.ContentFieldKeys(conn.ConnectorType))
		if ferr != nil {
			// Log the detailed failure server-side; keep the
			// agent-facing message generic so internal details (script
			// paths, command allowlist entries, evaluator stderr) don't
			// leak through the JSON-RPC error envelope.
			s.logAudit(tok, connID, opName, call.Arguments, "response_filter_failed", ferr.Error(), durationMs)
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      id,
				Error:   &JSONRPCError{Code: -32000, Message: "response filter failed"},
			}
		}
		resultJSON = filtered
		reason = summary
	}

	s.logAudit(tok, connID, opName, call.Arguments, "allow", reason, durationMs)

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: ToolCallResult{
			Content: []ContentBlock{{Type: "text", Text: string(resultJSON)}},
		},
	}
}

// handleListConnections returns the token's available connections.
func (s *Server) handleListConnections(id any, tok *tokens.Token, start time.Time) *JSONRPCResponse {
	var conns []map[string]string
	for _, connID := range s.tokenConnectionIDs(tok) {
		conn, err := s.connections.Get(connID)
		if err != nil {
			continue
		}
		conns = append(conns, map[string]string{
			"id":        conn.ID,
			"connector": conn.ConnectorType,
			"name":      conn.DisplayName,
			"status":    conn.Status,
		})
	}

	resultJSON, _ := json.Marshal(conns)
	durationMs := time.Since(start).Milliseconds()
	s.logAudit(tok, "", "list_connections", nil, "allow", "", durationMs)

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: ToolCallResult{
			Content: []ContentBlock{{Type: "text", Text: string(resultJSON)}},
		},
	}
}

// resolveToolCall determines the connection ID and operation name from a tool call.
// When there are multiple connections, the tool name may be prefixed with the
// connector type, and a "connection" argument may be provided. For single
// connections the tool name maps directly to the operation.
func (s *Server) resolveToolCall(tok *tokens.Token, call ToolCallParams) (connID string, opName string, err error) {
	// If a "connection" argument is explicitly provided, use it.
	if connArg, ok := call.Arguments["connection"]; ok {
		connIDStr, ok := connArg.(string)
		if !ok {
			return "", "", fmt.Errorf("connection argument must be a string")
		}
		connID = connIDStr

		// The tool name may be prefixed with connector type; strip it.
		conn, err := s.connections.Get(connID)
		if err != nil {
			return "", "", fmt.Errorf("connection %q not found", connID)
		}
		prefix := conn.ConnectorType + "_"
		opName = call.Name
		if strings.HasPrefix(opName, prefix) {
			opName = strings.TrimPrefix(opName, prefix)
		}
		opName = denormalizeDots(opName)

		return connID, opName, nil
	}

	// Single connection: use the only available connection.
	// Reverse the dot-to-underscore normalization applied when building tool names.
	connIDs := s.tokenConnectionIDs(tok)
	if len(connIDs) == 1 {
		return connIDs[0], denormalizeDots(call.Name), nil
	}

	// Multiple connections: tool name is prefixed with connection ID.
	for _, cID := range connIDs {
		prefix := cID + "_"
		if strings.HasPrefix(call.Name, prefix) {
			return cID, denormalizeDots(strings.TrimPrefix(call.Name, prefix)), nil
		}
	}

	return "", "", fmt.Errorf("cannot resolve connection for tool %q; provide a 'connection' argument", call.Name)
}

// tokenHasConnection reports whether the token may reach the connection. IAM is
// the gate: per-op Decide default-denies if no rule of any of the token's roles
// permits this connection, so resolution itself doesn't pre-check.
func (s *Server) tokenHasConnection(tok *tokens.Token, connID string) bool {
	return true
}

// rolesForToken resolves every role assigned to a token (RBAC, spec §5.1).
// Missing roles are skipped.
func (s *Server) rolesForToken(tok *tokens.Token) []*roles.Role {
	out := make([]*roles.Role, 0, len(tok.RoleIDs))
	for _, rid := range tok.RoleIDs {
		if r, err := s.roles.Get(rid); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// tokenConnectionIDs lists the connections to expose as tools for this token.
// IAM gates each tool CALL per-op (Decide default-denies if no rule permits), so
// discovery lists all connections; calls the token can't make are denied at
// execution rather than hidden.
func (s *Server) tokenConnectionIDs(tok *tokens.Token) []string {
	conns, err := s.connections.List()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(conns))
	for _, c := range conns {
		out = append(out, c.ID)
	}
	return out
}

// denormalizeDots reverses the dot-to-underscore normalization applied to tool
// names. Operations with namespace prefixes like "drive_list_files" are converted
// back to "drive.list_files" to match the connector's Execute method.
// Only the FIRST underscore after a known namespace prefix is converted.
func denormalizeDots(name string) string {
	prefixes := []string{"drive", "calendar", "people", "sheets", "docs",
		"s3", "ec2", "lambda", "ses", "dynamodb", "hyperstack"}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p+"_") {
			return p + "." + name[len(p)+1:]
		}
	}
	return name
}

// buildInputSchema generates a JSON Schema object for a connector operation,
// optionally adding a "connection" parameter when multi-connection mode is active.
func buildInputSchema(op connector.OperationDef, multiConn bool) map[string]any {
	properties := make(map[string]any)
	var required []string

	for name, param := range op.Params {
		prop := map[string]any{
			"description": param.Description,
		}

		switch param.Type {
		case "string":
			prop["type"] = "string"
		case "int":
			prop["type"] = "integer"
		case "float", "number":
			prop["type"] = "number"
		case "bool":
			prop["type"] = "boolean"
		case "[]string":
			prop["type"] = "array"
			prop["items"] = map[string]any{"type": "string"}
		case "object":
			// Free-form object — schema-less because the upstream API's
			// shape lives in its docs, not in our catalog. MCP clients
			// pass these through as-is.
			prop["type"] = "object"
		case "[]object":
			prop["type"] = "array"
			prop["items"] = map[string]any{"type": "object"}
		default:
			prop["type"] = "string"
		}

		properties[name] = prop

		if param.Required {
			required = append(required, name)
		}
	}

	if multiConn {
		properties["connection"] = map[string]any{
			"type":        "string",
			"description": "The connection ID to use for this operation.",
		}
	}

	schema := map[string]any{
		"type":       "object",
		"properties": properties,
	}

	if len(required) > 0 {
		schema["required"] = required
	}

	return schema
}

// logAudit writes an entry to the audit log, ignoring errors.
func (s *Server) logAudit(tok *tokens.Token, connID, operation string, params map[string]any, policyResult, responseSummary string, durationMs int64) {
	_ = s.audit.Log(&audit.LogRequest{
		TokenID:         tok.ID,
		TokenName:       tok.Name,
		ConnectionID:    connID,
		Operation:       operation,
		Params:          params,
		PolicyResult:    policyResult,
		ResponseSummary: responseSummary,
		DurationMs:      durationMs,
	})
}

// writeError writes a JSON-RPC error response directly to the http.ResponseWriter.
// JSON-RPC 2.0 says id MUST be null when the request id can't be detected
// (parse errors, transport-level rejections like missing auth). However,
// the MCP TypeScript SDK's response Zod schema rejects id=null — it
// requires string|number — so a strictly-spec-compliant null response
// makes Claude Code (and any other MCP client built on the official SDK)
// fail to parse the error envelope, masking the real problem (e.g.
// "missing bearer token") behind a confusing union-type error.
// To stay compatible with strict MCP clients we coerce id=nil to id=0
// (numeric). Strict JSON-RPC 2.0 callers see a non-null id and ignore it
// (id correlation only matters for matched request/response pairs); MCP
// clients see a valid number and parse the error.
func (s *Server) writeError(w http.ResponseWriter, id any, code int, message string) {
	if id == nil {
		id = 0
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &JSONRPCError{Code: code, Message: message},
	})
}

// mcpReauthRequiredText builds the canonical MCP tool-error text for a
// "connection needs re-auth" condition. The stable "reauth_required: "
// prefix lets agent SDKs branch on a fixed token without parsing the
// prose tail (see docs/agent-error-contract.md). Both detection paths
// (pre-flight gate and post-flight ErrNeedsReauth) route through this
// helper so their content blocks are byte-equal.
func mcpReauthRequiredText(connID, reason string) string {
	if reason == "" {
		reason = "credentials no longer valid"
	}
	return fmt.Sprintf(
		"reauth_required: Connection %q needs re-authentication. Reason: %s. A human must visit the Sieve admin UI and click Re-authenticate on this connection (URL: /connections/%s/reauth).",
		connID, reason, connID,
	)
}

// connectionStateError translates connections.ErrReauthRequired and
// connections.ErrConnectionDisabled into a structured IsError tool-call
// result (MCP's mechanism for tool-level errors, distinct from JSON-RPC
// transport errors). Returns nil for unrecognised errors so callers can
// fall through to their existing handling.
// Agents must receive a stable error code without leaking credentials
// or upstream response details.
// connID is needed so the reauth text matches the post-execution path.
// When unknown (caller doesn't have an id in scope), pass "".
func connectionStateError(id any, connID string, reason string, err error) *JSONRPCResponse {
	switch {
	case errors.Is(err, connections.ErrReauthRequired):
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: ToolCallResult{
				Content: []ContentBlock{{Type: "text", Text: mcpReauthRequiredText(connID, reason)}},
				IsError: true,
			},
		}
	case errors.Is(err, connections.ErrConnectionDisabled):
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: ToolCallResult{
				Content: []ContentBlock{{Type: "text", Text: "disabled: connection is disabled"}},
				IsError: true,
			},
		}
	}
	return nil
}

// errorCode returns a short stable identifier for known sentinel errors,
// suitable for audit-log decision tags.
func errorCode(err error) string {
	switch {
	case errors.Is(err, connections.ErrReauthRequired):
		return "reauth_required"
	case errors.Is(err, connections.ErrConnectionDisabled):
		return "disabled"
	default:
		return "error"
	}
}
