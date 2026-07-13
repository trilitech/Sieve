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
	// Determine if there are multiple connections (affects tool naming). A
	// connection appears in connIDs iff the token may call ≥1 of its ops, so this
	// matches the set of connections that will contribute ≥1 tool below.
	multiConn := len(connIDs) > 1

	for _, connID := range connIDs {
		md, err := s.connections.Get(connID)
		if err != nil {
			continue // skip connections we can't load
		}

		c, err := s.connections.GetConnector(connID)
		if err != nil {
			continue
		}

		for _, op := range c.Operations() {
			// Advertise a tool only if the token may actually call this op — a
			// non-deny dry-run Decide (nil params). This surfaces write-only
			// grants (a single representative-read probe would hide them) and
			// hides ops the token can't call; the per-op Decide at call time
			// stays authoritative. (A script-mode condition would run here per op
			// with nil params — acceptable for infrequent discovery.)
			if s.iam != nil {
				dec, derr := s.decide(context.Background(), tok, md.ConnectorType, connID, md.Status, op.Name, nil)
				if derr != nil || dec == nil || dec.Action == "deny" {
					continue
				}
			}

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

// errUnknownConnection is returned by resolveToolCall when an explicit
// "connection" argument names a connection that doesn't exist. handleToolsCall
// maps it to the uniform not-authorized response so a missing connection can't
// be distinguished from an ungranted one (existence-oracle closure).
var errUnknownConnection = errors.New("unknown connection")

// notAuthorized is the single uniform tool-call response for every
// unauthorized-or-missing outcome (missing/unknown connection, a deny decision,
// or a needs_reauth connection the token isn't granted). Keeping it
// byte-identical is a security requirement: the MCP response must not be usable
// as a connection existence/status oracle. The specific reason reaches the audit
// log only, never the agent.
func (s *Server) notAuthorized(id any) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: ToolCallResult{
			Content: []ContentBlock{{Type: "text", Text: "Policy denied"}},
			IsError: true,
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

	// Resolve the connection id + operation from the tool name. A failure that
	// names a specific (missing) connection is funneled to the uniform
	// not-authorized response below so it can't be used as an existence oracle;
	// a genuinely ambiguous tool name (which reveals no connection) keeps its
	// grammar hint.
	connID, opName, rerr := s.resolveToolCall(tok, call)
	if rerr != nil && !errors.Is(rerr, errUnknownConnection) {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32602, Message: rerr.Error()},
		}
	}

	// "connection" is ROUTING metadata (already consumed by resolveToolCall),
	// not an operation parameter. Strip it so the connector's Execute, the
	// policy context's `param` record, and the audit log see only real op
	// params — identical whether or not the caller passed the advertised
	// connection arg. (The deny itself is fixed in resolveToolCall; this keeps
	// the routing arg out of everything downstream.) All downstream reads use
	// call.Arguments, so swap in a cleaned copy once rather than mutating the
	// caller's map.
	if _, ok := call.Arguments["connection"]; ok {
		cleaned := make(map[string]any, len(call.Arguments))
		for k, v := range call.Arguments {
			if k == "connection" {
				continue
			}
			cleaned[k] = v
		}
		call.Arguments = cleaned
	}

	// The IAM decision is the SOLE gate and MUST run before anything
	// connection-specific is revealed (the reauth envelope, the connector build).
	// Look up connection METADATA (type + status) without building the connector,
	// so a missing / needs_reauth / disabled / ungranted connection are all
	// indistinguishable to an unauthorized token — no existence/status oracle
	// (mirrors the REST fix in 73af5f2).
	var conn *connections.Connection
	var decision *policy.PolicyDecision
	if rerr == nil {
		if c, err := s.connections.Get(connID); err == nil {
			conn = c
			d, derr := s.decide(ctx, tok, c.ConnectorType, connID, c.Status, opName, call.Arguments)
			if derr != nil {
				s.logAudit(tok, connID, opName, call.Arguments, "policy_error", derr.Error(), time.Since(start).Milliseconds())
				return s.notAuthorized(id)
			}
			decision = d
		}
	}
	// Missing/unknown connection or a deny decision → the identical uniform
	// not-authorized response. The specific reason is audited, never returned.
	if conn == nil || decision == nil || decision.Action == "deny" {
		reason := "unknown connection"
		if decision != nil {
			reason = decision.Reason
		}
		s.logAudit(tok, connID, opName, call.Arguments, "deny", reason, time.Since(start).Milliseconds())
		return s.notAuthorized(id)
	}

	// Authorized (allow / approval_required); connection-specific handling is now
	// safe to reveal.
	//
	// Reauth fast-path — surface the structured reauth envelope (the
	// "reauth_required:" prefix lets agent SDKs branch without parsing prose).
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

	if decision.Action == "approval_required" {
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
	}

	if decision.Action != "allow" {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "unexpected policy action: " + decision.Action},
		}
	}
	// allow → fall through to execute.

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

		// Existence check. Don't leak existence — the caller maps this sentinel
		// to the uniform not-authorized response (existence-oracle closure).
		if _, err := s.connections.Get(connID); err != nil {
			return "", "", errUnknownConnection
		}

		// The tool name may be the bare op, or — in multi-connection mode —
		// prefixed with the CONNECTION ID ("<connID>_<op>", see the tool-name
		// builder). Strip that connID prefix so op resolution is identical
		// whether the caller used the advertised prefixed tool name plus a
		// connection arg, or a bare op name plus a connection arg.
		//
		// The prior code stripped the connector *type* prefix, which never
		// matches a connID-prefixed name (e.g. "TT-google_list_labels" doesn't
		// start with "google_"), so opName became the whole tool name and the
		// call fell through to default-deny — passing the advertised connection
		// arg silently broke every prefixed tool. (tezos_ops P0 2026-07-13.)
		opName = call.Name
		if p := connID + "_"; strings.HasPrefix(opName, p) {
			opName = strings.TrimPrefix(opName, p)
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

// tokenConnectionIDs lists the connections visible to this token for discovery
// (list_connections + tool-name resolution). A connection is visible iff the
// token has a non-deny IAM decision for AT LEAST ONE of its operations — not
// merely a representative read op — so a write-only grant (e.g. only send_email)
// keeps the connection discoverable while connections the token has no grant on
// stay hidden. Per-op Decide at tool-CALL time remains the authoritative gate.
func (s *Server) tokenConnectionIDs(tok *tokens.Token) []string {
	conns, err := s.connections.List()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(conns))
	for _, c := range conns {
		if s.iam == nil {
			// IAM unwired (defensive): preserve prior list-everything behavior.
			out = append(out, c.ID)
			continue
		}
		if s.hasAllowedOp(tok, c.ConnectorType, c.ID, c.Status) {
			out = append(out, c.ID)
		}
	}
	return out
}

// hasAllowedOp reports whether the token has a non-deny IAM decision for at
// least one operation of the connection (short-circuits on the first). Ops come
// from the registry metadata (no keyring / connector build). A script-mode
// condition would run here per op with nil params until the first allow —
// acceptable for infrequent discovery.
func (s *Server) hasAllowedOp(tok *tokens.Token, connType, connID, connStatus string) bool {
	meta, ok := s.registry.Meta(connType)
	if !ok {
		return false
	}
	for _, op := range meta.Operations {
		dec, err := s.decide(context.Background(), tok, connType, connID, connStatus, op.Name, nil)
		if err == nil && dec != nil && dec.Action != "deny" {
			return true
		}
	}
	return false
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
