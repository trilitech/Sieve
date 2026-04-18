// Package mcp implements the Model Context Protocol (MCP) server for Sieve.
//
// MCP is the protocol AI agents (e.g., Claude) use to discover and invoke tools.
// This server exposes connector operations as MCP tools, with every tool call
// passing through the policy pipeline:
//
//  1. Pre-execution check: Before the connector runs, the policy evaluator
//     decides whether the operation is allowed, denied, or requires human
//     approval. This is the primary access-control gate.
//
//  2. Response filtering: After the connector returns data, any ResponseFilter
//     objects collected during evaluation are applied to the response. This
//     enables content filtering and redaction without a second evaluation pass.
//
// The approval flow is non-blocking for MCP clients: when approval is required,
// the server returns immediately with an approval ID and URL. The agent can
// poll for resolution. This differs from the REST API which blocks with
// WaitForResolution (suitable for synchronous HTTP clients).
//
// Tool naming handles multi-connection scenarios by prefixing tool names with
// the connector type (e.g., "google_list_emails") when a token has access to
// multiple connections. Single-connection tokens get unprefixed names.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/murbard/Sieve/internal/approval"
	"github.com/murbard/Sieve/internal/audit"
	"github.com/murbard/Sieve/internal/connections"
	"github.com/murbard/Sieve/internal/connector"
	"github.com/murbard/Sieve/internal/policies"
	"github.com/murbard/Sieve/internal/policy"
	"github.com/murbard/Sieve/internal/roles"
	"github.com/murbard/Sieve/internal/tokens"
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
	policies    *policies.Service
	roles       *roles.Service
	approval *approval.Queue
	audit    *audit.Logger
}

// NewServer creates a new MCP Server.
func NewServer(
	tokensSvc *tokens.Service,
	connsSvc *connections.Service,
	policiesSvc *policies.Service,
	rolesSvc *roles.Service,
	approvalQ *approval.Queue,
	auditLog *audit.Logger,
) *Server {
	return &Server{
		tokens:      tokensSvc,
		connections: connsSvc,
		policies:    policiesSvc,
		roles:       rolesSvc,
		approval: approvalQ,
		audit:    auditLog,
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
	role, err := s.roles.Get(tok.RoleID)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "role not found: " + err.Error()},
		}
	}

	var tools []ToolDef

	connIDs := role.ConnectionIDs()
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

	tools = append(tools, ToolDef{
		Name:        "list_policies",
		Description: "List all available policies with their names and rule summaries.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	})

	tools = append(tools, ToolDef{
		Name:        "get_my_policy",
		Description: "Get the full policy (rules) that applies to this token.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	})

	tools = append(tools, ToolDef{
		Name:        "get_policy_schema",
		Description: "Get the full JSON schema for policy rules. Use this before calling propose_policy to understand exactly what match fields, actions, and filters are available.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	})

	tools = append(tools, ToolDef{
		Name:        "propose_policy",
		Description: "Propose a new policy or changes to an existing policy. The proposal goes to the human admin for approval — you cannot enact policy changes directly. Call get_policy_schema first to see all available match fields and actions.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type":        "string",
					"description": "Name for the proposed policy",
				},
				"description": map[string]any{
					"type":        "string",
					"description": "Human-readable description of what this policy does and why you're proposing it",
				},
				"default_action": map[string]any{
					"type":        "string",
					"enum":        []string{"allow", "deny"},
					"description": "Action when no rule matches. Use 'deny' for fail-closed (recommended).",
				},
				"rules": map[string]any{
					"type":        "array",
					"description": "Ordered array of policy rules. First matching rule wins.",
					"items": map[string]any{
						"type": "object",
					},
				},
			},
			"required": []string{"name", "description", "rules"},
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
	case "list_policies":
		return s.handleListPolicies(id, tok, start)
	case "get_my_policy":
		return s.handleGetMyPolicy(id, tok, start)
	case "get_policy_schema":
		return s.handleGetPolicySchema(id, tok, start)
	case "propose_policy":
		return s.handleProposePolicy(id, tok, start, call.Arguments)
	}

	// Resolve the role for this token.
	role, err := s.roles.Get(tok.RoleID)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "role not found: " + err.Error()},
		}
	}

	// Resolve connection and operation from the tool name.
	connID, opName, err := s.resolveToolCall(role, call)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32602, Message: err.Error()},
		}
	}

	// Security: verify the resolved connection is in the role's allow-list.
	// This prevents an agent from accessing connections it wasn't granted,
	// even if it crafts a tool name or "connection" argument manually.
	if !s.tokenHasConnection(role, connID) {
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

	// Build policy request.
	policyReq := &policy.PolicyRequest{
		Operation:  opName,
		Connection: connID,
		Connector:  conn.ConnectorType,
		Params:     call.Arguments,
		Metadata:   call.Arguments,
		Phase:      "pre",
	}

	// Get or create the policy evaluator for this connection's policies.
	evaluator, err := s.getEvaluator(role, connID)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "policy evaluator error: " + err.Error()},
		}
	}

	// Phase 1: Pre-execution policy check. The Phase field is not set here,
	// so it defaults to "pre" in the evaluator. This is the primary access
	// control gate — deny/approval_required decisions stop execution entirely.
	decision, err := evaluator.Evaluate(ctx, policyReq)
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

	// Execute via connector.
	c, err := s.connections.GetConnector(connID)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "connector error: " + err.Error()},
		}
	}

	result, err := c.Execute(ctx, opName, call.Arguments)
	durationMs := time.Since(start).Milliseconds()

	if err != nil {
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
	var reason string
	if len(decision.Filters) > 0 {
		resultJSON, reason = policy.ApplyResponseFilters(resultJSON, decision.Filters)
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
	role, err := s.roles.Get(tok.RoleID)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "role not found: " + err.Error()},
		}
	}

	var conns []map[string]string
	for _, connID := range role.ConnectionIDs() {
		conn, err := s.connections.Get(connID)
		if err != nil {
			continue
		}
		conns = append(conns, map[string]string{
			"id":        conn.ID,
			"connector": conn.ConnectorType,
			"name":      conn.DisplayName,
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

func (s *Server) handleListPolicies(id any, tok *tokens.Token, start time.Time) *JSONRPCResponse {
	pols, err := s.policies.List()
	if err != nil {
		return &JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: -32000, Message: err.Error()}}
	}

	var summaries []map[string]any
	for _, p := range pols {
		summary := map[string]any{
			"id":   p.ID,
			"name": p.Name,
			"type": p.PolicyType,
		}
		if rules, ok := p.PolicyConfig["rules"].([]any); ok {
			summary["rule_count"] = len(rules)
		}
		summaries = append(summaries, summary)
	}

	resultJSON, _ := json.Marshal(summaries)
	s.logAudit(tok, "", "list_policies", nil, "allow", "", time.Since(start).Milliseconds())

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  ToolCallResult{Content: []ContentBlock{{Type: "text", Text: string(resultJSON)}}},
	}
}

func (s *Server) handleGetMyPolicy(id any, tok *tokens.Token, start time.Time) *JSONRPCResponse {
	role, err := s.roles.Get(tok.RoleID)
	if err != nil {
		return &JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: -32000, Message: "role not found: " + err.Error()}}
	}

	var results []map[string]any
	for _, binding := range role.Bindings {
		var bindingPolicies []map[string]any
		for _, pid := range binding.PolicyIDs {
			p, err := s.policies.Get(pid)
			if err != nil {
				return &JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: -32000, Message: err.Error()}}
			}
			bindingPolicies = append(bindingPolicies, map[string]any{
				"id":     p.ID,
				"name":   p.Name,
				"type":   p.PolicyType,
				"config": p.PolicyConfig,
			})
		}
		results = append(results, map[string]any{
			"connection_id": binding.ConnectionID,
			"policies":      bindingPolicies,
		})
	}

	resultJSON, _ := json.Marshal(results)
	s.logAudit(tok, "", "get_my_policy", nil, "allow", "", time.Since(start).Milliseconds())

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  ToolCallResult{Content: []ContentBlock{{Type: "text", Text: string(resultJSON)}}},
	}
}

func (s *Server) handleGetPolicySchema(id any, tok *tokens.Token, start time.Time) *JSONRPCResponse {
	schema := map[string]any{
		"description": "A policy has an ordered list of rules (first match wins) and a default_action (\"allow\" or \"deny\"). Each rule has a match block (all conditions ANDed; omit for catch-all) and an action.",
		"actions": map[string]any{
			"allow":             "Permit the operation.",
			"deny":              "Block the operation. Optionally set 'reason'.",
			"approval_required": "Queue for human approval before executing.",
			"filter":            "Like allow, but apply content filters (filter_exclude / redact_patterns) to the response before returning it.",
		},
		"common_rule_fields": map[string]any{
			"action":          "Required. One of: allow, deny, approval_required, filter.",
			"reason":          "Optional. Human-readable reason shown when this rule fires.",
			"filter_exclude":  "For filter action: remove response items containing this string (case-insensitive).",
			"redact_patterns": "For filter action: array of regex patterns replaced with [REDACTED].",
		},
		"common_match_fields": map[string]any{
			"operations": "Array of operation names this rule applies to. Empty or omitted = match all operations.",
		},
		"scopes": map[string]any{
			"gmail": map[string]any{
				"operations": []string{"list_emails", "read_email", "read_thread", "get_attachment", "create_draft", "update_draft", "reply", "send_email", "send_draft", "add_label", "remove_label", "archive", "list_labels"},
				"match_fields": map[string]any{
					"from":             "Array of sender patterns (glob: \"*@company.com\").",
					"to":               "Array of recipient patterns (glob: \"*@company.com\").",
					"subject_contains": "Array of strings — match if subject contains any.",
					"content_contains": "String — match if response body contains this.",
					"labels":           "Array of label names — match if email has any of these.",
				},
				"example": map[string]any{
					"default_action": "deny",
					"rules": []any{
						map[string]any{"match": map[string]any{"operations": []any{"list_emails", "read_email"}}, "action": "allow"},
						map[string]any{"match": map[string]any{"operations": []any{"send_email"}, "to": []any{"*@company.com"}}, "action": "approval_required"},
					},
				},
			},
			"llm": map[string]any{
				"description": "For LLM API connections (Anthropic, OpenAI, Gemini, Bedrock).",
				"operations":  []string{"chat", "complete", "embed"},
				"match_fields": map[string]any{
					"model":                  "Array of model patterns (glob: \"claude-*\", \"gpt-4*\").",
					"providers":              "Array of provider names (exact: \"anthropic\", \"openai\", \"gemini\", \"bedrock\").",
					"max_tokens":             "Integer — deny if request's max_tokens exceeds this.",
					"max_cost":               "Float — deny if estimated cost per request exceeds this (dollars).",
					"extended_thinking":      "\"enabled\" or \"disabled\". Anthropic only.",
					"system_prompt_contains": "String — match if system prompt contains this.",
					"max_temperature":        "Float — deny if temperature exceeds this. OpenAI.",
					"json_mode":              "\"required\" or \"forbidden\". OpenAI.",
					"grounding":              "\"enabled\" or \"disabled\". Gemini.",
					"safety_threshold":       "Safety level. Gemini.",
				},
				"example": map[string]any{
					"default_action": "deny",
					"rules": []any{
						map[string]any{"match": map[string]any{"model": []any{"claude-sonnet-*"}, "max_tokens": 4096, "max_cost": 0.10}, "action": "allow"},
					},
				},
			},
			"http_proxy": map[string]any{
				"description": "For generic HTTP proxy connections. Operations are proxy:{METHOD}:{path}.",
				"match_fields": map[string]any{
					"path":          "Glob pattern for request path (e.g. \"/v1/messages*\").",
					"body_contains": "String — match if request body contains this (case-insensitive).",
				},
				"example": map[string]any{
					"default_action": "deny",
					"rules": []any{
						map[string]any{"match": map[string]any{"path": "/v1/chat/completions"}, "action": "allow"},
					},
				},
			},
			"drive": map[string]any{
				"operations": []string{"drive.list_files", "drive.get_file", "drive.download_file", "drive.upload_file", "drive.share_file"},
				"match_fields": map[string]any{
					"mime_type":     "Glob pattern for file MIME type (e.g. \"application/pdf\").",
					"owner":         "Glob pattern for file owner email.",
					"shared_status": "\"shared with me\" or \"owned by me\".",
				},
			},
			"calendar": map[string]any{
				"operations": []string{"calendar.list_events", "calendar.get_event", "calendar.create_event", "calendar.update_event", "calendar.delete_event"},
				"match_fields": map[string]any{
					"calendar_id": "Exact match for calendar ID (e.g. \"primary\", \"work@group.calendar.google.com\").",
					"attendee":    "Glob pattern for attendee email.",
				},
			},
			"people": map[string]any{
				"operations": []string{"people.list_contacts", "people.get_contact", "people.create_contact", "people.update_contact", "people.delete_contact"},
				"match_fields": map[string]any{
					"contact_group":  "Exact match for contact group (e.g. \"myContacts\").",
					"allowed_fields": "Comma-separated allowed fields (e.g. \"names,emailAddresses\"). Denies if request asks for other fields.",
				},
			},
			"sheets": map[string]any{
				"operations": []string{"sheets.get_spreadsheet", "sheets.read_range", "sheets.write_range", "sheets.create_spreadsheet"},
				"match_fields": map[string]any{
					"spreadsheet_id": "Exact match — restrict to a specific spreadsheet.",
					"range_pattern":  "Glob pattern for cell range (e.g. \"Sheet1!*\").",
				},
			},
			"docs": map[string]any{
				"operations": []string{"docs.get_document", "docs.list_documents", "docs.create_document", "docs.update_document"},
				"match_fields": map[string]any{
					"document_id":    "Exact match — restrict to a specific document.",
					"title_contains": "Case-insensitive substring match on document title.",
				},
			},
			"ec2": map[string]any{
				"operations": []string{"ec2.describe_instances", "ec2.describe_vpcs", "ec2.describe_security_groups", "ec2.describe_subnets", "ec2.describe_images", "ec2.run_instances", "ec2.start_instances", "ec2.stop_instances", "ec2.terminate_instances", "ec2.reboot_instances", "ec2.create_security_group", "ec2.authorize_security_group_ingress", "ec2.create_key_pair"},
				"match_fields": map[string]any{
					"instance_type": "Array of allowed types (e.g. [\"t3.micro\", \"t3.small\"]).",
					"region":        "AWS region (e.g. \"us-east-1\").",
					"max_count":     "Integer — max instances per launch request.",
					"ami":           "Glob pattern for AMI ID (e.g. \"ami-0abc*\").",
					"vpc":           "VPC or subnet ID to restrict to.",
					"ports":         "Comma-separated allowed ports (e.g. \"443,8080\").",
					"cidr":          "CIDR pattern. Use \"!0.0.0.0/0\" to block public access.",
					"tag":           "Tag in \"key=value\" format.",
				},
				"example": map[string]any{
					"default_action": "deny",
					"rules": []any{
						map[string]any{"match": map[string]any{"operations": []any{"ec2.describe_instances", "ec2.describe_vpcs"}}, "action": "allow"},
						map[string]any{"match": map[string]any{"operations": []any{"ec2.run_instances"}, "instance_type": []any{"t3.micro"}, "region": "us-east-1", "max_count": 3}, "action": "allow"},
					},
				},
			},
			"s3": map[string]any{
				"operations": []string{"s3.list_buckets", "s3.list_objects", "s3.get_object", "s3.head_object", "s3.put_object", "s3.delete_object", "s3.copy_object"},
				"match_fields": map[string]any{
					"bucket":     "Glob pattern for bucket name (e.g. \"prod-*\").",
					"key_prefix": "Prefix match for object key (e.g. \"public/\").",
					"region":     "AWS region.",
				},
			},
			"lambda": map[string]any{
				"operations": []string{"lambda.list_functions", "lambda.get_function", "lambda.invoke", "lambda.invoke_async"},
				"match_fields": map[string]any{
					"function_name": "Glob pattern for function name.",
					"region":        "AWS region.",
				},
			},
			"ses": map[string]any{
				"operations": []string{"ses.send_email", "ses.send_templated_email", "ses.list_identities", "ses.get_send_quota"},
				"match_fields": map[string]any{
					"recipient":       "Glob pattern for recipient email (e.g. \"*@company.com\").",
					"sender_identity": "Exact match for sender email address.",
				},
			},
			"dynamodb": map[string]any{
				"operations": []string{"dynamodb.get_item", "dynamodb.query", "dynamodb.scan", "dynamodb.list_tables", "dynamodb.put_item", "dynamodb.update_item", "dynamodb.delete_item"},
				"match_fields": map[string]any{
					"table_name": "Exact match for table name.",
					"index_name": "Exact match for index name.",
				},
			},
			"hyperstack": map[string]any{
				"operations": []string{"hyperstack.list_vms", "hyperstack.get_vm", "hyperstack.create_vm", "hyperstack.delete_vm", "hyperstack.start_vm", "hyperstack.stop_vm", "hyperstack.restart_vm", "hyperstack.list_flavors", "hyperstack.list_images"},
				"match_fields": map[string]any{
					"flavor":  "Exact match for VM flavor (e.g. \"a100\").",
					"max_vms": "Integer — max VMs per request.",
				},
			},
		},
	}

	resultJSON, _ := json.Marshal(schema)
	s.logAudit(tok, "", "get_policy_schema", nil, "allow", "", time.Since(start).Milliseconds())

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  ToolCallResult{Content: []ContentBlock{{Type: "text", Text: string(resultJSON)}}},
	}
}

func (s *Server) handleProposePolicy(id any, tok *tokens.Token, start time.Time, args map[string]any) *JSONRPCResponse {
	name, _ := args["name"].(string)
	description, _ := args["description"].(string)
	rules, _ := args["rules"].([]any)

	if name == "" || description == "" {
		return &JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: -32602, Message: "name and description are required"}}
	}

	// Submit to approval queue — the human decides
	item, err := s.approval.Submit(&approval.SubmitRequest{
		TokenID:      tok.ID,
		ConnectionID: "",
		Operation:    "propose_policy",
		RequestData: map[string]any{
			"name":           name,
			"description":    description,
			"rules":          rules,
			"default_action": "deny",
			"proposed_by":    tok.Name,
		},
	})
	if err != nil {
		return &JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: -32000, Message: err.Error()}}
	}

	s.logAudit(tok, "", "propose_policy", args, "approval_required", description, time.Since(start).Milliseconds())

	msg := fmt.Sprintf("Policy proposal submitted for review.\n\nProposal: %s\nDescription: %s\nRules: %d rule(s)\nApproval ID: %s\nReview at: the Sieve admin UI (/approvals)",
		name, description, len(rules), item.ID)

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  ToolCallResult{Content: []ContentBlock{{Type: "text", Text: msg}}},
	}
}

// resolveToolCall determines the connection ID and operation name from a tool call.
// When there are multiple connections, the tool name may be prefixed with the
// connector type, and a "connection" argument may be provided. For single
// connections the tool name maps directly to the operation.
func (s *Server) resolveToolCall(role *roles.Role, call ToolCallParams) (connID string, opName string, err error) {
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
	connIDs := role.ConnectionIDs()
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

// tokenHasConnection checks whether the given connection ID is in the role's allowed list.
func (s *Server) tokenHasConnection(role *roles.Role, connID string) bool {
	for _, c := range role.ConnectionIDs() {
		if c == connID {
			return true
		}
	}
	return false
}

// getEvaluator creates a composite evaluator from the policies assigned to a
// specific connection within a role. Different connections in the same role can
// have different policies. Returns a deny-all evaluator if the connection has
// no policies in the role.
func (s *Server) getEvaluator(role *roles.Role, connID string) (policy.Evaluator, error) {
	policyIDs := role.PoliciesForConnection(connID)
	if len(policyIDs) == 0 {
		return nil, fmt.Errorf("no policies for connection %q in role %q — access denied", connID, role.Name)
	}
	return s.policies.BuildEvaluator(policyIDs)
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
		case "bool":
			prop["type"] = "boolean"
		case "[]string":
			prop["type"] = "array"
			prop["items"] = map[string]any{"type": "string"}
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
func (s *Server) writeError(w http.ResponseWriter, id any, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &JSONRPCError{Code: code, Message: message},
	})
}
