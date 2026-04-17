// Package api implements the REST API for Sieve, providing two interfaces:
//
//  1. The Sieve-native API (/api/v1/...) for generic connector operations and
//     approval status polling.
//
//  2. A Gmail-compatible API (/gmail/v1/...) that mirrors Google's Gmail REST
//     API surface. This allows existing Gmail client libraries and tools to
//     work against Sieve with minimal changes — they just point at a different
//     base URL. Requests are translated to Sieve connector operations and go
//     through the same auth + policy pipeline.
//
// All routes pass through authMiddleware, which validates the bearer token and
// injects the token object into the request context. The token determines which
// connections and policy apply to the request.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/murbard/Sieve/internal/approval"
	"github.com/murbard/Sieve/internal/audit"
	"github.com/murbard/Sieve/internal/connections"
	"github.com/murbard/Sieve/internal/policies"
	"github.com/murbard/Sieve/internal/policy"
	"github.com/murbard/Sieve/internal/roles"
	"github.com/murbard/Sieve/internal/tokens"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

const tokenContextKey contextKey = "token"

// Router holds the dependencies for the REST API handlers.
type Router struct {
	tokens      *tokens.Service
	connections *connections.Service
	policies    *policies.Service
	roles       *roles.Service
	approval    *approval.Queue
	audit       *audit.Logger
}

// NewRouter creates a new Router with the given service dependencies.
func NewRouter(
	tokensSvc *tokens.Service,
	connsSvc *connections.Service,
	policiesSvc *policies.Service,
	rolesSvc *roles.Service,
	approvalQ *approval.Queue,
	auditLog *audit.Logger,
) *Router {
	return &Router{
		tokens:      tokensSvc,
		connections: connsSvc,
		policies:    policiesSvc,
		roles:       rolesSvc,
		approval:    approvalQ,
		audit:       auditLog,
	}
}

// Handler returns an http.Handler with all API routes registered.
func (rt *Router) Handler() http.Handler {
	mux := http.NewServeMux()

	// Sieve API
	mux.HandleFunc("GET /api/v1/connections", rt.listConnections)
	mux.HandleFunc("POST /api/v1/connections/{conn}/ops/{operation}", rt.executeOperation)
	mux.HandleFunc("GET /api/v1/connections/{conn}/ops/{operation}", rt.executeOperation)

	// Approval status polling
	mux.HandleFunc("GET /api/v1/approvals/{id}/status", rt.approvalStatus)

	// Gmail-compatible API — same policy pipeline, Gmail REST format
	// {userId} is "me" for single-connection tokens, or the connection alias for multi-connection
	mux.HandleFunc("GET /gmail/v1/users", rt.gmailListUsers)
	mux.HandleFunc("GET /gmail/v1/users/{userId}/messages", rt.gmailListMessages)
	mux.HandleFunc("GET /gmail/v1/users/{userId}/messages/{id}", rt.gmailGetMessage)
	mux.HandleFunc("GET /gmail/v1/users/{userId}/threads/{id}", rt.gmailGetThread)
	mux.HandleFunc("POST /gmail/v1/users/{userId}/messages/send", rt.gmailSendMessage)
	mux.HandleFunc("POST /gmail/v1/users/{userId}/drafts", rt.gmailCreateDraft)
	mux.HandleFunc("GET /gmail/v1/users/{userId}/labels", rt.gmailListLabels)
	mux.HandleFunc("POST /gmail/v1/users/{userId}/messages/{id}/modify", rt.gmailModifyMessage)
	mux.HandleFunc("GET /gmail/v1/users/{userId}/messages/{messageId}/attachments/{attachmentId}", rt.gmailGetAttachment)

	// Transparent HTTP proxy — forwards requests to any API with credential
	// substitution. The agent uses /proxy/{connection}/{path...} and Sieve
	// swaps the Sieve token for the real API key. This is the universal
	// connector that works with any HTTP API without provider-specific code.
	mux.HandleFunc("/proxy/", rt.handleProxy)

	return rt.authMiddleware(mux)
}

// authMiddleware extracts and validates the Bearer token from the Authorization
// header, storing it in the request context. Returns 401 if missing or invalid.
func (rt *Router) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			writeError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		bearer, found := strings.CutPrefix(auth, "Bearer ")
		if !found || bearer == "" {
			writeError(w, http.StatusUnauthorized, "invalid authorization header")
			return
		}

		tok, err := rt.tokens.Validate(bearer)
		if err != nil {
			writeError(w, http.StatusUnauthorized, fmt.Sprintf("invalid token: %v", err))
			return
		}

		ctx := context.WithValue(r.Context(), tokenContextKey, tok)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// listConnections returns the connections accessible to the authenticated token.
func (rt *Router) listConnections(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromContext(r)
	if tok == nil {
		writeError(w, http.StatusUnauthorized, "no token in context")
		return
	}

	role, err := rt.roles.Get(tok.RoleID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "role not found: "+err.Error())
		return
	}

	type connInfo struct {
		ID          string `json:"id"`
		Connector   string `json:"connector"`
		DisplayName string `json:"display_name"`
	}

	connIDs := role.ConnectionIDs()
	result := make([]connInfo, 0, len(connIDs))
	for _, connID := range connIDs {
		conn, err := rt.connections.Get(connID)
		if err != nil {
			// Skip connections that can't be found (may have been removed).
			continue
		}
		result = append(result, connInfo{
			ID:          conn.ID,
			Connector:   conn.ConnectorType,
			DisplayName: conn.DisplayName,
		})
	}

	writeJSON(w, http.StatusOK, result)
}

// executeOperation handles both GET and POST requests to run a connector operation.
func (rt *Router) executeOperation(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	tok := tokenFromContext(r)
	if tok == nil {
		writeError(w, http.StatusUnauthorized, "no token in context")
		return
	}

	connID := r.PathValue("conn")
	operation := r.PathValue("operation")

	role, err := rt.roles.Get(tok.RoleID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "role not found: "+err.Error())
		return
	}

	// Verify the connection is in the role's allowed list.
	if !connectionAllowed(role, connID) {
		writeError(w, http.StatusForbidden, fmt.Sprintf("connection %q not allowed for this token", connID))
		return
	}

	// Parse params from body (POST) or query string (GET).
	var params map[string]any
	if r.Method == http.MethodPost {
		if r.Body != nil {
			defer r.Body.Close()
			if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
				return
			}
		}
	} else {
		params = make(map[string]any)
		for key, values := range r.URL.Query() {
			if len(values) == 1 {
				params[key] = values[0]
			} else {
				params[key] = values
			}
		}
	}
	if params == nil {
		params = make(map[string]any)
	}

	// Get the connector instance.
	conn, err := rt.connections.GetConnector(connID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("connector not found: %v", err))
		return
	}

	// Evaluate policy.
	policyReq := &policy.PolicyRequest{
		Operation:  operation,
		Connection: connID,
		Connector:  conn.Type(),
		Params:     params,
		Metadata:   params,
		Phase:      "pre",
	}

	evaluator, err := rt.getEvaluator(role, connID)
	if err != nil {
		writeError(w, http.StatusForbidden, fmt.Sprintf("policy error: %v", err))
		return
	}

	decision, err := evaluator.Evaluate(r.Context(), policyReq)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("policy evaluation error: %v", err))
		return
	}

	durationMs := time.Since(start).Milliseconds()

	switch decision.Action {
	case "allow":
		result, err := conn.Execute(r.Context(), operation, params)
		if err != nil {
			rt.logAudit(tok, connID, operation, params, "allow(error)", "", time.Since(start).Milliseconds())
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("execute operation: %v", err))
			return
		}
		resultJSON, _ := json.Marshal(result)
		var reason string
		if len(decision.Filters) > 0 {
			resultJSON, reason = policy.ApplyResponseFilters(resultJSON, decision.Filters)
		}
		rt.logAudit(tok, connID, operation, params, "allow", reason, time.Since(start).Milliseconds())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(resultJSON)

	case "deny":
		rt.logAudit(tok, connID, operation, params, "deny", decision.Reason, durationMs)
		writeError(w, http.StatusForbidden, fmt.Sprintf("policy denied: %s", decision.Reason))

	case "approval_required":
		item, err := rt.approval.Submit(&approval.SubmitRequest{
			TokenID:      tok.ID,
			ConnectionID: connID,
			Operation:    operation,
			RequestData:  params,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("submit for approval: %v", err))
			return
		}

		resolved, err := rt.approval.WaitForResolution(item.ID, 5*time.Minute)
		if err != nil {
			rt.logAudit(tok, connID, operation, params, "approval_timeout", "", time.Since(start).Milliseconds())
			writeError(w, http.StatusGatewayTimeout, "approval request timed out")
			return
		}

		if resolved.Status != approval.StatusApproved {
			rt.logAudit(tok, connID, operation, params, "approval_rejected", "", time.Since(start).Milliseconds())
			writeError(w, http.StatusForbidden, "approval request was rejected")
			return
		}

		// Re-validate the token after the approval wait. The token may have
		// been revoked while waiting for human approval. Use strings.CutPrefix
		// to safely extract the bearer value (mirrors authMiddleware), instead
		// of the unchecked slice [len("Bearer "):] which would return garbage
		// or panic on a malformed header.
		bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || bearer == "" {
			rt.logAudit(tok, connID, operation, params, "denied(malformed_auth_during_approval)", "", time.Since(start).Milliseconds())
			writeError(w, http.StatusUnauthorized, "malformed authorization header")
			return
		}
		if _, err := rt.tokens.Validate(bearer); err != nil {
			rt.logAudit(tok, connID, operation, params, "denied(revoked_during_approval)", "", time.Since(start).Milliseconds())
			writeError(w, http.StatusUnauthorized, "token was revoked during approval wait")
			return
		}

		result, err := conn.Execute(r.Context(), operation, params)
		if err != nil {
			rt.logAudit(tok, connID, operation, params, "approved(error)", "", time.Since(start).Milliseconds())
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("execute operation: %v", err))
			return
		}
		resultJSON, _ := json.Marshal(result)
		var approvedReason string
		if len(decision.Filters) > 0 {
			resultJSON, approvedReason = policy.ApplyResponseFilters(resultJSON, decision.Filters)
		}
		rt.logAudit(tok, connID, operation, params, "approved", approvedReason, time.Since(start).Milliseconds())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(resultJSON)

	default:
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("unknown policy action: %s", decision.Action))
	}
}

// getEvaluator builds a composite evaluator from the policies assigned to a
// specific connection within a role.
func (rt *Router) getEvaluator(role *roles.Role, connID string) (policy.Evaluator, error) {
	policyIDs := role.PoliciesForConnection(connID)
	if len(policyIDs) == 0 {
		return nil, fmt.Errorf("no policies for connection %q in role %q — access denied", connID, role.Name)
	}
	return rt.policies.BuildEvaluator(policyIDs)
}


// handleProxy is the transparent HTTP proxy handler. It extracts the connection
// alias and path from the URL, validates the token has access, and delegates
// to the ProxyHTTP method on the http_proxy connector. The agent's Sieve token
// is swapped for the real API credential transparently.
//
// URL format: /proxy/{connection}/{path...}
// Example:    /proxy/anthropic/v1/messages
func (rt *Router) handleProxy(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromContext(r)
	if tok == nil {
		writeError(w, http.StatusUnauthorized, "no token")
		return
	}

	// Parse /proxy/{connection}/{path...} from the URL.
	// Strip the "/proxy/" prefix, then split on first "/".
	trimmed := strings.TrimPrefix(r.URL.Path, "/proxy/")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "usage: /proxy/{connection}/{path}")
		return
	}

	connID := parts[0]
	proxyPath := "/"
	if len(parts) > 1 {
		proxyPath = "/" + parts[1]
	}

	role, err := rt.roles.Get(tok.RoleID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "role not found: "+err.Error())
		return
	}

	if !connectionAllowed(role, connID) {
		writeError(w, http.StatusForbidden, fmt.Sprintf("connection %q not allowed", connID))
		return
	}

	conn, err := rt.connections.GetConnector(connID)
	if err != nil {
		writeError(w, http.StatusNotFound, "connection not available")
		return
	}

	// The connector must be an http_proxy type with ProxyHTTP method.
	type httpProxier interface {
		ProxyHTTP(w http.ResponseWriter, r *http.Request, path string, filters []policy.ResponseFilter) error
	}

	proxy, ok := conn.(httpProxier)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("connection %q is not an HTTP proxy", connID))
		return
	}

	start := time.Now()
	operation := "proxy:" + r.Method + ":" + proxyPath

	// Policy evaluation — proxy requests go through the same pipeline as
	// all other operations. The operation name encodes the HTTP method and
	// path so policy rules can match on them (e.g., "deny proxy:POST:/v1/images").
	evaluator, err := rt.getEvaluator(role, connID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "policy error")
		return
	}

	// Build policy params with method and path. For requests with a JSON body,
	// peek at the body and merge top-level fields into params so policy rules
	// can match on fields like "model", "max_tokens", etc.
	policyParams := map[string]any{
		"method": r.Method,
		"path":   proxyPath,
	}
	if r.Body != nil && r.Method != http.MethodGet {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil && len(bodyBytes) > 0 {
			// Restore body for the proxy to forward.
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			// Try to parse as JSON and merge top-level fields.
			var bodyFields map[string]any
			if json.Unmarshal(bodyBytes, &bodyFields) == nil {
				for k, v := range bodyFields {
					policyParams[k] = v
				}
			}
		}
	}

	policyReq := &policy.PolicyRequest{
		Operation:  operation,
		Connection: connID,
		Connector:  "http_proxy",
		Phase:      "pre",
		Params:     policyParams,
		Metadata:   policyParams,
	}

	decision, err := evaluator.Evaluate(r.Context(), policyReq)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "policy evaluation failed")
		return
	}

	if decision.Action == "deny" {
		rt.logAudit(tok, connID, operation, nil, "deny", decision.Reason, time.Since(start).Milliseconds())
		writeError(w, http.StatusForbidden, "policy denied: "+decision.Reason)
		return
	}

	if decision.Action == "approval_required" {
		rt.logAudit(tok, connID, operation, nil, "approval_required", "", time.Since(start).Milliseconds())
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusTooManyRequests, "action requires human approval")
		return
	}

	if decision.Action != "allow" {
		rt.logAudit(tok, connID, operation, nil, "deny", "unknown action", time.Since(start).Milliseconds())
		writeError(w, http.StatusForbidden, "policy denied")
		return
	}

	if err := proxy.ProxyHTTP(w, r, proxyPath, decision.Filters); err != nil {
		rt.logAudit(tok, connID, operation, nil, "bad_request", err.Error(), time.Since(start).Milliseconds())
	} else {
		rt.logAudit(tok, connID, operation, nil, "proxied", "", time.Since(start).Milliseconds())
	}
}

// logAudit is a helper that logs to the audit logger, ignoring errors.
func (rt *Router) logAudit(tok *tokens.Token, connID, operation string, params map[string]any, policyResult, responseSummary string, durationMs int64) {
	_ = rt.audit.Log(&audit.LogRequest{
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

// connectionAllowed checks if the given connection ID is in the role's allowed list.
func connectionAllowed(role *roles.Role, connID string) bool {
	for _, c := range role.ConnectionIDs() {
		if c == connID {
			return true
		}
	}
	return false
}

// tokenFromContext extracts the validated token from the request context.
func tokenFromContext(r *http.Request) *tokens.Token {
	tok, _ := r.Context().Value(tokenContextKey).(*tokens.Token)
	return tok
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes a JSON error response with the given status code and message.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// --- Approval status endpoint ---

func (rt *Router) approvalStatus(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromContext(r)
	if tok == nil {
		writeError(w, http.StatusUnauthorized, "no token in context")
		return
	}

	id := r.PathValue("id")
	item, err := rt.approval.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "approval not found")
		return
	}

	// Security: only the token that submitted this approval can query its status.
	// The generic "approval not found" message avoids leaking the existence of
	// other tokens' approvals.
	if item.TokenID != tok.ID {
		writeError(w, http.StatusForbidden, "approval not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":        item.ID,
		"status":    string(item.Status),
		"operation": item.Operation,
	})
}

// --- Gmail-compatible API handlers ---
// These translate Gmail REST API format into Sieve connector operations,
// going through the same auth + policy pipeline.

// resolveGmailConnection resolves a Gmail userId to a connection ID.
// "me" resolves to the first gmail connection. A specific alias is looked up directly.
func (rt *Router) resolveGmailConnection(role *roles.Role, userId string) (string, error) {
	if userId != "me" {
		// Treat userId as a connection alias — verify it's allowed and is gmail
		if !connectionAllowed(role, userId) {
			return "", fmt.Errorf("connection %q not allowed for this token", userId)
		}
		conn, err := rt.connections.Get(userId)
		if err != nil {
			return "", fmt.Errorf("connection %q not found", userId)
		}
		if conn.ConnectorType != "google" {
			return "", fmt.Errorf("connection %q is not a gmail connection", userId)
		}
		return userId, nil
	}

	// "me" — find the first gmail connection
	for _, connID := range role.ConnectionIDs() {
		conn, err := rt.connections.Get(connID)
		if err != nil {
			continue
		}
		if conn.ConnectorType == "google" {
			return connID, nil
		}
	}
	return "", fmt.Errorf("no gmail connection available for this token")
}

// gmailExecute runs an operation through the full policy pipeline and returns the result.
func (rt *Router) gmailExecute(w http.ResponseWriter, r *http.Request, operation string, params map[string]any) {
	start := time.Now()
	tok := tokenFromContext(r)
	if tok == nil {
		writeError(w, http.StatusUnauthorized, "no token")
		return
	}

	role, err := rt.roles.Get(tok.RoleID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "role not found: "+err.Error())
		return
	}

	userId := r.PathValue("userId")
	if userId == "" {
		userId = "me"
	}

	connID, err := rt.resolveGmailConnection(role, userId)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	conn, err := rt.connections.GetConnector(connID)
	if err != nil {
		writeError(w, http.StatusNotFound, "connector not available")
		return
	}

	// Policy check
	policyReq := &policy.PolicyRequest{
		Operation:  operation,
		Connection: connID,
		Connector:  "google",
		Phase:      "pre",
		Params:     params,
		Metadata:   params,
	}

	evaluator, err := rt.getEvaluator(role, connID)
	if err != nil {
		writeError(w, http.StatusForbidden, "policy error: "+err.Error())
		return
	}

	decision, err := evaluator.Evaluate(r.Context(), policyReq)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "policy evaluation failed")
		return
	}

	if decision.Action == "deny" {
		rt.logAudit(tok, connID, operation, params, "deny", decision.Reason, time.Since(start).Milliseconds())
		writeError(w, http.StatusForbidden, "policy denied: "+decision.Reason)
		return
	}

	if decision.Action == "approval_required" {
		item, err := rt.approval.Submit(&approval.SubmitRequest{
			TokenID: tok.ID, ConnectionID: connID, Operation: operation, RequestData: params,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "approval submission failed")
			return
		}

		rt.logAudit(tok, connID, operation, params, "approval_required", "", time.Since(start).Milliseconds())

		// Return 429 with Retry-After. This is a deliberate choice for Gmail
		// compatibility: Gmail client libraries natively handle 429 by backing
		// off and retrying, so the agent will automatically re-attempt the
		// request after the human has had time to approve or reject it.
		w.Header().Set("Retry-After", "30")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":    429,
				"message": "Action requires human approval. Check the Sieve admin UI to approve or reject.",
				"status":  "RESOURCE_EXHAUSTED",
				"details": []map[string]any{
					{
						"approval_id": item.ID,
						"poll_url":    "/api/v1/approvals/" + item.ID + "/status",
					},
				},
			},
		})
		return
	}

	if decision.Action != "allow" {
		rt.logAudit(tok, connID, operation, params, "deny", "unknown policy action: "+decision.Action, time.Since(start).Milliseconds())
		writeError(w, http.StatusForbidden, "policy denied")
		return
	}

	result, err := conn.Execute(r.Context(), operation, params)
	if err != nil {
		rt.logAudit(tok, connID, operation, params, "error", err.Error(), time.Since(start).Milliseconds())
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Apply response filters collected during pre-execution evaluation.
	resultJSON, _ := json.Marshal(result)
	var reason string
	if len(decision.Filters) > 0 {
		resultJSON, reason = policy.ApplyResponseFilters(resultJSON, decision.Filters)
	}

	rt.logAudit(tok, connID, operation, params, "allow", reason, time.Since(start).Milliseconds())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resultJSON)
}

// gmailListUsers returns the Google connections available to this token.
// This is a Sieve extension (not part of the real Gmail API) that lets
// agents discover which accounts they can access.
func (rt *Router) gmailListUsers(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromContext(r)
	if tok == nil {
		writeError(w, http.StatusUnauthorized, "no token")
		return
	}

	role, err := rt.roles.Get(tok.RoleID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "role not found")
		return
	}

	type userInfo struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		Email       string `json:"emailAddress,omitempty"`
	}

	var users []userInfo
	for _, connID := range role.ConnectionIDs() {
		conn, err := rt.connections.Get(connID)
		if err != nil {
			continue
		}
		if conn.ConnectorType != "google" {
			continue
		}
		u := userInfo{
			ID:          conn.ID,
			DisplayName: conn.DisplayName,
		}
		// Try to get the email from the config.
		if full, err := rt.connections.GetWithConfig(connID); err == nil {
			if email, ok := full.Config["email"].(string); ok {
				u.Email = email
			}
		}
		users = append(users, u)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"users": users,
	})
}

func (rt *Router) gmailListMessages(w http.ResponseWriter, r *http.Request) {
	params := map[string]any{}
	if q := r.URL.Query().Get("q"); q != "" {
		params["query"] = q
	}
	if max := r.URL.Query().Get("maxResults"); max != "" {
		params["max_results"] = max
	}
	if pt := r.URL.Query().Get("pageToken"); pt != "" {
		params["page_token"] = pt
	}
	rt.gmailExecute(w, r, "list_emails", params)
}

func (rt *Router) gmailGetMessage(w http.ResponseWriter, r *http.Request) {
	rt.gmailExecute(w, r, "read_email", map[string]any{
		"message_id": r.PathValue("id"),
	})
}

func (rt *Router) gmailGetThread(w http.ResponseWriter, r *http.Request) {
	rt.gmailExecute(w, r, "read_thread", map[string]any{
		"thread_id": r.PathValue("id"),
	})
}

func (rt *Router) gmailSendMessage(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if r.Body != nil {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	if body == nil {
		body = map[string]any{}
	}
	rt.gmailExecute(w, r, "send_email", body)
}

func (rt *Router) gmailCreateDraft(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if r.Body != nil {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	if body == nil {
		body = map[string]any{}
	}
	rt.gmailExecute(w, r, "create_draft", body)
}

func (rt *Router) gmailListLabels(w http.ResponseWriter, r *http.Request) {
	rt.gmailExecute(w, r, "list_labels", map[string]any{})
}

func (rt *Router) gmailGetAttachment(w http.ResponseWriter, r *http.Request) {
	rt.gmailExecute(w, r, "get_attachment", map[string]any{
		"message_id":    r.PathValue("messageId"),
		"attachment_id": r.PathValue("attachmentId"),
	})
}

// gmailModifyMessage translates Gmail's modify endpoint into specific Sieve
// operations. Gmail's modify is a single endpoint that handles both adding and
// removing labels, but Sieve exposes these as distinct operations (add_label,
// remove_label, archive) so that policies can grant fine-grained permissions.
// For example, a policy can allow adding labels but deny archiving.
// The explicit action checks here ensure each operation goes through the policy
// engine with the correct operation name rather than a generic "modify".
func (rt *Router) gmailModifyMessage(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if r.Body != nil {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	if body == nil {
		body = map[string]any{}
	}
	body["message_id"] = r.PathValue("id")

	// Gmail's modify endpoint adds/removes labels
	if addLabels, ok := body["addLabelIds"].([]any); ok && len(addLabels) > 0 {
		if labelID, ok := addLabels[0].(string); ok {
			rt.gmailExecute(w, r, "add_label", map[string]any{
				"message_id": r.PathValue("id"),
				"label_id":   labelID,
			})
			return
		}
	}
	if removeLabels, ok := body["removeLabelIds"].([]any); ok && len(removeLabels) > 0 {
		if labelID, ok := removeLabels[0].(string); ok {
			// Check if it's an archive (removing INBOX)
			if labelID == "INBOX" {
				rt.gmailExecute(w, r, "archive", map[string]any{
					"message_id": r.PathValue("id"),
				})
				return
			}
			rt.gmailExecute(w, r, "remove_label", map[string]any{
				"message_id": r.PathValue("id"),
				"label_id":   labelID,
			})
			return
		}
	}

	writeError(w, http.StatusBadRequest, "modify requires addLabelIds or removeLabelIds")
}
