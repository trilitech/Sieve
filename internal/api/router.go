// Package api implements the REST API for Sieve, providing two interfaces:
// 1. The Sieve-native API (/api/v1/...) for generic connector operations and
// approval status polling.
// 2. A Gmail-compatible API (/gmail/v1/...) that mirrors Google's Gmail REST
// API surface. This allows existing Gmail client libraries and tools to
// work against Sieve with minimal changes — they just point at a different
// base URL. Requests are translated to Sieve connector operations and go
// through the same auth + policy pipeline.
// All routes pass through authMiddleware, which validates the bearer token and
// injects the token object into the request context. The token determines which
// connections and policy apply to the request.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/trilitech/Sieve/internal/approval"
	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/connector"
	githubconn "github.com/trilitech/Sieve/internal/connectors/github"
	"github.com/trilitech/Sieve/internal/connectors/httpproxy"
	"github.com/trilitech/Sieve/internal/connectors/mcpproxy"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/policies"
	"github.com/trilitech/Sieve/internal/policy"
	"github.com/trilitech/Sieve/internal/ratelimit"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/secrets"
	"github.com/trilitech/Sieve/internal/settings"
	"github.com/trilitech/Sieve/internal/tokens"
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
	// limiter throttles bearer-token validation failures per source IP.
	// Defaults: 10
	// tokens, 1 refill / 6s = 10 failures per 60s window.
	limiter *ratelimit.Limiter

	// IAM (internal/iam) — opt-in via SetIAM. When iam != nil and the
	// iam_enabled setting is "true", the decision source for every operation is
	// iam.Decide instead of the legacy evaluator. All downstream control flow
	// (execute, approval, response filters, audit) is unchanged.
	iam      *iampolicies.Service
	registry *connector.Registry
	settings *settings.Service
}

// SetIAM wires the IAM engine into the request path (opt-in; keeps NewRouter's
// signature stable). The flag is read per request from settings, so it can be
// flipped live without restart.
func (rt *Router) SetIAM(iamSvc *iampolicies.Service, registry *connector.Registry, settingsSvc *settings.Service) {
	rt.iam = iamSvc
	rt.registry = registry
	rt.settings = settingsSvc
}

// iamEnabled reports whether the IAM engine should decide this request.
func (rt *Router) iamEnabled() bool {
	if rt.iam == nil || rt.settings == nil {
		return false
	}
	v, _ := rt.settings.Get("iam_enabled")
	return v == "true"
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
		limiter:     ratelimit.NewLimiter(0, 0, 0), // documented defaults
	}
}

// SetRateLimiter replaces the default per-IP auth limiter. Used by the
// process bootstrap to wire operator-tuned settings (window / capacity).
func (rt *Router) SetRateLimiter(l *ratelimit.Limiter) {
	if l != nil {
		rt.limiter = l
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

	// Wrap responses in the sensitive-data header set so intermediate
	// proxies don't cache agent-API responses (which can carry entity
	// data tied to a specific bearer token). The cache headers wrap
	// authMiddleware so 401 responses also carry them — caches MUST NOT
	// retain failed auth attempts.
	return noCacheMiddleware(rt.authMiddleware(mux))
}

// noCacheMiddleware sets Cache-Control: no-store and companion headers
// on every response. Mirrors internal/web.WriteSensitive — duplicated
// here to keep the api package free of an import on internal/web (the
// constitution forbids cross-layer imports).
func noCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store, no-cache, max-age=0, must-revalidate, private")
		h.Set("Pragma", "no-cache")
		h.Set("Expires", "0")
		h.Set("Vary", "Authorization")
		next.ServeHTTP(w, r)
	})
}

// authMiddleware extracts and validates the Bearer token from the Authorization
// header, storing it in the request context. Returns 401 if missing or invalid.
// Per-IP token-bucket throttling (
// ) wraps the validation path: failed auth attempts deplete
// the bucket; success refunds. When the bucket is empty, HTTP 429 with
// Retry-After is returned instead of 401.
func (rt *Router) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := sourceIPKey(r)

		// Rate-limit BEFORE Argon2id / DB validation runs. Keeps the
		// brute-force budget tight regardless of upstream auth cost.
		if rt.limiter != nil {
			if ok, retry := rt.limiter.Allow(key); !ok {
				w.Header().Set("Retry-After", retryAfterSeconds(retry))
				writeError(w, http.StatusTooManyRequests, "too many auth attempts, retry later")
				return
			}
		}

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

		// Successful auth refunds the token consumed at the top so a
		// legitimate high-throughput agent never accumulates penalty.
		if rt.limiter != nil {
			rt.limiter.Refund(key)
		}

		ctx := context.WithValue(r.Context(), tokenContextKey, tok)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sourceIPKey extracts the source IP for rate-limit keying. Strips port;
// deliberately ignores X-Forwarded-For (an unauthenticated header an
// attacker would set to evade the limiter). Operators behind a trusted
// reverse proxy who need XFF-based keying should add an explicit
// "trusted proxy" setting in a future iteration.
func sourceIPKey(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// retryAfterSeconds renders a Duration as the Retry-After header value
// (an integer count of seconds, RFC 9110 §10.2.3 — delta-seconds form).
func retryAfterSeconds(d time.Duration) string {
	s := int(d.Seconds())
	if s < 1 {
		s = 1
	}
	return fmt.Sprintf("%d", s)
}

// listConnections returns the connections accessible to the authenticated token.
func (rt *Router) listConnections(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromContext(r)
	if tok == nil {
		writeError(w, http.StatusUnauthorized, "no token in context")
		return
	}

	type connInfo struct {
		ID          string `json:"id"`
		Connector   string `json:"connector"`
		DisplayName string `json:"display_name"`
		Status      string `json:"status"`
	}

	connIDs := rt.tokenConnectionIDs(tok)
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
			Status:      conn.Status,
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

	// Verify the token may reach this connection. In IAM mode the rules are the
	// gate (the engine default-denies if no rule permits); in legacy mode the
	// connection must be bound by at least one of the token's roles.
	if !rt.tokenConnectionAllowed(tok, connID) {
		writeError(w, http.StatusForbidden, fmt.Sprintf("connection %q not allowed for this token", connID))
		return
	}

	// Pre-flight: if the connection is already flagged needs_reauth, fail
	// fast with a structured response so the agent's wrapper can surface the
	// re-auth URL to its human. Saves us building the connector and running
	// policy only to fail at Token inside Execute.
	if c, err := rt.connections.Get(connID); err == nil && c.Status == connections.StatusReauthRequired {
		writeReauthError(w, connID, c.ReauthReason)
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
		rt.writeConnectionError(w, http.StatusNotFound, fmt.Sprintf("connector not found: %v", err), connID, err)
		return
	}

	// Evaluate policy. The decision SOURCE is the IAM engine when enabled, else
	// the legacy evaluator; both yield a *policy.PolicyDecision, so all
	// downstream control flow is identical.
	decision, err := rt.decide(r.Context(), tok, conn, connID, operation, params)
	if err != nil {
		writeError(w, http.StatusForbidden, fmt.Sprintf("policy error: %v", err))
		return
	}

	durationMs := time.Since(start).Milliseconds()

	switch decision.Action {
	case "allow":
		result, err := conn.Execute(r.Context(), operation, params)
		if err != nil {
			// W1.1: header-denied is a distinct deny class, not an opaque
			// 500. Surface it via http_proxy.header_denied policy_result and
			// HTTP 400 so analytics can spot exploit attempts.
			if errors.Is(err, httpproxy.ErrHeaderDenied) {
				rt.logAudit(tok, connID, operation, params, "http_proxy.header_denied", err.Error(), time.Since(start).Milliseconds())
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			// W1.3: mcp_proxy upstream response body exceeded the cap.
			if errors.Is(err, mcpproxy.ErrResponseOversized) {
				rt.logAudit(tok, connID, operation, params, "mcp_proxy.response_oversized", err.Error(), time.Since(start).Milliseconds())
				writeError(w, http.StatusBadGateway, err.Error())
				return
			}
			// W1.4: github cross-fork PR head denied at the connector layer.
			if errors.Is(err, githubconn.ErrCrossForkHeadDenied) {
				rt.logAudit(tok, connID, operation, params, "github.cross_fork_head_denied", err.Error(), time.Since(start).Milliseconds())
				writeError(w, http.StatusForbidden, err.Error())
				return
			}
			if errors.Is(err, connector.ErrOperationNotEnabled) {
				reason := stripSentinelPrefix(err, connector.ErrOperationNotEnabled)
				rt.logAudit(tok, connID, operation, params, "operation_not_enabled", reason, time.Since(start).Milliseconds())
				writeOperationNotEnabledError(w, connID, operation, reason)
				return
			}
			rt.logAudit(tok, connID, operation, params, "allow(error)", "", time.Since(start).Milliseconds())
			if errors.Is(err, connector.ErrNeedsReauth) {
				reason := err.Error()
				if c, e := rt.connections.Get(connID); e == nil && c.ReauthReason != "" {
					reason = c.ReauthReason
				}
				writeReauthError(w, connID, reason)
				return
			}
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("execute operation: %v", err))
			return
		}
		// Detect the http_proxy auth_query_param override signal
		// smuggled through the result map's private `_auth_query_overridden`
		// key. Strip the key before serialising so the agent never sees it.
		policyResult := "allow"
		if er, ok := result.(*httpproxy.ExecuteResult); ok && er.AuthQueryOverridden {
			policyResult = "http_proxy.auth_query_overridden"
		}
		resultJSON, _ := json.Marshal(result)
		var reason string
		if len(decision.Filters) > 0 {
			filtered, summary, ferr := policy.ApplyResponseFilters(resultJSON, decision.Filters)
			if ferr != nil {
				rt.logAudit(tok, connID, operation, params, "response_filter_failed", ferr.Error(), time.Since(start).Milliseconds())
				writeError(w, http.StatusInternalServerError, "response filter failed")
				return
			}
			resultJSON = filtered
			reason = summary
		}
		rt.logAudit(tok, connID, operation, params, policyResult, reason, time.Since(start).Milliseconds())
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
			// W1.1: same header-denied detection as the pre-approval path.
			if errors.Is(err, httpproxy.ErrHeaderDenied) {
				rt.logAudit(tok, connID, operation, params, "http_proxy.header_denied", err.Error(), time.Since(start).Milliseconds())
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			// W1.3: mcp_proxy oversized response on the post-approval path.
			if errors.Is(err, mcpproxy.ErrResponseOversized) {
				rt.logAudit(tok, connID, operation, params, "mcp_proxy.response_oversized", err.Error(), time.Since(start).Milliseconds())
				writeError(w, http.StatusBadGateway, err.Error())
				return
			}
			// W1.4: github cross-fork PR head denied on the post-approval path.
			if errors.Is(err, githubconn.ErrCrossForkHeadDenied) {
				rt.logAudit(tok, connID, operation, params, "github.cross_fork_head_denied", err.Error(), time.Since(start).Milliseconds())
				writeError(w, http.StatusForbidden, err.Error())
				return
			}
			if errors.Is(err, connector.ErrOperationNotEnabled) {
				reason := stripSentinelPrefix(err, connector.ErrOperationNotEnabled)
				rt.logAudit(tok, connID, operation, params, "operation_not_enabled", reason, time.Since(start).Milliseconds())
				writeOperationNotEnabledError(w, connID, operation, reason)
				return
			}
			rt.logAudit(tok, connID, operation, params, "approved(error)", "", time.Since(start).Milliseconds())
			if errors.Is(err, connector.ErrNeedsReauth) {
				reason := err.Error()
				if c, e := rt.connections.Get(connID); e == nil && c.ReauthReason != "" {
					reason = c.ReauthReason
				}
				writeReauthError(w, connID, reason)
				return
			}
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("execute operation: %v", err))
			return
		}
		// Same private-key smuggling pattern as the pre-approval path.
		policyResult := "approved"
		if er, ok := result.(*httpproxy.ExecuteResult); ok && er.AuthQueryOverridden {
			policyResult = "http_proxy.auth_query_overridden"
		}
		resultJSON, _ := json.Marshal(result)
		var approvedReason string
		if len(decision.Filters) > 0 {
			filtered, summary, ferr := policy.ApplyResponseFilters(resultJSON, decision.Filters)
			if ferr != nil {
				rt.logAudit(tok, connID, operation, params, "response_filter_failed", ferr.Error(), time.Since(start).Milliseconds())
				writeError(w, http.StatusInternalServerError, "response filter failed")
				return
			}
			resultJSON = filtered
			approvedReason = summary
		}
		rt.logAudit(tok, connID, operation, params, policyResult, approvedReason, time.Since(start).Milliseconds())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(resultJSON)

	default:
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("unknown policy action: %s", decision.Action))
	}
}

// decide produces the policy decision for a request. When the IAM engine is
// enabled it is the decision source (iam.Decide); otherwise the legacy
// per-(role,connection) evaluator. Both return a *policy.PolicyDecision, so the
// caller's allow/deny/approval handling is identical either way. Errors
// fail closed (the caller maps them to 403).
func (rt *Router) decide(ctx context.Context, tok *tokens.Token, conn connector.Connector, connID, operation string, params map[string]any) (*policy.PolicyDecision, error) {
	if rt.iamEnabled() {
		connStatus := ""
		if c, err := rt.connections.Get(connID); err == nil {
			connStatus = c.Status
		}
		// RBAC: the token's whole role set composes (spec §5.1); the engine
		// default-denies if no rule of any role permits this op on this connection.
		return rt.iam.Decide(ctx, rt.registry, tok.ID, tok.RoleIDs, conn.Type(), connID, connStatus, operation, params)
	}
	evaluator, err := rt.getEvaluatorForToken(tok, connID)
	if err != nil {
		return nil, err
	}
	return evaluator.Evaluate(ctx, &policy.PolicyRequest{
		Operation:  operation,
		Connection: connID,
		Connector:  conn.Type(),
		Params:     params,
		Metadata:   params,
		Phase:      "pre",
	})
}

// getEvaluatorForToken builds a legacy composite evaluator from the union of the
// policies bound to connID across ALL of the token's roles (multi-role). For a
// single-role token this is exactly the one role's policies (back-compat).
func (rt *Router) getEvaluatorForToken(tok *tokens.Token, connID string) (policy.Evaluator, error) {
	seen := map[string]bool{}
	var policyIDs []string
	for _, role := range rt.rolesForToken(tok) {
		for _, pid := range role.PoliciesForConnection(connID) {
			if !seen[pid] {
				seen[pid] = true
				policyIDs = append(policyIDs, pid)
			}
		}
	}
	if len(policyIDs) == 0 {
		return nil, fmt.Errorf("no policies for connection %q — access denied", connID)
	}
	return rt.policies.BuildEvaluator(policyIDs)
}

// handleProxy is the transparent HTTP proxy handler. It extracts the connection
// alias and path from the URL, validates the token has access, and delegates
// to the ProxyHTTP method on the http_proxy connector. The agent's Sieve token
// is swapped for the real API credential transparently.
// URL format: /proxy/{connection}/{path...}
// Example: /proxy/anthropic/v1/messages
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

	if !rt.tokenConnectionAllowed(tok, connID) {
		writeError(w, http.StatusForbidden, fmt.Sprintf("connection %q not allowed", connID))
		return
	}

	conn, err := rt.connections.GetConnector(connID)
	if err != nil {
		rt.writeConnectionError(w, http.StatusNotFound, "connection not available", connID, err)
		return
	}

	// The connector must be an http_proxy type with ProxyHTTP method.
	// Signature: (filterSummary, queryOverridden, error). filterSummary
	// is used to detect auth_value scrub matches; queryOverridden is
	// true when the auth_query_param injection dropped an agent-supplied
	// value. Both feed the audit-log policy_result selection.
	type httpProxier interface {
		ProxyHTTP(w http.ResponseWriter, r *http.Request, path string, filters []policy.ResponseFilter) (string, bool, error)
	}

	proxy, ok := conn.(httpProxier)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("connection %q is not an HTTP proxy", connID))
		return
	}

	// Connectors that expose AuthValueScrubFilter (today: http_proxy) get a
	// built-in scrub filter prepended to the policy decision's filter list.
	// This forces http_proxy through the buffered (filtered) path of
	// ProxyHTTP, so the configured auth_value cannot reach the agent — even
	// in 4xx/5xx error bodies that would otherwise stream through unfiltered.
	type authValueFilterer interface {
		AuthValueScrubFilter() *policy.ResponseFilter
	}

	start := time.Now()
	operation := "proxy:" + r.Method + ":" + proxyPath

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

	// Policy evaluation — proxy requests go through the same pipeline. With IAM
	// enabled, the action is the connector's `proxy_request` op and the HTTP
	// method/path land in context (policies gate via context.http_method /
	// context.param.path). With the legacy engine, the synthetic
	// "proxy:METHOD:path" operation name is matched by rules.
	var decision *policy.PolicyDecision
	if rt.iamEnabled() {
		connStatus := ""
		if c, e := rt.connections.Get(connID); e == nil {
			connStatus = c.Status
		}
		decision, err = rt.iam.Decide(r.Context(), rt.registry, tok.ID, tok.RoleIDs, "http_proxy", connID, connStatus, "proxy_request", policyParams)
	} else {
		var evaluator policy.Evaluator
		evaluator, err = rt.getEvaluatorForToken(tok, connID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "policy error")
			return
		}
		decision, err = evaluator.Evaluate(r.Context(), &policy.PolicyRequest{
			Operation:  operation,
			Connection: connID,
			Connector:  "http_proxy",
			Phase:      "pre",
			Params:     policyParams,
			Metadata:   policyParams,
		})
	}
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

	// Auto-attach the auth_value scrub filter for http_proxy connections that
	// have it enabled. Prepended (not appended) so it runs before any
	// operator-attached redact pattern; operator filters never see the
	// unredacted auth_value. Closes audit row W1.2.
	if avf, ok := conn.(authValueFilterer); ok {
		if scrubFilter := avf.AuthValueScrubFilter(); scrubFilter != nil {
			decision.Filters = append([]policy.ResponseFilter{*scrubFilter}, decision.Filters...)
		}
	}

	filterSummary, queryOverridden, err := proxy.ProxyHTTP(w, r, proxyPath, decision.Filters)
	if err != nil {
		// W1.1: a denied header is a distinct deny class; the audit row uses
		// http_proxy.header_denied so analytics can spot exploitation attempts.
		policyResult := "bad_request"
		if errors.Is(err, httpproxy.ErrHeaderDenied) {
			policyResult = "http_proxy.header_denied"
		}
		rt.logAudit(tok, connID, operation, nil, policyResult, err.Error(), time.Since(start).Milliseconds())
		return
	}
	// Audit identifier precedence:
	// 1. http_proxy.auth_query_overridden (override is an attempted exploit)
	// 2. http_proxy.auth_value_scrubbed (routine defensive event)
	// 3. proxied (vanilla success)
	policyResult := "proxied"
	if queryOverridden {
		policyResult = "http_proxy.auth_query_overridden"
	} else if strings.Contains(filterSummary, "auth_value_scrubbed") {
		policyResult = "http_proxy.auth_value_scrubbed"
	}
	rt.logAudit(tok, connID, operation, nil, policyResult, filterSummary, time.Since(start).Milliseconds())
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

// rolesForToken resolves every role assigned to a token (RBAC composition,
// spec §5.1). Missing roles are skipped — a deleted role simply grants nothing.
func (rt *Router) rolesForToken(tok *tokens.Token) []*roles.Role {
	out := make([]*roles.Role, 0, len(tok.RoleIDs))
	for _, rid := range tok.RoleIDs {
		if r, err := rt.roles.Get(rid); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// tokenConnectionIDs is the union of connection IDs bound across all the token's
// roles (the legacy binding view; used for discovery/listing).
func (rt *Router) tokenConnectionIDs(tok *tokens.Token) []string {
	seen := map[string]bool{}
	var out []string
	for _, role := range rt.rolesForToken(tok) {
		for _, c := range role.ConnectionIDs() {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// tokenConnectionAllowed gates connection access for a token. In IAM mode the
// rules are the gate — an IAM role need not carry a legacy binding, and the
// engine default-denies if no rule of any assigned role permits the op on this
// connection (spec §10) — so we do NOT pre-check here. In legacy mode the
// connection must be bound by at least one of the token's roles.
func (rt *Router) tokenConnectionAllowed(tok *tokens.Token, connID string) bool {
	if rt.iamEnabled() {
		return true
	}
	for _, c := range rt.tokenConnectionIDs(tok) {
		if c == connID {
			return true
		}
	}
	return false
}

// tokenCandidateConnections lists connections to consider for Gmail alias
// resolution. Legacy: the token's bound connections. IAM: all connections — the
// per-op Decide is the real gate, so a pure-IAM role (no legacy binding) can
// still resolve "me" to a Google connection (which Decide then allows or denies).
func (rt *Router) tokenCandidateConnections(tok *tokens.Token) []string {
	if rt.iamEnabled() {
		conns, err := rt.connections.List()
		if err != nil {
			return rt.tokenConnectionIDs(tok)
		}
		ids := make([]string, 0, len(conns))
		for _, c := range conns {
			ids = append(ids, c.ID)
		}
		return ids
	}
	return rt.tokenConnectionIDs(tok)
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

// writeStructuredError writes a JSON error response with separate `error`
// (machine-readable code) and `message` (human-readable detail) fields.
// Used by sentinel-mapping for ErrReauthRequired / ErrConnectionDisabled
// so callers can branch on a stable error code without parsing the
// message text.
func writeStructuredError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}

// writeConnectionError centralizes connection-state response mapping.
// Sentinel priority:
// - secrets.ErrKeyringNotLoaded → 503 "service locked"
// - secrets.ErrKeyringRotating → 503 + Retry-After so retry-aware
// agent SDKs back off cleanly during the brief rotation window
// - connections.ErrReauthRequired → 403 reauth_required envelope
// (delegates to writeReauthError so the byte shape is identical to
// the post-flight path)
// - connections.ErrConnectionDisabled → 403 {"error":"disabled",...}
// Otherwise falls through to the caller-supplied default. Routed through
// one helper so every credential-touching endpoint produces identical
// bodies.
// rt is needed so the helper can look up the connection's reauth_reason
// when emitting the reauth_required envelope. connID is the connection
// the caller was attempting to address; both threads through to the
// envelope's connection_id / reauth_url fields.
func (rt *Router) writeConnectionError(w http.ResponseWriter, defaultStatus int, defaultMessage, connID string, err error) {
	switch {
	case errors.Is(err, secrets.ErrKeyringNotLoaded):
		writeError(w, http.StatusServiceUnavailable, "service locked: passphrase required")
	case errors.Is(err, secrets.ErrKeyringRotating):
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, "rotation in progress, retry shortly")
	case errors.Is(err, connections.ErrReauthRequired):
		reason := ""
		if connID != "" {
			if c, e := rt.connections.Get(connID); e == nil {
				reason = c.ReauthReason
			}
		}
		writeReauthError(w, connID, reason)
	case errors.Is(err, connections.ErrConnectionDisabled):
		writeStructuredError(w, http.StatusForbidden, "disabled",
			"connection is disabled; an admin must re-enable it before agents can use it")
	default:
		writeError(w, defaultStatus, defaultMessage)
	}
}

// writeOperationNotEnabledError emits HTTP 501 with the canonical
// operation_not_enabled envelope:
// {
// "error": "operation_not_enabled",
// "connection_id": "<connection-id>",
// "operation": "<operation-name>",
// "message": "<reason text from the connector>"
// }
// reason is the connector-supplied detail (the err string with the
// sentinel prefix stripped). Distinct from 403 (reauth) and 503
// (service locked) — agent SDKs should NOT retry.
func writeOperationNotEnabledError(w http.ResponseWriter, connID, operation, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]any{
		"error":         "operation_not_enabled",
		"connection_id": connID,
		"operation":     operation,
		"message":       reason,
	})
}

// stripSentinelPrefix removes the wrapped sentinel error's leading
// "<sentinel-text>: " prefix from err.Error so the response body
// carries only the connector-supplied reason. If the format isn't a
// wrap, returns the full error string.
func stripSentinelPrefix(err error, sentinel error) string {
	msg := err.Error()
	prefix := sentinel.Error() + ": "
	if strings.HasPrefix(msg, prefix) {
		return msg[len(prefix):]
	}
	return msg
}

// writeReauthError emits the structured response that points an agent (and
// the human reading the agent's tool output) at the re-authentication URL.
// Used both pre-flight (status='reauth_required' detected before Execute)
// and post-flight (Execute returned ErrNeedsReauth, which means the status
// was just transitioned).
// HTTP 403 + the canonical reauth_required envelope. The legacy 503/
// connection_reauth_required response was retired so 503 stays reserved
// for genuinely transient conditions (notably keyring-not-loaded
// "service locked"). See docs/agent-error-contract.md.
func writeReauthError(w http.ResponseWriter, connID, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]any{
		"error":         "reauth_required",
		"connection_id": connID,
		"reason":        reason,
		"reauth_url":    "/connections/" + connID + "/reauth",
		"message":       "This connection's credentials are no longer valid. A human must re-authenticate via the Sieve web UI.",
	})
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
func (rt *Router) resolveGmailConnection(tok *tokens.Token, userId string) (string, error) {
	if userId != "me" {
		// Treat userId as a connection alias — verify it's allowed and is gmail.
		// (IAM: per-op Decide is the real gate; this only resolves the alias.)
		if !rt.tokenConnectionAllowed(tok, userId) {
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

	// "me" — find the first gmail connection this token can resolve.
	for _, connID := range rt.tokenCandidateConnections(tok) {
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

	userId := r.PathValue("userId")
	if userId == "" {
		userId = "me"
	}

	connID, err := rt.resolveGmailConnection(tok, userId)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	// Pre-flight reauth check — short-circuit if the connection is dead.
	if c, err := rt.connections.Get(connID); err == nil && c.Status == connections.StatusReauthRequired {
		writeReauthError(w, connID, c.ReauthReason)
		return
	}

	conn, err := rt.connections.GetConnector(connID)
	if err != nil {
		rt.writeConnectionError(w, http.StatusNotFound, "connector not available", connID, err)
		return
	}

	// Policy check (IAM decision source when enabled, else legacy).
	decision, err := rt.decide(r.Context(), tok, conn, connID, operation, params)
	if err != nil {
		writeError(w, http.StatusForbidden, "policy error: "+err.Error())
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
		if errors.Is(err, connector.ErrOperationNotEnabled) {
			reason := stripSentinelPrefix(err, connector.ErrOperationNotEnabled)
			rt.logAudit(tok, connID, operation, params, "operation_not_enabled", reason, time.Since(start).Milliseconds())
			writeOperationNotEnabledError(w, connID, operation, reason)
			return
		}
		rt.logAudit(tok, connID, operation, params, "error", err.Error(), time.Since(start).Milliseconds())
		if errors.Is(err, connector.ErrNeedsReauth) {
			reason := err.Error()
			if c, e := rt.connections.Get(connID); e == nil && c.ReauthReason != "" {
				reason = c.ReauthReason
			}
			writeReauthError(w, connID, reason)
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Apply response filters collected during pre-execution evaluation.
	resultJSON, _ := json.Marshal(result)
	var reason string
	if len(decision.Filters) > 0 {
		filtered, summary, ferr := policy.ApplyResponseFilters(resultJSON, decision.Filters)
		if ferr != nil {
			rt.logAudit(tok, connID, operation, params, "response_filter_failed", ferr.Error(), time.Since(start).Milliseconds())
			writeError(w, http.StatusInternalServerError, "response filter failed")
			return
		}
		resultJSON = filtered
		reason = summary
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

	type userInfo struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		Email       string `json:"emailAddress,omitempty"`
	}

	var users []userInfo
	for _, connID := range rt.tokenCandidateConnections(tok) {
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
	// Gmail's REST API accepts ?format= with values full, metadata, minimal,
	// raw. We route format=raw to a distinct connector op so policies can bind
	// to it explicitly (an archival role may grant read_email_raw but not
	// read_email, or vice versa). Every other format value — including unset
	// — keeps the existing read_email path which returns the Sieve-simplified
	// shape; the connector's behavior is "full" regardless.
	op := "read_email"
	if r.URL.Query().Get("format") == "raw" {
		op = "read_email_raw"
	}
	rt.gmailExecute(w, r, op, map[string]any{
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
