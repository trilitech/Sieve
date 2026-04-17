// Package web implements the Sieve admin web UI, served on a separate port
// from the API/MCP server. This separation is intentional: the web UI is for
// human operators only and must not be accessible to AI agents.
//
// Key security patterns:
//
//   - rejectIfAgentToken: approval endpoints check for Sieve bearer tokens in
//     the Authorization header. If found, the request is rejected. This prevents
//     an agent from self-approving its own pending operations by calling the
//     web UI endpoints directly. The web UI port (19816) should ideally not be
//     exposed to agents at all, but this check provides defense-in-depth.
//
//   - OAuth flow with pendingOAuth: When adding a Google account connection, the
//     connection is NOT saved to the database until OAuth completes successfully.
//     The pendingOAuth map holds the connection metadata (ID, type, display name)
//     keyed by a random state parameter. After Google redirects back with a
//     valid code, we exchange it for tokens, verify the email address, and only
//     THEN persist the connection. This prevents orphaned connections with
//     no credentials. The state parameter has a 10-minute expiry to limit the
//     window for CSRF-style attacks.
//
//   - State parameter: The OAuth state ties the callback to a specific
//     pending connection. It's a 16-byte random hex string, checked and consumed
//     atomically in handleOAuthCallback. This prevents both CSRF and replay attacks.
package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/murbard/Sieve/internal/approval"
	"github.com/murbard/Sieve/internal/audit"
	"github.com/murbard/Sieve/internal/connections"
	"github.com/murbard/Sieve/internal/connector"
	"github.com/murbard/Sieve/internal/policies"
	"github.com/murbard/Sieve/internal/roles"
	"github.com/murbard/Sieve/internal/scriptgen"
	"github.com/murbard/Sieve/internal/settings"
	"github.com/murbard/Sieve/internal/tokens"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	googleapi "google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

//go:embed templates/*
var templateFS embed.FS

// Server is the web UI server for the Sieve admin interface.
type Server struct {
	tokens               *tokens.Service
	connections          *connections.Service
	policies             *policies.Service
	roles                *roles.Service
	registry             *connector.Registry
	approval             *approval.Queue
	audit                *audit.Logger
	settings             *settings.Service
	scriptgen            *scriptgen.Service
	templates            map[string]*template.Template
	googleCredentialsFile string

	oauthMu     sync.Mutex
	oauthPending map[string]pendingOAuth // state -> pending connection info

	stopCleanup     chan struct{} // closed by Close() to stop the cleanup goroutine
	stopCleanupOnce sync.Once    // ensures Close() is safe under concurrent calls
}

// funcMap returns the template function map used across all templates.
func funcMap() template.FuncMap {
	return template.FuncMap{
		"json": func(v any) template.JS {
			b, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return template.JS(fmt.Sprintf("null /* error: %v */", err))
			}
			return template.JS(b)
		},
		"jsonAttr": func(v any) string {
			b, err := json.Marshal(v)
			if err != nil {
				return "{}"
			}
			return string(b)
		},
		"timeAgo": func(t time.Time) string {
			d := time.Since(t)
			switch {
			case d < time.Minute:
				return "just now"
			case d < time.Hour:
				return fmt.Sprintf("%dm ago", int(d.Minutes()))
			case d < 24*time.Hour:
				return fmt.Sprintf("%dh ago", int(d.Hours()))
			case d < 30*24*time.Hour:
				return fmt.Sprintf("%dd ago", int(d.Hours()/24))
			default:
				return fmt.Sprintf("%dmo ago", int(d.Hours()/(24*30)))
			}
		},
		"truncate": func(n int, s string) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
		"joinStrings": func(ss []string, sep string) string {
			return strings.Join(ss, sep)
		},
		"mapGet": func(m map[string]string, key string) string {
			if v, ok := m[key]; ok {
				return v
			}
			return key // fallback to showing the key itself
		},
		"add": func(a, b int) int {
			return a + b
		},
		"subtract": func(a, b int) int {
			return a - b
		},
		"lt": func(a, b int) bool {
			return a < b
		},
		"gt": func(a, b int) bool {
			return a > b
		},
		"derefTime": func(t *time.Time) time.Time {
			if t == nil {
				return time.Time{}
			}
			return *t
		},
	}
}

// NewServer creates a new web UI server. It starts a background goroutine for
// OAuth cleanup; callers MUST call (*Server).Close() when the server is no
// longer needed (e.g. via defer or t.Cleanup) to stop the goroutine.
func NewServer(
	tokensSvc *tokens.Service,
	connsSvc *connections.Service,
	policiesSvc *policies.Service,
	rolesSvc *roles.Service,
	registry *connector.Registry,
	approvalQ *approval.Queue,
	auditLog *audit.Logger,
	googleCredentialsFile string,
	settingsSvc *settings.Service,
	scriptgenSvc *scriptgen.Service,
) *Server {
	s := &Server{
		tokens:               tokensSvc,
		connections:          connsSvc,
		policies:             policiesSvc,
		roles:                rolesSvc,
		registry:             registry,
		approval:             approvalQ,
		audit:                auditLog,
		settings:             settingsSvc,
		scriptgen:            scriptgenSvc,
		templates:            make(map[string]*template.Template),
		googleCredentialsFile: googleCredentialsFile,
		oauthPending:         make(map[string]pendingOAuth),
		stopCleanup:          make(chan struct{}),
	}

	// Parse each page template together with the nav partial.
	pages := []string{"connections", "tokens", "approvals", "audit", "policies", "policy_edit", "settings", "roles", "role_edit"}
	for _, page := range pages {
		t := template.Must(
			template.New("").Funcs(funcMap()).ParseFS(templateFS,
				"templates/nav.html",
				fmt.Sprintf("templates/%s.html", page),
			),
		)
		s.templates[page] = t
	}

	// Background sweep of abandoned OAuth flows. Without this, the
	// oauthPending map would grow unboundedly (entries are normally
	// deleted when the callback completes, but incomplete flows would
	// never get cleaned up).
	go s.oauthPendingCleanupLoop()

	return s
}

// Handler returns the HTTP handler with all routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Dashboard redirect
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/connections", http.StatusFound)
	})

	// Connections
	mux.HandleFunc("GET /connections", s.handleConnections)
	mux.HandleFunc("POST /connections/add", s.handleConnectionAdd)
	mux.HandleFunc("POST /connections/{id}/delete", s.handleConnectionDelete)
	mux.HandleFunc("GET /oauth/callback", s.handleOAuthCallback)

	// Tokens
	mux.HandleFunc("GET /tokens", s.handleTokens)
	mux.HandleFunc("POST /tokens/create", s.handleTokenCreate)
	mux.HandleFunc("POST /tokens/{id}/revoke", s.handleTokenRevoke)

	// Roles
	mux.HandleFunc("GET /roles", s.handleRoles)
	mux.HandleFunc("POST /roles/create", s.handleRoleCreate)
	mux.HandleFunc("POST /roles/{id}/delete", s.handleRoleDelete)
	mux.HandleFunc("GET /roles/{id}/edit", s.handleRoleEdit)
	mux.HandleFunc("POST /roles/{id}/update", s.handleRoleUpdate)

	// Policies
	mux.HandleFunc("GET /policies", s.handlePolicies)
	mux.HandleFunc("POST /policies/create", s.handlePolicyCreate)
	mux.HandleFunc("GET /policies/{id}/edit", s.handlePolicyEdit)
	mux.HandleFunc("POST /policies/{id}/update", s.handlePolicyUpdate)
	mux.HandleFunc("POST /policies/{id}/delete", s.handlePolicyDelete)

	// Approvals
	mux.HandleFunc("GET /approvals", s.handleApprovals)
	mux.HandleFunc("POST /approvals/{id}/approve", s.handleApprovalApprove)
	mux.HandleFunc("POST /approvals/{id}/reject", s.handleApprovalReject)

	// Audit
	mux.HandleFunc("GET /audit", s.handleAudit)

	// Settings
	mux.HandleFunc("GET /settings", s.handleSettings)
	mux.HandleFunc("POST /settings", s.handleSettingsSave)

	// Script generation API
	mux.HandleFunc("POST /api/generate-script", s.handleGenerateScript)
	mux.HandleFunc("POST /api/save-script", s.handleSaveScript)

	// Docs
	mux.HandleFunc("GET /docs/{name}", s.handleDocs)

	return mux
}

func (s *Server) render(w http.ResponseWriter, page string, data any) {
	t, ok := s.templates[page]
	if !ok {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, page, data); err != nil {
		http.Error(w, fmt.Sprintf("render error: %v", err), http.StatusInternalServerError)
	}
}

// --- Connections handlers ---

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	allConns, err := s.connections.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// The ?type= parameter filters connections by connector category.
	connType := r.URL.Query().Get("type")
	active := "connections"
	if connType != "" {
		active = "connections-" + connType
	}

	// Determine each connection's category for filtering. Google connections
	// use the connector type directly. HTTP proxy connections use the
	// "category" field from their config (llm, aws, or generic http_proxy).
	var conns []connections.Connection
	for _, c := range allConns {
		if connType == "" {
			conns = append(conns, c)
		} else {
			cat := c.ConnectorType // "google", "http_proxy", "mcp_proxy"
			if cat == "http_proxy" {
				// Check config for a more specific category.
				if full, err := s.connections.GetWithConfig(c.ID); err == nil {
					if cfgCat, ok := full.Config["category"].(string); ok && cfgCat != "" {
						cat = cfgCat
					}
				}
			}
			// "proxy" tab shows both http_proxy and mcp_proxy
			if connType == "proxy" {
				if cat == "http_proxy" || c.ConnectorType == "mcp_proxy" {
					conns = append(conns, c)
				}
			} else if cat == connType {
				conns = append(conns, c)
			}
		}
	}

	// Filter the catalog to only show relevant connector cards.
	// The catalog contains registered connectors (Google, HTTP Proxy).
	// LLM and AWS are hardcoded cards in the template, not in the catalog.
	catalog := s.registry.Catalog()
	if connType != "" && connType != "llm" && connType != "cloud" {
		filtered := make(map[string][]connector.ConnectorMeta)
		for category, metas := range catalog {
			for _, m := range metas {
				match := m.Type == connType
				// "proxy" tab shows both http_proxy and mcp_proxy connectors
				if connType == "proxy" {
					match = m.Type == "http_proxy" || m.Type == "mcp_proxy"
				}
				if match {
					filtered[category] = append(filtered[category], m)
				}
			}
		}
		catalog = filtered
	} else if connType == "llm" || connType == "cloud" {
		// LLM and AWS cards are hardcoded in the template, not in the catalog.
		catalog = nil
	}

	data := map[string]any{
		"Active":      active,
		"Connections": conns,
		"Catalog":     catalog,
		"ConnType":    connType,
	}
	s.render(w, "connections", data)
}

// pendingOAuth holds info for a connection being added via OAuth.
type pendingOAuth struct {
	ID            string
	ConnectorType string
	DisplayName   string
	CreatedAt     time.Time
}

func (s *Server) handleConnectionAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	id := r.FormValue("id")
	connectorType := r.FormValue("connector_type")
	displayName := r.FormValue("display_name")

	if id == "" || connectorType == "" || displayName == "" {
		http.Error(w, "all fields are required", http.StatusBadRequest)
		return
	}

	// Check if alias is already taken.
	if exists, _ := s.connections.Exists(id); exists {
		http.Error(w, fmt.Sprintf("connection %q already exists", id), http.StatusBadRequest)
		return
	}

	// For proxy connectors (HTTP or MCP), read the proxy-specific fields
	// from the form and save the connection directly (no OAuth flow needed).
	if connectorType == "http_proxy" || connectorType == "mcp_proxy" {
		config := map[string]any{
			"target_url":  r.FormValue("target_url"),
			"auth_header": r.FormValue("auth_header"),
			"auth_value":  r.FormValue("auth_value"),
		}
		// Category tag (e.g., "llm" for LLM provider connections).
		if cat := r.FormValue("category"); cat != "" {
			config["category"] = cat
		}
		// AWS Bedrock-specific fields.
		if ak := r.FormValue("aws_access_key"); ak != "" {
			config["aws_access_key"] = ak
		}
		if region := r.FormValue("aws_region"); region != "" {
			config["aws_region"] = region
		}
		// Parse extra_headers if provided (JSON object of additional headers).
		if extra := r.FormValue("extra_headers"); extra != "" {
			var headers map[string]any
			if err := json.Unmarshal([]byte(extra), &headers); err == nil {
				config["extra_headers"] = headers
			}
		}
		if err := s.connections.Add(id, connectorType, displayName, config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/connections", http.StatusSeeOther)
		return
	}

	// For OAuth connectors (gmail), don't save the connection yet. We start
	// the OAuth flow first and only persist the connection in handleOAuthCallback
	// after receiving valid credentials. This avoids orphaned connections that
	// appear in the UI but have no working credentials.
	if connectorType == "google" {
		conf, err := s.googleOAuthConfig(r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		stateBytes := make([]byte, 16)
		if _, err := rand.Read(stateBytes); err != nil {
			http.Error(w, "failed to generate state", http.StatusInternalServerError)
			return
		}
		state := hex.EncodeToString(stateBytes)

		s.oauthMu.Lock()
		s.oauthPending[state] = pendingOAuth{ID: id, ConnectorType: connectorType, DisplayName: displayName, CreatedAt: time.Now()}
		s.oauthMu.Unlock()

		url := conf.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
		http.Redirect(w, r, url, http.StatusFound)
		return
	}

	// Non-OAuth connectors: save directly.
	if err := s.connections.Add(id, connectorType, displayName, map[string]any{}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

func (s *Server) handleConnectionDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.connections.Remove(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// --- OAuth handlers ---

func (s *Server) googleOAuthConfig(host string) (*oauth2.Config, error) {
	data, err := os.ReadFile(s.googleCredentialsFile)
	if err != nil {
		return nil, fmt.Errorf("read credentials file: %w", err)
	}

	scopes := []string{
		"https://www.googleapis.com/auth/gmail.modify",
		"https://www.googleapis.com/auth/drive",
		"https://www.googleapis.com/auth/calendar",
		"https://www.googleapis.com/auth/contacts",
		"https://www.googleapis.com/auth/spreadsheets",
	}
	conf, err := google.ConfigFromJSON(data, scopes...)
	if err != nil {
		return nil, fmt.Errorf("parse credentials file: %w", err)
	}

	// Single callback URL — connection ID is carried in the state parameter.
	conf.RedirectURL = fmt.Sprintf("http://%s/oauth/callback", host)
	return conf, nil
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if state == "" || code == "" {
		http.Error(w, "missing state or code parameter", http.StatusBadRequest)
		return
	}

	// Look up and consume the pending connection info atomically. The expiry
	// check and deletion are both inside the lock to prevent a TOCTOU race
	// where a concurrent request could use an expired state between the check
	// and the delete.
	s.oauthMu.Lock()
	pending, ok := s.oauthPending[state]
	if ok && time.Since(pending.CreatedAt) > 10*time.Minute {
		delete(s.oauthPending, state)
		s.oauthMu.Unlock()
		http.Error(w, "OAuth session expired — try adding the connection again", http.StatusBadRequest)
		return
	}
	if ok {
		delete(s.oauthPending, state)
	}
	s.oauthMu.Unlock()

	if !ok {
		http.Error(w, "invalid or expired state — try adding the connection again", http.StatusBadRequest)
		return
	}

	conf, err := s.googleOAuthConfig(r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Exchange the authorization code for a token.
	token, err := conf.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, fmt.Sprintf("token exchange failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Use the token to get the user's email address from Gmail.
	svc, err := googleapi.NewService(context.Background(), option.WithTokenSource(conf.TokenSource(context.Background(), token)))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create gmail service: %v", err), http.StatusInternalServerError)
		return
	}

	profile, err := svc.Users.GetProfile("me").Do()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get gmail profile: %v", err), http.StatusInternalServerError)
		return
	}

	// Build the connection config with real credentials.
	tokenMap := map[string]any{
		"access_token":  token.AccessToken,
		"token_type":    token.TokenType,
		"refresh_token": token.RefreshToken,
	}
	if !token.Expiry.IsZero() {
		tokenMap["expiry"] = token.Expiry.Format(time.RFC3339)
	}
	connConfig := map[string]any{
		"email":         profile.EmailAddress,
		"oauth_token":   tokenMap,
		"client_id":     conf.ClientID,
		"client_secret": conf.ClientSecret,
	}

	// NOW save the connection — only after OAuth succeeded and we have
	// verified credentials. This is the commit point: if anything above
	// failed, no connection record exists and the user can try again cleanly.
	if err := s.connections.Add(pending.ID, pending.ConnectorType, pending.DisplayName, connConfig); err != nil {
		http.Error(w, fmt.Sprintf("failed to save connection: %v", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// oauthPendingCleanupLoop runs until Close() is called, deleting oauthPending
// entries older than 10 minutes every 5 minutes.
func (s *Server) oauthPendingCleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.sweepOAuthPending(time.Now())
		case <-s.stopCleanup:
			return
		}
	}
}

// Close stops the background cleanup goroutine. It is safe to call
// concurrently and multiple times; subsequent calls are no-ops.
func (s *Server) Close() {
	s.stopCleanupOnce.Do(func() {
		close(s.stopCleanup)
	})
}

// sweepOAuthPending removes pendingOAuth entries older than 10 minutes.
// Extracted for testability.
func (s *Server) sweepOAuthPending(now time.Time) {
	s.oauthMu.Lock()
	defer s.oauthMu.Unlock()
	for state, pending := range s.oauthPending {
		if now.Sub(pending.CreatedAt) > 10*time.Minute {
			delete(s.oauthPending, state)
		}
	}
}

// --- Tokens handlers ---

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request) {
	allToks, err := s.tokens.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Filter tokens by status.
	filter := r.URL.Query().Get("filter")
	now := time.Now().UTC()
	var toks []tokens.Token
	for _, t := range allToks {
		switch filter {
		case "active":
			if t.Revoked {
				continue
			}
			if t.ExpiresAt != nil && now.After(*t.ExpiresAt) {
				continue
			}
		case "revoked":
			if !t.Revoked {
				continue
			}
		case "expired":
			if t.ExpiresAt == nil || !now.After(*t.ExpiresAt) {
				continue
			}
			if t.Revoked {
				continue // show revoked under "revoked", not "expired"
			}
		}
		toks = append(toks, t)
	}

	rolesList, err := s.roles.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Build a role ID → name map so the template can display names.
	roleNames := make(map[string]string, len(rolesList))
	for _, r := range rolesList {
		roleNames[r.ID] = r.Name
	}

	data := map[string]any{
		"Active":    "tokens",
		"Tokens":    toks,
		"Roles":     rolesList,
		"RoleNames": roleNames,
		"Filter":    filter,
	}
	s.render(w, "tokens", data)
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	roleID := r.FormValue("role_id")

	if roleID == "" {
		http.Error(w, "a role is required", http.StatusBadRequest)
		return
	}

	var expiresIn time.Duration
	if expStr := r.FormValue("expires_in"); expStr != "" {
		d, err := time.ParseDuration(expStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid expires_in: %v", err), http.StatusBadRequest)
			return
		}
		expiresIn = d
	}

	result, err := s.tokens.Create(&tokens.CreateRequest{
		Name:      name,
		RoleID:    roleID,
		ExpiresIn: expiresIn,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Re-fetch list for rendering
	toks, err := s.tokens.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	connList, err := s.connections.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pols, err := s.policies.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rolesList, err := s.roles.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"Active":         "tokens",
		"Tokens":         toks,
		"Connections":    connList,
		"Policies":       pols,
		"Roles":          rolesList,
		"PlaintextToken": result.PlaintextToken,
		"CreatedToken":   result.Token,
	}
	s.render(w, "tokens", data)
}

func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.tokens.Revoke(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

// --- Roles handlers ---

func (s *Server) handleRoles(w http.ResponseWriter, r *http.Request) {
	rolesList, err := s.roles.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	conns, err := s.connections.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pols, err := s.policies.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"Active":      "roles",
		"Roles":       rolesList,
		"Connections": conns,
		"Policies":    pols,
	}
	s.render(w, "roles", data)
}

func (s *Server) handleRoleCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	// Parse bindings from form. Each binding is a connection + policy IDs pair.
	bindingsJSON := r.FormValue("bindings")
	var bindings []roles.Binding
	if bindingsJSON != "" {
		if err := json.Unmarshal([]byte(bindingsJSON), &bindings); err != nil {
			http.Error(w, "invalid bindings JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	if _, err := s.roles.Create(name, bindings); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/roles", http.StatusSeeOther)
}

func (s *Server) handleRoleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.roles.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/roles", http.StatusSeeOther)
}

func (s *Server) handleRoleEdit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	role, err := s.roles.Get(id)
	if err != nil {
		http.Error(w, "role not found", http.StatusNotFound)
		return
	}

	conns, err := s.connections.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pols, err := s.policies.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"Active":      "roles",
		"Role":        role,
		"Connections": conns,
		"Policies":    pols,
	}
	s.render(w, "role_edit", data)
}

func (s *Server) handleRoleUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	bindingsJSON := r.FormValue("bindings")
	var bindings []roles.Binding
	if bindingsJSON != "" {
		if err := json.Unmarshal([]byte(bindingsJSON), &bindings); err != nil {
			http.Error(w, "invalid bindings JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	if err := s.roles.Update(id, name, bindings); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/roles", http.StatusSeeOther)
}

// --- Policies handlers ---

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	allPols, err := s.policies.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// The ?scope= parameter determines which connector's operations to show
	// in the rule builder. Policies are filtered to only show those matching
	// the current scope.
	scope := r.URL.Query().Get("scope")
	active := "policies"
	if scope != "" {
		active = "policies-" + scope
	}

	// Filter policies by scope. A policy's scope is stored in its config.
	// Policies without a scope (legacy/presets) show under all tabs.
	var pols []policies.Policy
	for _, p := range allPols {
		pScope, _ := p.PolicyConfig["scope"].(string)
		if scope == "" || pScope == "" || pScope == scope {
			pols = append(pols, p)
		}
	}

	data := map[string]any{
		"Active":   active,
		"Policies": pols,
		"Scope":    scope,
	}
	s.render(w, "policies", data)
}

func (s *Server) handlePolicyCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	policyType := r.FormValue("policy_type")
	configJSON := r.FormValue("policy_config")

	if name == "" || policyType == "" {
		http.Error(w, "name and policy_type are required", http.StatusBadRequest)
		return
	}

	var policyConfig map[string]any
	if configJSON != "" {
		if err := json.Unmarshal([]byte(configJSON), &policyConfig); err != nil {
			http.Error(w, "invalid policy config JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		policyConfig = make(map[string]any)
	}

	if _, err := s.policies.Create(name, policyType, policyConfig); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/policies", http.StatusSeeOther)
}

func (s *Server) handlePolicyEdit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	pol, err := s.policies.Get(id)
	if err != nil {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}

	// Detect scope from the policy config if stored, otherwise default to gmail.
	scope := "gmail"
	if s, ok := pol.PolicyConfig["scope"].(string); ok && s != "" {
		scope = s
	}

	data := map[string]any{
		"Active": "policies-" + scope,
		"Policy": pol,
		"Scope":  scope,
	}
	s.render(w, "policy_edit", data)
}

func (s *Server) handlePolicyUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	policyType := r.FormValue("policy_type")
	configJSON := r.FormValue("policy_config")

	if name == "" || policyType == "" {
		http.Error(w, "name and policy_type are required", http.StatusBadRequest)
		return
	}

	var policyConfig map[string]any
	if configJSON != "" {
		if err := json.Unmarshal([]byte(configJSON), &policyConfig); err != nil {
			http.Error(w, "invalid policy config JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		policyConfig = make(map[string]any)
	}

	if err := s.policies.Update(id, name, policyType, policyConfig); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/policies", http.StatusSeeOther)
}

func (s *Server) handlePolicyDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.policies.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/policies", http.StatusSeeOther)
}

// --- Approvals handlers ---

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	items, err := s.approval.ListPending()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"Active":    "approvals",
		"Approvals": items,
	}
	s.render(w, "approvals", data)
}

// rejectIfAgentToken checks whether the request carries an Authorization header
// with a Sieve bearer token. Agents communicate via the MCP API port using
// bearer tokens; the web UI is intended for human operators only. Rejecting
// requests that carry a Sieve token prevents an agent from approving its own
// pending operations by hitting the web UI endpoint directly.
// NOTE: The web UI port (19816) should NOT be exposed to agents.
func rejectIfAgentToken(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer sieve_tok_") {
		http.Error(w, "approval endpoints are not accessible to agents", http.StatusForbidden)
		return true
	}
	return false
}

func (s *Server) handleApprovalApprove(w http.ResponseWriter, r *http.Request) {
	if rejectIfAgentToken(w, r) {
		return
	}
	id := r.PathValue("id")

	// Check if this is a policy proposal — if so, create the policy on approval.
	// If Get fails, it's fine — we just treat it as a normal (non-proposal) approval.
	item, getErr := s.approval.Get(id)
	if getErr == nil && item.Operation == "propose_policy" {
		if err := s.approval.Approve(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Create the policy from the proposal
		data := item.RequestData
		name, _ := data["name"].(string)
		rules, _ := data["rules"].([]any)
		defaultAction, _ := data["default_action"].(string)
		if defaultAction == "" {
			defaultAction = "deny"
		}
		config := map[string]any{
			"rules":          rules,
			"default_action": defaultAction,
		}
		if _, err := s.policies.Create(name, "rules", config); err != nil {
			http.Error(w, "failed to create policy: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/approvals", http.StatusSeeOther)
		return
	}

	if err := s.approval.Approve(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/approvals", http.StatusSeeOther)
}

func (s *Server) handleApprovalReject(w http.ResponseWriter, r *http.Request) {
	if rejectIfAgentToken(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.approval.Reject(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/approvals", http.StatusSeeOther)
}

// --- Audit handlers ---

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	filter := &audit.ListFilter{
		TokenID:      r.URL.Query().Get("token_id"),
		ConnectionID: r.URL.Query().Get("connection_id"),
		Operation:    r.URL.Query().Get("operation"),
		Limit:        50,
	}

	if afterStr := r.URL.Query().Get("after"); afterStr != "" {
		t, err := time.Parse("2006-01-02", afterStr)
		if err == nil {
			filter.After = &t
		}
	}
	if beforeStr := r.URL.Query().Get("before"); beforeStr != "" {
		t, err := time.Parse("2006-01-02", beforeStr)
		if err == nil {
			filter.Before = &t
		}
	}

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	filter.Offset = (page - 1) * filter.Limit

	entries, err := s.audit.List(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	total, err := s.audit.Count(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"Active":       "audit",
		"Entries":      entries,
		"Page":         page,
		"TotalPages":   (total + filter.Limit - 1) / filter.Limit,
		"Total":        total,
		"TokenID":      filter.TokenID,
		"ConnectionID": filter.ConnectionID,
		"Operation":    filter.Operation,
		"After":        r.URL.Query().Get("after"),
		"Before":       r.URL.Query().Get("before"),
	}
	s.render(w, "audit", data)
}

// --- Settings handlers ---

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	allConns, err := s.connections.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Only show LLM-capable connections. We check the stored config for
	// a "category" field (set by the LLM provider cards in the connections UI)
	// or fall back to checking the target_url for known LLM provider domains.
	var llmConns []connections.Connection
	llmDomains := []string{"anthropic.com", "openai.com", "googleapis.com", "bedrock"}
	for _, c := range allConns {
		if c.ConnectorType == "google" {
			continue
		}
		// Check if this connection has config indicating it's an LLM provider.
		full, err := s.connections.GetWithConfig(c.ID)
		if err != nil {
			continue
		}
		targetURL, _ := full.Config["target_url"].(string)
		category, _ := full.Config["category"].(string)
		if category == "llm" {
			llmConns = append(llmConns, c)
			continue
		}
		for _, domain := range llmDomains {
			if strings.Contains(targetURL, domain) {
				llmConns = append(llmConns, c)
				break
			}
		}
	}

	allSettings, err := s.settings.GetAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	maxTokens := allSettings[settings.KeyLLMMaxTokens]
	if maxTokens == "" {
		maxTokens = "4096"
	}

	data := map[string]any{
		"Active":        "settings",
		"Connections":   llmConns,
		"LLMConnection": allSettings[settings.KeyLLMConnection],
		"LLMModel":      allSettings[settings.KeyLLMModel],
		"LLMMaxTokens":  maxTokens,
		"Success":       r.URL.Query().Get("saved") == "1",
	}
	s.render(w, "settings", data)
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	pairs := map[string]string{
		settings.KeyLLMConnection: r.FormValue("llm_connection"),
		settings.KeyLLMModel:     r.FormValue("llm_model"),
		settings.KeyLLMMaxTokens: r.FormValue("llm_max_tokens"),
	}

	for k, v := range pairs {
		if err := s.settings.Set(k, v); err != nil {
			http.Error(w, fmt.Sprintf("failed to save %s: %v", k, err), http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

// --- Script generation API handler ---

func (s *Server) handleGenerateScript(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Description string `json:"description"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Description == "" {
		http.Error(w, "description is required", http.StatusBadRequest)
		return
	}
	if req.Scope == "" {
		req.Scope = "gmail"
	}

	result, err := s.scriptgen.Generate(r.Context(), &scriptgen.GenerateRequest{
		Description: req.Description,
		Scope:       req.Scope,
	})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"script":      result.Script,
		"explanation": result.Explanation,
	})
}

func (s *Server) handleSaveScript(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Filename string `json:"filename"`
		Content  string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Filename == "" || req.Content == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "filename and content required"})
		return
	}

	// Sanitize filename — only allow alphanumeric, underscore, hyphen, dot.
	safe := ""
	for _, c := range req.Filename {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
			safe += string(c)
		}
	}
	if safe == "" {
		safe = "generated_policy.py"
	}
	if !strings.HasSuffix(safe, ".py") {
		safe += ".py"
	}

	path := "policies/" + safe

	// Ensure the policies directory exists.
	os.MkdirAll("policies", 0755)

	if err := os.WriteFile(path, []byte(req.Content), 0644); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"path": "./" + path})
}

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	// Read the markdown file from the docs directory.
	content, err := os.ReadFile(fmt.Sprintf("docs/%s.md", name))
	if err != nil {
		http.Error(w, "doc not found", http.StatusNotFound)
		return
	}

	// Serve as a simple styled page with a markdown renderer.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Sieve - %s</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Inter', sans-serif; }
    .prose pre { background: #1e293b; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }
    .prose code { color: #e2e8f0; font-size: 0.875rem; }
    .prose p code { background: #334155; padding: 0.125rem 0.375rem; border-radius: 0.25rem; }
    .prose table { width: 100%%; border-collapse: collapse; }
    .prose th, .prose td { border: 1px solid #334155; padding: 0.5rem; text-align: left; }
    .prose th { background: #1e293b; }
    .prose a { color: #818cf8; }
    .prose h1 { font-size: 1.5rem; font-weight: 700; margin-top: 2rem; }
    .prose h2 { font-size: 1.25rem; font-weight: 600; margin-top: 1.5rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }
    .prose h3 { font-size: 1.1rem; font-weight: 600; margin-top: 1rem; }
  </style>
</head>
<body class="bg-slate-900 text-slate-200 min-h-screen p-8">
  <div class="max-w-4xl mx-auto">
    <a href="/tokens" class="text-indigo-400 hover:text-indigo-300 text-sm">&larr; Back to tokens</a>
    <div id="content" class="prose prose-invert mt-4"></div>
  </div>
  <script>
    const md = %s;
    document.getElementById('content').innerHTML = marked.parse(md);
  </script>
</body>
</html>`, name, string(mustJSON(string(content))))
}

func mustJSON(s string) []byte {
	b, _ := json.Marshal(s)
	return b
}
