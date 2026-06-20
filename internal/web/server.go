// Package web implements the Sieve admin web UI, served on a separate port
// from the API/MCP server. This separation is intentional: the web UI is for
// human operators only and must not be accessible to AI agents.
// Key security patterns:
// - requireOperatorSession (auth.go): every admin endpoint is wrapped by
// this middleware via adminAuthWrapper. A request without a valid
// operator-session cookie is rejected (401 for a browser; 403 when the
// request carries a Sieve bearer token, so a compromised agent that
// discovers an admin URL cannot self-approve its own pending operations
// by calling it directly). The two-port split (19816 admin / 19817 agent)
// is the structural defense; this middleware is defense-in-depth.
// - OAuth flow with pendingOAuth: When adding a Google account connection, the
// connection is NOT saved to the database until OAuth completes successfully.
// The pendingOAuth map holds the connection metadata (ID, type, display name)
// keyed by a random state parameter. After Google redirects back with a
// valid code, we exchange it for tokens, verify the email address, and only
// THEN persist the connection. This prevents orphaned connections with
// no credentials. The state parameter has a 10-minute expiry to limit the
// window for CSRF-style attacks.
// - State parameter: The OAuth state ties the callback to a specific
// pending connection. It's a 16-byte random hex string, checked and consumed
// atomically in handleOAuthCallback. This prevents both CSRF and replay attacks.
package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trilitech/Sieve/internal/approval"
	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/httpguard"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/operator"
	"github.com/trilitech/Sieve/internal/policies"
	"github.com/trilitech/Sieve/internal/policy"
	"github.com/trilitech/Sieve/internal/ratelimit"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/secrets"
	"github.com/trilitech/Sieve/internal/session"
	"github.com/trilitech/Sieve/internal/settings"
	"github.com/trilitech/Sieve/internal/tokens"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	googleapi "google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

//go:embed templates/*
var templateFS embed.FS

// llmModelsHealthClient is the shared *http.Client used by the
// admin /api/models health check, which fetches /v1/models from an
// operator-configured LLM provider target_url. The target_url is an
// attacker-influenceable field — without httpguard, pointing it at
// 169.254.169.254 would let an admin-side feature exfiltrate cloud
// IMDS credentials. Loopback is allowed (matches the LLM evaluator's
// rationale: Ollama dev installs are on localhost); AbsoluteDeny still
// blocks IMDS.
var llmModelsHealthClient = httpguard.Client(httpguard.ClientOptions{
	Allowlist: mustParseCIDRs([]string{"127.0.0.0/8", "::1/128"}),
	Timeout:   10 * time.Second,
})

func mustParseCIDRs(cidrs []string) []netip.Prefix {
	p, err := httpguard.ParseCIDRs(cidrs)
	if err != nil {
		panic(fmt.Sprintf("web: bad allowlist CIDR: %v", err))
	}
	return p
}

// Server is the web UI server for the Sieve admin interface.
type Server struct {
	tokens                *tokens.Service
	connections           *connections.Service
	policies              *policies.Service
	roles                 *roles.Service
	registry              *connector.Registry
	approval              *approval.Queue
	audit                 *audit.Logger
	settings              *settings.Service
	scriptgen             *scriptgen.Service
	keyring               *secrets.Keyring
	db                    *database.DB
	webAddr               string // host:port the admin UI listens on (Origin allow-list)
	templates             map[string]*template.Template
	googleCredentialsFile string

	oauthMu      sync.Mutex
	oauthPending map[string]pendingOAuth // state -> pending connection info

	githubApp *gitHubAppState // pending GitHub App manifest installs

	// Passphrase-rotation lockout state (per-process). Wired into
	// handleRotatePassphrase. The zero values mean "no failures
	// recorded, not locked".
	rotateMu        sync.Mutex
	rotateFailures  int       // consecutive wrong-current-passphrase count
	rotateLockedTil time.Time // zero = not locked; otherwise = cooldown end

	stopCleanup     chan struct{} // closed by Close() to stop the cleanup goroutine
	stopCleanupOnce sync.Once     // ensures Close() is safe under concurrent calls

	// Operator + session services for the admin-authentication path.
	// Populated by SetAuth; nil when running in tests/dev that don't
	// need the auth gate. When non-nil, requireOperatorSession middleware
	// enforces session + CSRF on every wrapped endpoint.
	operatorSvc *operator.Service
	sessionMgr  *session.Manager

	// loginLimiter throttles POST /login and POST /setup per client IP.
	// Without it, argon2's ~150-300 ms cost is the only brake on an
	// online credential guess — not nearly enough to stop a determined
	// attacker. Populated by SetLoginRateLimiter; when nil, /login and
	// /setup are not throttled (tests, dev).
	loginLimiter *ratelimit.Limiter

	// IAM engine wiring for the /iam admin page. All three are populated
	// together by SetIAM; nil when SetIAM was never called (the /iam routes
	// are still registered but render "IAM not configured"). iam is the
	// Cedar-policy + decision store; iamRegistry is threaded into
	// iam.Decide for operation-taxonomy lookups; iamSettings backs the
	// iam_enabled toggle. settings already exists on the Server, but IAM
	// keeps its own reference so the wiring mirrors api/router + mcp/server
	// (SetIAM(iamSvc, registry, settingsSvc)) exactly.
	iam         *iampolicies.Service
	iamRegistry *connector.Registry
	iamSettings *settings.Service
}

// funcMap returns the template function map used across all templates.
func funcMap() template.FuncMap {
	return template.FuncMap{
		// json marshals v to a JSON string with aggressive escaping
		// suitable for embedding inside <script type="application/json">
		// blocks. Returns a plain string (NOT template.JS) so Go's
		// html/template auto-escaper treats the result as text content,
		// not as already-safe JavaScript — the latter is the wrong
		// shape for serialised user-controlled data. Callers MUST embed
		// the result inside <script type="application/json" id="...">
		// and read it from the browser side via
		// JSON.parse(scriptEl.textContent).
		"json": func(v any) string {
			b, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return fmt.Sprintf("null /* error: %v */", err)
			}
			// json.MarshalIndent already escapes <, >, & (SetEscapeHTML
			// default). Belt-and-suspenders: also escape "/" so a
			// closing </script> inside a string value cannot terminate
			// the surrounding script element, and U+2028 / U+2029 which
			// break some JSON.parse paths.
			out := string(b)
			out = strings.ReplaceAll(out, "</", "<\\/")
			out = strings.ReplaceAll(out, "\u2028", "\\u2028")
			out = strings.ReplaceAll(out, "\u2029", "\\u2029")
			return out
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
		"isExpired": func(t *time.Time) bool {
			if t == nil {
				return false
			}
			return time.Now().After(*t)
		},
		"timeUntil": func(t time.Time) string {
			d := time.Until(t)
			if d < 0 {
				// Already past — show "ago" format.
				d = -d
				switch {
				case d < time.Minute:
					return "just expired"
				case d < time.Hour:
					return fmt.Sprintf("%dm ago", int(d.Minutes()))
				case d < 24*time.Hour:
					return fmt.Sprintf("%dh ago", int(d.Hours()))
				default:
					return fmt.Sprintf("%dd ago", int(d.Hours()/24))
				}
			}
			switch {
			case d < time.Minute:
				return "in <1m"
			case d < time.Hour:
				return fmt.Sprintf("in %dm", int(d.Minutes()))
			case d < 24*time.Hour:
				return fmt.Sprintf("in %dh", int(d.Hours()))
			case d < 30*24*time.Hour:
				return fmt.Sprintf("in %dd", int(d.Hours()/24))
			default:
				return fmt.Sprintf("in %dmo", int(d.Hours()/(24*30)))
			}
		},
	}
}

// NewServer creates a new web UI server. It starts a background goroutine for
// OAuth cleanup; callers MUST call (*Server).Close when the server is no
// longer needed (e.g. via defer or t.Cleanup) to stop the goroutine.
// keyring, db, and webAddr are required by the passphrase-rotation handler
// (POST /settings/rotate-passphrase). keyring drives the actual rotation;
// db is the SQL handle threaded into Keyring.Rotate; webAddr is the
// allow-list value for the rotation form's Origin/Referer CSRF check.
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
	keyring *secrets.Keyring,
	db *database.DB,
	webAddr string,
) *Server {
	s := &Server{
		tokens:                tokensSvc,
		connections:           connsSvc,
		policies:              policiesSvc,
		roles:                 rolesSvc,
		registry:              registry,
		approval:              approvalQ,
		audit:                 auditLog,
		settings:              settingsSvc,
		scriptgen:             scriptgenSvc,
		keyring:               keyring,
		db:                    db,
		webAddr:               webAddr,
		templates:             make(map[string]*template.Template),
		googleCredentialsFile: googleCredentialsFile,
		oauthPending:          make(map[string]pendingOAuth),
		githubApp:             newGitHubAppState(),
		stopCleanup:           make(chan struct{}),
	}

	// Parse each page template together with the nav + ops-picker partials.
	// Partials added here are loaded for EVERY page; pages that don't use a
	// given partial just ignore it. The ops picker partial is included so
	// policies.html and policy_edit.html resolve to the same scope-aware
	// markup — making create/edit divergence structurally impossible.
	pages := []string{"connections", "connection_edit", "tokens", "approvals", "audit", "policies", "policy_edit", "settings", "roles", "role_edit", "iam", "docs"}
	for _, page := range pages {
		t := template.Must(
			template.New("").Funcs(funcMap()).ParseFS(templateFS,
				"templates/nav.html",
				"templates/policy_ops_picker.html",
				"templates/connection_edit_field.html",
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

// SetAuth wires the operator + session services that drive the
// admin-authentication path.
// Call this after NewServer to enable login / logout / setup
// handlers and the requireOperatorSession middleware. When nil
// values are passed (or SetAuth is never called) the auth surface
// is disabled — existing dev/test flows that don't yet seed an
// operator stay functional.
// Production wiring lives in cmd/sieve/main.go.
func (s *Server) SetAuth(op *operator.Service, sess *session.Manager) {
	s.operatorSvc = op
	s.sessionMgr = sess
}

// SetLoginRateLimiter wires the per-IP rate limiter that gates
// POST /login and POST /setup. Pass nil to disable throttling
// (default; tests and dev only). The agent listener has its own
// rate limiter wired separately in cmd/sieve/main.go.
func (s *Server) SetLoginRateLimiter(rl *ratelimit.Limiter) {
	s.loginLimiter = rl
}

// SetIAM wires the IAM engine services that drive the /iam admin page.
// Call this after NewServer to enable the IAM policy list / create /
// delete, the iam_enabled toggle, and the decision explorer. When nil
// values are passed (or SetIAM is never called) the /iam routes stay
// registered but render an "IAM not configured" notice. The signature
// mirrors Router.SetIAM / mcp.Server.SetIAM so the same call site shape
// (SetIAM(iamSvc, registry, settingsSvc)) works for all three surfaces.
// Production wiring lives in cmd/sieve/main.go; the e2e testserver wires
// it too.
func (s *Server) SetIAM(iamSvc *iampolicies.Service, registry *connector.Registry, settingsSvc *settings.Service) {
	s.iam = iamSvc
	s.iamRegistry = registry
	s.iamSettings = settingsSvc
}

// Handler returns the HTTP handler with all routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Dashboard redirect
	// --- Operator authentication routes.
	// These routes are intentionally public: login itself can't require
	// a session, and setup is one-shot for fresh installs. Every OTHER
	// admin route is wrapped with requireOperatorSession via
	// adminAuthWrapper below.
	mux.HandleFunc("GET /login", s.handleLoginGet)
	mux.HandleFunc("POST /login", s.handleLoginPost)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /setup", s.handleSetupGet)
	mux.HandleFunc("POST /setup", s.handleSetupPost)

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/connections", http.StatusFound)
	})

	// Connections
	mux.HandleFunc("GET /connections", s.handleConnections)
	mux.HandleFunc("POST /connections/add", s.handleConnectionAdd)
	mux.HandleFunc("POST /connections/{id}/delete", s.handleConnectionDelete)
	mux.HandleFunc("POST /connections/{id}/reauth", s.handleConnectionReauth)
	mux.HandleFunc("GET /connections/{id}/edit", s.handleConnectionEditPage)
	mux.HandleFunc("POST /connections/{id}/edit", s.handleConnectionEditSave)
	mux.HandleFunc("POST /connections/{id}/disable", s.handleConnectionDisable)
	mux.HandleFunc("POST /connections/{id}/enable", s.handleConnectionEnable)
	mux.HandleFunc("GET /oauth/callback", s.handleOAuthCallback)

	// GitHub-specific setup flows
	mux.HandleFunc("POST /connections/github/pat", s.handleGitHubPAT)
	// Slack connector flows.
	mux.HandleFunc("POST /connections/slack/oauth/configure", s.handleSlackOAuthConfigure)
	mux.HandleFunc("POST /connections/slack/oauth/clear", s.handleSlackOAuthClearConfig)
	mux.HandleFunc("POST /connections/slack/oauth/start", s.handleSlackOAuthStart)
	mux.HandleFunc("POST /connections/slack/token", s.handleSlackToken)
	mux.HandleFunc("POST /connections/slack/{id}/reauth", s.handleSlackReauth)
	mux.HandleFunc("POST /connections/github/app/start", s.handleGitHubAppStart)
	mux.HandleFunc("GET /connections/github/app/created", s.handleGitHubAppCreated)
	mux.HandleFunc("GET /connections/github/app/installed", s.handleGitHubAppInstalled)

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
	mux.HandleFunc("POST /settings/rotate-passphrase", s.handleRotatePassphrase)

	// IAM (Cedar engine admin surface). Operator-authenticated like every
	// other admin page: these paths are NOT in authExemptPaths, so the
	// requireOperatorSession middleware gates them (session cookie + CSRF
	// on the POSTs) and rejects agent tokens with 403. See iam.go.
	mux.HandleFunc("GET /iam", s.handleIAM)
	mux.HandleFunc("POST /iam/roles", s.handleIAMRoleCreate)
	mux.HandleFunc("POST /iam/policies", s.handleIAMPolicyCreate)
	mux.HandleFunc("POST /iam/policies/{id}/delete", s.handleIAMPolicyDelete)
	mux.HandleFunc("POST /iam/filters", s.handleIAMFilterCreate)
	mux.HandleFunc("POST /iam/filters/{name}/delete", s.handleIAMFilterDelete)
	mux.HandleFunc("POST /iam/toggle", s.handleIAMToggle)
	mux.HandleFunc("POST /iam/explore", s.handleIAMExplore)

	// Script generation API
	mux.HandleFunc("POST /api/generate-script", s.handleGenerateScript)
	mux.HandleFunc("POST /api/save-script", s.handleSaveScript)

	// Model discovery API
	mux.HandleFunc("GET /api/models", s.handleListModels)

	// Docs
	mux.HandleFunc("GET /docs", s.handleDocsIndex)
	mux.HandleFunc("GET /docs/", s.handleDocsIndex)
	mux.HandleFunc("GET /docs/category/{id}", s.handleDocsCategory)
	mux.HandleFunc("GET /docs/{name}", s.handleDocs)

	// Wrap the admin mux with two layers:
	//   1. adminAuthWrapper — routes through requireOperatorSession
	//      (session cookie + CSRF token gate) for every non-exempt path;
	//      exempt paths are login/setup/OAuth-callback/docs.
	//   2. noCacheAllAdmin — sensitive-response header writer that
	//      stamps Cache-Control: no-store etc. on every admin response.
	// Header wrapping is OUTERMOST so 401/403/redirect responses
	// produced by the auth gate also carry the headers.
	return noCacheAllAdmin(s.adminAuthWrapper(mux))
}

// authExemptPaths is the set of admin paths that bypass the
// requireOperatorSession middleware. Login + setup are bootstrap;
// OAuth callbacks identify the operator via the OAuth state parameter
// + a session-hash check inside the handler rather than a Sieve
// session cookie surfacing at the middleware layer.
var authExemptPaths = map[string]bool{
	"/login":                            true,
	"/setup":                            true,
	"/logout":                           true, // session needed, but CSRF gate skipped — see authExemptCSRF
	"/oauth/callback":                   true,
	"/connections/github/app/created":   true,
	"/connections/github/app/installed": true,
}

// authExemptPrefixes is the set of path prefixes that bypass auth
// entirely — currently just the bundled documentation. Operators
// reading docs without logging in is a feature.
var authExemptPrefixes = []string{
	"/docs",
}

// authExemptCSRF is the set of paths that need a session but skip
// the CSRF check. Logout is the only case: it's a recoverable
// destructive action and a CSRF attacker forcing a logout costs
// the operator a re-login at worst.
var authExemptCSRF = map[string]bool{
	"/logout": true,
}

// adminAuthWrapper routes admin requests through requireOperatorSession
// unless the path is exempt. Exempt paths are served directly by the
// wrapped mux (no session lookup, no CSRF check). The middleware
// itself short-circuits to pass-through when SetAuth was never
// called (transitional; tests that don't yet seed an operator stay
// functional).
func (s *Server) adminAuthWrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if authExemptPaths[path] {
			// Logout still needs a session lookup so we know whose to
			// delete; the middleware no-ops the CSRF check via
			// authExemptCSRF.
			if path == "/logout" {
				s.requireOperatorSessionExceptCSRF(next).ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		for _, prefix := range authExemptPrefixes {
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				next.ServeHTTP(w, r)
				return
			}
		}
		s.requireOperatorSession(next).ServeHTTP(w, r)
	})
}

// injectCSRFToken sets data["CSRFToken"] (for maps) or data.CSRFToken
// (for structs that declare the field) when the value is currently
// unset/zero. Used by render() to surface the token to nav.html.
// Reflection is fine here — admin renders are not on a hot path. The
// caller passes "" when no session is present; we still need to set
// the key so the template renders a valid JS string literal rather
// than the bare `;` that an absent map key produces inside
// `{{.CSRFToken}}`.
func injectCSRFToken(data any, token string) {
	if m, ok := data.(map[string]any); ok {
		if _, present := m["CSRFToken"]; !present {
			m["CSRFToken"] = token
		}
		return
	}
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return
	}
	f := v.FieldByName("CSRFToken")
	if !f.IsValid() || !f.CanSet() || f.Kind() != reflect.String {
		return
	}
	if f.String() == "" && token != "" {
		f.SetString(token)
	}
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data any) {
	t, ok := s.templates[page]
	if !ok {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	// Inject the plaintext CSRF token into the template data so
	// nav.html (included on every admin page) can expose it to the
	// page script that injects `csrf_token` hidden inputs into every
	// POST form on submit. Two shapes are supported:
	//   - map[string]any: set m["CSRFToken"] when missing.
	//   - struct (or *struct) with a settable CSRFToken string field:
	//     set via reflection when zero. Typed view-models like
	//     connectionEditData declare the field so the same nav.html
	//     access works uniformly.
	// Always set the key — even to "" when the session is missing the
	// CSRF cookie (older session, lost cookie). nav.html writes the
	// value as `window.SIEVE_CSRF = {{.CSRFToken}};` and relies on
	// html/template's JS-context escaping to emit a valid quoted
	// string (or `""` when the value is empty). Leaving the key
	// absent from the data map would produce invalid JS (`= ;`) and
	// break every script on the page. The empty-string case is
	// harmless: the form-submit handler and fetch wrapper both skip
	// injecting when SIEVE_CSRF is falsy, and the middleware fails
	// closed at the next POST anyway.
	var token string
	if sess := sessionFromContext(r); sess != nil {
		token = sess.CSRFToken
	}
	injectCSRFToken(data, token)
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
			} else if connType == "version_control" {
				// "version_control" tab groups github + gitlab.
				// Match the immutable ConnectorType directly so an
				// http_proxy that happens to carry config.category =
				// "github" / "gitlab" (a legitimate generic-LLM /
				// generic-proxy override) does NOT slip into the VCS
				// filter. `cat` reflects the http_proxy override and
				// would do that here; ConnectorType cannot be forged.
				if c.ConnectorType == "github" || c.ConnectorType == "gitlab" {
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
				// "version_control" tab shows both github and gitlab connectors
				if connType == "version_control" {
					match = m.Type == "github" || m.Type == "gitlab"
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

	// Build display labels for connection types. LLM connections show
	// their provider name instead of generic "http_proxy".
	connLabels := make(map[string]string)
	for _, c := range conns {
		label := c.ConnectorType
		if label == "http_proxy" || label == "mcp_proxy" {
			if full, err := s.connections.GetWithConfig(c.ID); err == nil {
				if cat, ok := full.Config["category"].(string); ok {
					switch cat {
					case "llm":
						label = "LLM API"
						// Try to detect specific provider from target_url.
						if target, ok := full.Config["target_url"].(string); ok {
							switch {
							case strings.Contains(target, "anthropic"):
								label = "Anthropic"
							case strings.Contains(target, "openai.com"):
								label = "OpenAI"
							case strings.Contains(target, "googleapis.com"):
								label = "Gemini"
							case strings.Contains(target, "bedrock"):
								label = "Bedrock"
							}
						}
					case "cloud":
						label = "Cloud"
						if target, ok := full.Config["target_url"].(string); ok {
							if strings.Contains(target, "hyperstack") {
								label = "Hyperstack"
							} else {
								label = "AWS"
							}
						}
					}
				}
				if label == "http_proxy" {
					label = "HTTP Proxy"
				}
			}
		}
		if label == "mcp_proxy" {
			label = "MCP Proxy"
		}
		connLabels[c.ID] = label
	}

	data := map[string]any{
		"Active":      active,
		"Connections": conns,
		"ConnLabels":  connLabels,
		"Catalog":     catalog,
		"ConnType":    connType,
		// Per-connector UI capability flags. Slack OAuth requires
		// operator-supplied client credentials. The UI shows different
		// content depending on whether they're configured: the install
		// button when set, the configure-form when not. Same lookup
		// chain (settings → env) the install handler uses, so the
		// flag and runtime behavior never diverge.
		"SlackOAuthConfigured": s.slackOAuthIsConfigured(),
	}
	s.render(w, r, "connections", data)
}

// pendingOAuth holds info for a connection being added via OAuth.
// IsReauth distinguishes a fresh-add flow (insert a new connection record on
// success) from a re-authentication of an existing connection (update the
// existing record's config and clear needs_reauth). The handler picks one or
// the other based on this flag — keeping it explicit avoids accidentally
// overwriting an existing connection during a normal Add, or duplicating one
// during a Re-auth.
// OperatorSessionHash binds the OAuth state to the operator session that
// initiated /start. The callback (which is in authExemptPaths because the
// upstream provider doesn't carry our cookie back) re-derives the hash
// from the cookie presented by the browser and refuses the callback if it
// differs. Closes a state-confusion attack where someone who can reach
// /start (pre-auth attacker) races a legitimate operator's callback.
type pendingOAuth struct {
	ID                  string
	ConnectorType       string
	DisplayName         string
	CreatedAt           time.Time
	IsReauth            bool
	OperatorSessionHash string // hex(sha256(cookie value)); empty when no session was active
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

	// Generic save path. The connector's declared SetupFields drive
	// which form values get pulled into the config map — there's no
	// per-connector switch here. Bespoke flows (Slack install, Google
	// OAuth) intercept BEFORE this point.
	if meta, ok := s.registry.Meta(connectorType); ok && !connectorRequiresBespokeAdd(connectorType) {
		config := map[string]any{}
		if msg := applyConnectorFormFields(meta, formModeCreate, r, config); msg != "" {
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		if err := s.connections.Add(id, connectorType, displayName, config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = s.audit.LogOperator(operatorDisplayName(r, s), "connection.add", id,
			map[string]any{"connector_type": connectorType, "display_name": displayName},
			"success")
		http.Redirect(w, r, "/connections", http.StatusSeeOther)
		return
	}

	// Slack must use the dedicated /connections/slack/{oauth/start,token,...}
	// routes which validate against Slack before persisting. Falling
	// through to the generic "save directly" branch below would store a
	// connection with empty config — the row would appear in the UI but
	// every operation would fail because the live connector can't be
	// instantiated without auth_kind set.
	if connectorType == "slack" {
		http.Error(w,
			"Slack connections must be added via the Slack-specific install flow "+
				"(POST /connections/slack/oauth/start or /connections/slack/token). "+
				"The generic add endpoint cannot validate Slack credentials.",
			http.StatusBadRequest)
		return
	}

	// GitHub is similar to Slack: credentials are installed via dedicated
	// /connections/github/{pat,app/start,...} endpoints that validate
	// against GitHub before persisting. Falling through to the empty-config
	// save below would leave a row with no credentials — every operation
	// would fail because parseConfig requires at least one credential.
	if connectorType == "github" {
		http.Error(w,
			"GitHub connections must be added via the GitHub-specific install flow "+
				"(POST /connections/github/pat or /connections/github/app/start). "+
				"The generic add endpoint cannot validate GitHub credentials.",
			http.StatusBadRequest)
		return
	}

	// For OAuth connectors (gmail), don't save the connection yet. We start
	// the OAuth flow first and only persist the connection in handleOAuthCallback
	// after receiving valid credentials. This avoids orphaned connections that
	// appear in the UI but have no working credentials.
	if connectorType == "google" {
		conf, err := s.googleOAuthConfig(r)
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
		s.oauthPending[state] = pendingOAuth{
			ID:                  id,
			ConnectorType:       connectorType,
			DisplayName:         displayName,
			CreatedAt:           time.Now(),
			OperatorSessionHash: operatorSessionHash(r),
		}
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
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "connection.add", id,
		map[string]any{"connector_type": connectorType, "display_name": displayName},
		"success")
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

func (s *Server) handleConnectionDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.connections.Remove(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "connection.delete", id, nil, "success")
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// handleConnectionReauth kicks off the OAuth flow for an existing connection
// whose refresh token has been invalidated. The flow re-uses the same Google
// OAuth start (AccessTypeOffline + ApprovalForce so we get a fresh refresh
// token, even if the user's account already grants this app). On callback,
// we'll UpdateConfig on the existing record (which atomically clears
// needs_reauth) instead of inserting a new one.
// Limited to Google connections today; GitHub PAT/App connections have their
// own setup flow and would need a separate re-auth surface if their tokens
// expire.
func (s *Server) handleConnectionReauth(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	conn, err := s.connections.Get(id)
	if err != nil {
		http.Error(w, "connection not found", http.StatusNotFound)
		return
	}
	if conn.ConnectorType != "google" {
		http.Error(w, "re-auth not supported for connector type "+conn.ConnectorType, http.StatusBadRequest)
		return
	}

	conf, err := s.googleOAuthConfig(r)
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
	s.oauthPending[state] = pendingOAuth{
		ID:                  id,
		ConnectorType:       conn.ConnectorType,
		DisplayName:         conn.DisplayName,
		CreatedAt:           time.Now(),
		IsReauth:            true,
		OperatorSessionHash: operatorSessionHash(r),
	}
	s.oauthMu.Unlock()

	_ = s.audit.LogOperator(operatorDisplayName(r, s), "connection.reauth_start", id,
		map[string]any{"connector_type": conn.ConnectorType},
		"success")

	url := conf.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusFound)
}

// handleConnectionDisable transitions a connection's status to "disabled".
// Operator-driven hard stop: agent operations will be denied with HTTP 403
// until handleConnectionEnable returns the row to "active". Differs from
// reauth_required in two ways: (1) the operator chose this state
// explicitly; (2) re-auth flows do NOT clear it — only the explicit
// Enable button does. Agent-token rejection is upstream via the
// requireOperatorSession middleware.
func (s *Server) handleConnectionDisable(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.connections.SetStatus(id, connections.StatusDisabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "connection.disable", id, nil, "success")
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// handleConnectionEnable transitions a "disabled" connection back into
// the lifecycle. The post-action status is NOT unconditionally "active":
// if the row carries a non-empty reauth_reason (the underlying credential
// was broken before the operator disabled the connection), the enable
// action transitions to "reauth_required" instead of "active" so the
// connection never serves agent traffic with known-broken credentials.
// The action itself always succeeds — only the destination state
// varies. Agent-token rejection is upstream via the
// requireOperatorSession middleware.
func (s *Server) handleConnectionEnable(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Inspect reauth_reason: a non-empty value indicates the credential
	// was broken before disable. Route the post-enable state accordingly.
	c, err := s.connections.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if c.ReauthReason != "" {
		if err := s.connections.SetStatusWithReason(id, connections.StatusReauthRequired, c.ReauthReason); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := s.connections.SetStatus(id, connections.StatusActive); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "connection.enable", id,
		map[string]any{"reauth_pending": c.ReauthReason != ""},
		"success")
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// publicBaseURL returns the externally-visible base URL Sieve uses to
// construct OAuth callback / redirect / setup / manifest URLs. Reads from
// settings.PublicBaseURL — never from inbound Host / X-Forwarded-Host /
// X-Forwarded-Proto headers, which an attacker could forge to redirect
// an OAuth flow to an attacker-controlled callback.
// The *http.Request argument is intentionally accepted (and ignored) so
// every call site reads with awareness of the forged-header threat — the
// signature carries the reminder that r.Host MUST NOT be used here.
func (s *Server) publicBaseURL(_ *http.Request) string {
	if s.settings != nil {
		if u := s.settings.PublicBaseURL(); u != "" {
			return strings.TrimRight(u, "/")
		}
	}
	return "http://127.0.0.1:19816"
}

// --- OAuth handlers ---

func (s *Server) googleOAuthConfig(r *http.Request) (*oauth2.Config, error) {
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
		"https://www.googleapis.com/auth/documents",
	}
	conf, err := google.ConfigFromJSON(data, scopes...)
	if err != nil {
		return nil, fmt.Errorf("parse credentials file: %w", err)
	}

	// Single callback URL — connection ID is carried in the state parameter.
	// Derived from settings.public_base_url. MUST NOT be built from r.Host
	// because an attacker reaching the admin listener could forge the Host
	// header and redirect the OAuth callback to an attacker-controlled
	// server.
	conf.RedirectURL = s.publicBaseURL(r) + "/oauth/callback"
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

	// State-confusion guard: the callback must come back through the same
	// operator session that initiated /start. Without this check, anyone
	// who can reach /start can pre-mint a state and claim the resulting
	// connection record by racing a legitimate operator's callback.
	if pending.OperatorSessionHash != "" {
		if !operatorSessionHashesEqual(pending.OperatorSessionHash, operatorSessionHash(r)) {
			http.Error(w, "OAuth callback rejected: session mismatch — restart the connection flow from the same browser session", http.StatusForbidden)
			return
		}
	}

	// Per-connector dispatch. Slack lands in slackOAuthExchange (web/slack.go);
	// google falls through to the existing path below.
	if pending.ConnectorType == "slack" {
		s.completeSlackOAuth(w, r, pending, code)
		return
	}

	conf, err := s.googleOAuthConfig(r)
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

	// Commit point. For a fresh add, INSERT; for a re-auth, UPDATE the
	// existing record (which atomically clears needs_reauth in the same
	// statement). If anything above failed, no DB write happens — the user
	// retries from the connections page either way.
	if pending.IsReauth {
		// Identity guard: if the operator picked a different Google account
		// in the consent screen than the one the connection was originally
		// bound to, refuse the swap. Otherwise the display_name still says
		// e.g. "C1.org gmail" but the underlying mailbox is now the user's
		// personal account — and any policy keyed on email is silently
		// wrong. Better to abort and make them retry with the right account.
		existing, gerr := s.connections.GetWithConfig(pending.ID)
		if gerr != nil {
			http.Error(w, fmt.Sprintf("re-auth: load existing connection: %v", gerr), http.StatusInternalServerError)
			return
		}
		if err := matchesReauthIdentity(existing, profile.EmailAddress); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.connections.UpdateConfig(pending.ID, connConfig); err != nil {
			http.Error(w, fmt.Sprintf("failed to update connection: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		if err := s.connections.Add(pending.ID, pending.ConnectorType, pending.DisplayName, connConfig); err != nil {
			http.Error(w, fmt.Sprintf("failed to save connection: %v", err), http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// matchesReauthIdentity returns nil if the OAuth consent that just completed
// is for the same Google account the connection was originally bound to, or
// a descriptive error if it isn't. Comparison is case-insensitive (Google
// addresses are case-insensitive in the local part too in practice).
// The check exists because the re-auth flow uses oauth2.ApprovalForce — the
// operator is shown the Google account chooser and could pick a different
// one. Without this guard, an honest mistake silently rebinds the connection
// to a different mailbox while the display_name and bindings keep pointing
// at the old identity.
// If the existing config has no email at all (a state we don't currently
// produce, but might in tests or after a future schema change), allow the
// update — there's nothing to compare against.
func matchesReauthIdentity(existing *connections.Connection, newEmail string) error {
	existingEmail, _ := existing.Config["email"].(string)
	if existingEmail == "" {
		return nil
	}
	if !strings.EqualFold(existingEmail, newEmail) {
		return fmt.Errorf(
			"re-auth identity mismatch: connection is bound to %q but you signed in as %q. Click Re-authenticate again and pick %q in the Google account chooser. (To switch a connection to a different Google account, delete it and add it fresh.)",
			existingEmail, newEmail, existingEmail,
		)
	}
	return nil
}

// oauthPendingCleanupLoop runs until Close is called, deleting oauthPending
// entries older than 10 minutes every 5 minutes.
func (s *Server) oauthPendingCleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.sweepOAuthPending(time.Now())
			s.githubApp.sweep(time.Now())
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
	s.render(w, r, "tokens", data)
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
	// Audit producer. Plaintext token redacted by
	// audit.RedactSensitive via the LogOperator helper. Failures don't
	// block the user-visible response — best-effort persistence.
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "token.create", result.Token.ID,
		map[string]any{"name": name, "role_id": roleID}, "success")

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
	s.render(w, r, "tokens", data)
}

func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.tokens.Revoke(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "token.revoke", id, nil, "success")
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
	s.render(w, r, "roles", data)
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

	role, err := s.roles.Create(name, bindings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "role.create", role.ID,
		map[string]any{"name": name, "binding_count": len(bindings)}, "success")

	http.Redirect(w, r, "/roles", http.StatusSeeOther)
}

func (s *Server) handleRoleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.roles.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "role.delete", id, nil, "success")
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
	s.render(w, r, "role_edit", data)
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

	_ = s.audit.LogOperator(operatorDisplayName(r, s), "role.update", id,
		map[string]any{"name": name, "binding_count": len(bindings)},
		"success")
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
	// The synthetic "version_control" scope is strictly defined as
	// github + gitlab + unscoped. A policy literally stamped with
	// scope=version_control would be nonsense (creation is blocked in
	// handlePolicyCreate); excluding it here keeps the filter honest
	// against any hand-crafted DB row that slipped through, and keeps
	// the handlePolicyCreate comment accurate.
	var pols []policies.Policy
	for _, p := range allPols {
		pScope, _ := p.PolicyConfig["scope"].(string)
		var match bool
		if scope == "version_control" {
			match = pScope == "" || pScope == "github" || pScope == "gitlab"
		} else {
			match = scope == "" || pScope == "" || pScope == scope
		}
		if match {
			pols = append(pols, p)
		}
	}

	data := map[string]any{
		"Active":   active,
		"Policies": pols,
		"Scope":    scope,
	}
	s.render(w, r, "policies", data)
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

	// "version_control" is a synthetic browse-only scope used in the
	// sidebar grouping; it isn't a real connector scope. The
	// /policies?scope=version_control list-filter (handlePolicies)
	// pulls policies whose stored scope is github or gitlab (plus
	// unscoped legacies). Persisting scope=version_control on a new
	// policy would orphan it from both the github and gitlab tabs
	// while only matching the synthetic group — almost certainly an
	// accident, so refuse it loudly. The policies.html template
	// hides the create form under this scope; this server-side
	// reject is defence-in-depth against a hand-crafted POST or an
	// out-of-date browser tab.
	if sc, _ := policyConfig["scope"].(string); sc == "version_control" {
		http.Error(w, "scope \"version_control\" is a browse-only filter; pick github or gitlab for a real policy", http.StatusBadRequest)
		return
	}

	// Validate the policy rules against known operations.
	if errs := s.validatePolicyRules(policyConfig); len(errs) > 0 {
		http.Error(w, "Policy validation errors:\n"+strings.Join(errs, "\n"), http.StatusBadRequest)
		return
	}
	// Script-command allowlist enforcement : rejects top-level
	// script policies and nested rules[].script actions whose command
	// field is not on the operator-configured allowlist.
	if msg := validatePolicyCommandAllowlist(policyType, policyConfig); msg != "" {
		http.Error(w, "Policy command not allowed: "+msg, http.StatusBadRequest)
		return
	}
	// Numeric-ceiling lint : warn-once on the
	// deny + ceiling + non-deny-default composition. On create there's
	// no prior sticky ack, so any fire requires acknowledge_lint=true.
	if warn := policy.DenyCeilingLint(policyType, policyConfig); warn != nil {
		if r.FormValue("acknowledge_lint") != "true" {
			writeLintWarningResponse(w, warn)
			return
		}
	}

	pol, err := s.policies.Create(name, policyType, policyConfig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "policy.create", pol.ID,
		map[string]any{"name": name, "policy_type": policyType}, "success")
	// Store sticky acknowledgement for any lint that fired.
	if warn := policy.DenyCeilingLint(policyType, policyConfig); warn != nil {
		ack := map[string]any{
			warn.Rule: map[string]any{
				"acknowledged_at": time.Now().UTC().Format(time.RFC3339),
				"by":              operatorDisplayName(r, s),
				"fingerprint":     warn.Fingerprint,
			},
		}
		if err := s.policies.SetLintAck(pol.ID, ack); err != nil {
			// Log-and-continue: the policy is saved; the sticky ack is
			// best-effort. A future save will re-warn until ack persists.
			http.Error(w, "policy saved but lint ack failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/policies", http.StatusSeeOther)
}

// writeLintWarningResponse returns the structured lint warning to the
// caller. JSON for fetch-style callers (admin JS); fallback text/html
// 400 page for the form submission path.
func writeLintWarningResponse(w http.ResponseWriter, warn *policy.LintWarning) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	body := map[string]any{
		"error": "lint_acknowledgement_required",
		"lints": []*policy.LintWarning{warn},
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) handlePolicyEdit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	pol, err := s.policies.Get(id)
	if err != nil {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}

	// Detect scope. Preference order: explicit `scope` field > shape inference
	// from the rules > "gmail" as last-resort default. Older policies that
	// were created before the create form started persisting `scope` end up
	// with an empty value; inferring from rules keeps the edit page from
	// silently rendering the wrong connector's UI.
	scope := "gmail"
	if v, ok := pol.PolicyConfig["scope"].(string); ok && v != "" {
		scope = v
	} else if inferred := inferPolicyScope(pol.PolicyConfig); inferred != "" {
		scope = inferred
	}

	data := map[string]any{
		"Active": "policies-" + scope,
		"Policy": pol,
		"Scope":  scope,
	}
	s.render(w, r, "policy_edit", data)
}

// inferPolicyScope guesses a policy's connector scope from the shape of its
// rules. Returns "" when nothing distinctive is found (caller defaults to
// "gmail" for backwards compatibility with the legacy default).
// Signals checked, in order of specificity:
// - rule.match.method or rule.match.path → http_proxy
// - match.operations contains "proxy_request" → http_proxy
// - rule.match.providers or LLM-only fields → llm
// - match.operations contains a Drive/Calendar/etc op name → that scope
func inferPolicyScope(cfg map[string]any) string {
	rules, _ := cfg["rules"].([]any)
	for _, ri := range rules {
		r, ok := ri.(map[string]any)
		if !ok {
			continue
		}
		match, _ := r["match"].(map[string]any)
		if match == nil {
			continue
		}
		if _, ok := match["method"]; ok {
			return "http_proxy"
		}
		if _, ok := match["path"]; ok {
			return "http_proxy"
		}
		if ops, ok := match["operations"].([]any); ok {
			for _, op := range ops {
				s, _ := op.(string)
				if s == "proxy_request" {
					return "http_proxy"
				}
				switch s {
				case "list_channels", "list_users", "read_user_profile",
					"read_channel_history", "read_thread", "post_message",
					"search_messages":
					return "slack"
				}
			}
		}
		if _, ok := match["channel"]; ok {
			return "slack"
		}
		if _, ok := match["text_contains"]; ok {
			return "slack"
		}
		if _, ok := match["user"]; ok {
			return "slack"
		}
		if _, ok := match["providers"]; ok {
			return "llm"
		}
		for _, k := range []string{"model", "max_tokens", "max_cost", "extended_thinking", "system_prompt_contains", "max_temperature", "json_mode", "grounding", "safety_threshold"} {
			if _, ok := match[k]; ok {
				return "llm"
			}
		}
	}
	return ""
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

	if errs := s.validatePolicyRules(policyConfig); len(errs) > 0 {
		http.Error(w, "Policy validation errors:\n"+strings.Join(errs, "\n"), http.StatusBadRequest)
		return
	}
	// Script-command allowlist enforcement — applies on UPDATE so
	// an existing benign policy cannot be flipped to bash/sh/perl.
	if msg := validatePolicyCommandAllowlist(policyType, policyConfig); msg != "" {
		http.Error(w, "Policy command not allowed: "+msg, http.StatusBadRequest)
		return
	}
	// Numeric-ceiling lint with sticky ack. If the
	// existing policy already has an ack whose fingerprint matches the
	// current shape, the warning is silenced. Otherwise the operator
	// must re-acknowledge.
	warn := policy.DenyCeilingLint(policyType, policyConfig)
	if warn != nil {
		existing, _ := s.policies.Get(id)
		var existingAck map[string]any
		if existing != nil {
			existingAck = existing.LintAck
		}
		if !policy.StickyAcknowledgmentMatches(existingAck, warn.Rule, warn.Fingerprint) {
			if r.FormValue("acknowledge_lint") != "true" {
				writeLintWarningResponse(w, warn)
				return
			}
		}
	}

	if err := s.policies.Update(id, name, policyType, policyConfig); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "policy.update", id,
		map[string]any{"name": name, "policy_type": policyType}, "success")
	// Sticky-ack maintenance. Three cases:
	// - Lint fired AND no prior matching sticky ack → operator just
	// supplied acknowledge_lint=true; persist a fresh ack row.
	// - Lint fired AND prior matching sticky ack → keep the row.
	// - Lint did NOT fire → composition was removed; clear the ack
	// so a future re-introduction re-warns.
	if warn != nil {
		ack := map[string]any{
			warn.Rule: map[string]any{
				"acknowledged_at": time.Now().UTC().Format(time.RFC3339),
				"by":              "operator",
				"fingerprint":     warn.Fingerprint,
			},
		}
		_ = s.policies.SetLintAck(id, ack)
	} else {
		// Clear any acks — composition removed.
		_ = s.policies.SetLintAck(id, nil)
	}

	http.Redirect(w, r, "/policies", http.StatusSeeOther)
}

// validatePolicyCommandAllowlist enforces the script-command allowlist at
// policy CREATE/UPDATE.
// The allowlist applies in three places:
// 1. Top-level script-type policy_config (policy_type == "script").
// 2. Nested script actions inside a rules-type policy
// (rules[i].action == "script" with rules[i].script.command).
// 3. Post-execution response filters that exec a script command —
// global response_filters[].script_command AND rule-scoped
// rules[i].response_filters[].script_command. These run AFTER the
// operation, so a disallowed script command silently failing the
// filter would leak the un-redacted response to the agent. The
// validator catches this at save time; the runtime fails closed
// (see policy.ApplyResponseFilters / ResponseFilterError).
// The package-level allowlist (policy.CurrentCommandAllowlist) is wired at
// startup from settings.CommandAllowlist; when unset the bundled-Python
// interpreter is the only permitted value. Returns a non-empty error string
// when validation fails — caller surfaces it as HTTP 400.
func validatePolicyCommandAllowlist(policyType string, config map[string]any) string {
	allow := policy.CurrentCommandAllowlist()
	if policyType == "script" {
		cmd, _ := config["command"].(string)
		if err := policy.ValidateCommand(cmd, allow); err != nil {
			return fmt.Sprintf("script policy: %v", err)
		}
		// A script policy may still emit ResponseFilter values via its
		// decision (the Python script controls that at runtime, not at
		// save time). Nothing to validate statically here.
		return ""
	}
	// Rules-type policy: walk rules[] for action=script entries AND for
	// rule-scoped response_filters[].script_command.
	rules, _ := config["rules"].([]any)
	for i, ri := range rules {
		rm, ok := ri.(map[string]any)
		if !ok {
			continue
		}
		action, _ := rm["action"].(string)
		if action == "script" {
			if sm, ok := rm["script"].(map[string]any); ok {
				cmd, _ := sm["command"].(string)
				if err := policy.ValidateCommand(cmd, allow); err != nil {
					return fmt.Sprintf("rule %d (script action): %v", i+1, err)
				}
			}
		}
		if msg := validateResponseFilterCommands(rm["response_filters"], allow, fmt.Sprintf("rule %d", i+1)); msg != "" {
			return msg
		}
	}
	// Global (rules-config-level) response_filters[].
	if msg := validateResponseFilterCommands(config["response_filters"], allow, "global"); msg != "" {
		return msg
	}
	return ""
}

// validateResponseFilterCommands walks a response_filters[] list and runs
// the script_command of each entry through policy.ValidateCommand. Returns
// an empty string on success; otherwise an operator-facing message naming
// the offending filter. `where` is a label ("global" or "rule N") used in
// that message.
func validateResponseFilterCommands(filtersAny any, allow []string, where string) string {
	filters, ok := filtersAny.([]any)
	if !ok {
		return ""
	}
	for j, fi := range filters {
		fm, ok := fi.(map[string]any)
		if !ok {
			continue
		}
		cmd, _ := fm["script_command"].(string)
		path, _ := fm["script_path"].(string)
		if cmd == "" && path == "" {
			// Pure regex/exclude filter — no command to validate.
			continue
		}
		if err := policy.ValidateCommand(cmd, allow); err != nil {
			return fmt.Sprintf("%s response_filters[%d] (script_command): %v", where, j+1, err)
		}
	}
	return ""
}

// validatePolicyRules gathers all operations from all live connections and
// validates the policy config against them. Returns nil if valid.
func (s *Server) validatePolicyRules(config map[string]any) []string {
	// Gather all operations from all connections.
	conns, err := s.connections.List()
	if err != nil {
		return nil // can't validate without connections, skip
	}

	var allOps []connector.OperationDef
	seen := make(map[string]bool)
	for _, conn := range conns {
		c, err := s.connections.GetConnector(conn.ID)
		if err != nil {
			continue
		}
		for _, op := range c.Operations() {
			if !seen[op.Name] {
				allOps = append(allOps, op)
				seen[op.Name] = true
			}
		}
	}

	if len(allOps) == 0 {
		return nil // no connectors available, skip validation
	}

	return policy.ValidatePolicy(config, allOps)
}

func (s *Server) handlePolicyDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.policies.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "policy.delete", id, nil, "success")
	http.Redirect(w, r, "/policies", http.StatusSeeOther)
}

// --- Approvals handlers ---

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	items, err := s.approval.ListPending()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Build token name lookup for display.
	tokenNames := make(map[string]string)
	for _, item := range items {
		if _, ok := tokenNames[item.TokenID]; !ok {
			if tok, err := s.tokens.Get(item.TokenID); err == nil {
				tokenNames[item.TokenID] = tok.Name
			}
		}
	}

	data := map[string]any{
		"Active":     "approvals",
		"Approvals":  items,
		"TokenNames": tokenNames,
	}
	s.render(w, r, "approvals", data)
}

// The historical rejectIfAgentToken helper has been removed. The
// requireOperatorSession middleware in auth.go is its strict superset:
// a request without a valid operator-session cookie is rejected (401
// for browsers / 403 when the request carries a Sieve bearer token —
// see isAgentTokenRequest). The middleware runs from Server.Handler
// via adminAuthWrapper and gates every admin endpoint that isn't in
// authExemptPaths/authExemptPrefixes.

func (s *Server) handleApprovalApprove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Check if this is a policy proposal — if so, create the policy on approval.
	// If Get fails, it's fine — we just treat it as a normal (non-proposal) approval.
	item, getErr := s.approval.Get(id)
	if getErr == nil && item.Operation == "propose_policy" {
		// Validate the proposal payload BEFORE Approve(): a malformed
		// proposal that we'd then fail to materialise as a policy would
		// leave an "approved" row pointing at no policy, which is
		// indistinguishable from an honest approve+fail and confuses
		// the audit trail.
		data := item.RequestData
		name, _ := data["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			http.Error(w, "policy proposal is missing the required \"name\" field", http.StatusBadRequest)
			return
		}
		rules, _ := data["rules"].([]any)
		defaultAction, _ := data["default_action"].(string)
		if defaultAction == "" {
			defaultAction = "deny"
		}
		config := map[string]any{
			"rules":          rules,
			"default_action": defaultAction,
		}
		if err := s.approval.Approve(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		policyRow, err := s.policies.Create(name, "rules", config)
		if err != nil {
			http.Error(w, "failed to create policy: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = s.audit.LogOperator(operatorDisplayName(r, s), "approval.approve_proposal", id,
			map[string]any{"policy_id": policyRow.ID, "policy_name": name},
			"success")
		http.Redirect(w, r, "/approvals", http.StatusSeeOther)
		return
	}

	if err := s.approval.Approve(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "approval.approve", id, nil, "success")
	http.Redirect(w, r, "/approvals", http.StatusSeeOther)
}

func (s *Server) handleApprovalReject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.approval.Reject(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "approval.reject", id, nil, "success")
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
	s.render(w, r, "audit", data)
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

	rotationSuccess := r.URL.Query().Get("rotated") == "1"
	rotationCount := 0
	if rotationSuccess {
		// Best-effort parse; a missing or bogus count just shows zero,
		// which the template can guard against.
		if n, err := strconv.Atoi(r.URL.Query().Get("count")); err == nil && n >= 0 {
			rotationCount = n
		}
	}

	data := map[string]any{
		"Active":           "settings",
		"Connections":      llmConns,
		"LLMConnection":    allSettings[settings.KeyLLMConnection],
		"LLMModel":         allSettings[settings.KeyLLMModel],
		"LLMMaxTokens":     maxTokens,
		"PublicBaseURL":    allSettings[settings.KeyPublicBaseURL],
		"CommandAllowlist": allSettings[settings.KeyCommandAllowlist],
		"AdminTLSCertPath": allSettings[settings.KeyAdminTLSCertPath],
		"AdminTLSKeyPath":  allSettings[settings.KeyAdminTLSKeyPath],
		"APITLSCertPath":   allSettings[settings.KeyAPITLSCertPath],
		"APITLSKeyPath":    allSettings[settings.KeyAPITLSKeyPath],
		"Success":          r.URL.Query().Get("saved") == "1",
		"RotationSuccess":  rotationSuccess,
		"RotationCount":    rotationCount,
	}
	s.render(w, r, "settings", data)
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	pairs := map[string]string{
		settings.KeyLLMConnection: r.FormValue("llm_connection"),
		settings.KeyLLMModel:      r.FormValue("llm_model"),
		settings.KeyLLMMaxTokens:  r.FormValue("llm_max_tokens"),
	}
	// public_base_url is optional (empty = use loopback default). Validate
	// the supplied value parses as a URL with http/https scheme so an
	// operator can't accidentally persist garbage that would later be
	// embedded into an OAuth manifest.
	if v := strings.TrimSpace(r.FormValue("public_base_url")); v != "" {
		if u, err := url.Parse(v); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			http.Error(w, "public_base_url must be a URL like https://sieve.example.com (http/https only, non-empty host)", http.StatusBadRequest)
			return
		}
		pairs[settings.KeyPublicBaseURL] = v
	} else {
		// Empty submission clears the override (revert to loopback default).
		pairs[settings.KeyPublicBaseURL] = ""
	}

	// TLS cert/key paths. Each pair is both-or-neither —
	// validated at startup by tlsPair.enabled, but the form-save here
	// only persists the strings.
	for _, key := range []string{
		settings.KeyAdminTLSCertPath, settings.KeyAdminTLSKeyPath,
		settings.KeyAPITLSCertPath, settings.KeyAPITLSKeyPath,
	} {
		// form name == settings key.
		pairs[key] = strings.TrimSpace(r.FormValue(key))
	}

	// command_allowlist is a newline-separated list of absolute interpreter
	// paths. Each non-empty line MUST be an absolute path; empty submission
	// reverts to the bundled-Python default. After save, push the new value
	// into the policy package's in-process allowlist so subsequent policy
	// CREATE/UPDATE and evaluation calls see the updated rules.
	allowlistRaw := r.FormValue("command_allowlist")
	if v := strings.TrimSpace(allowlistRaw); v != "" {
		for _, line := range strings.Split(v, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if !filepath.IsAbs(line) {
				http.Error(w, fmt.Sprintf("command_allowlist entry %q must be an absolute path", line), http.StatusBadRequest)
				return
			}
		}
		pairs[settings.KeyCommandAllowlist] = v
	} else {
		pairs[settings.KeyCommandAllowlist] = ""
	}

	for k, v := range pairs {
		if err := s.settings.Set(k, v); err != nil {
			http.Error(w, fmt.Sprintf("failed to save %s: %v", k, err), http.StatusInternalServerError)
			return
		}
	}

	// Reload the in-process command allowlist so subsequent policy CRUD
	// + evaluation calls observe the new value without a process restart.
	policy.SetCommandAllowlist(s.settings.CommandAllowlist())

	// Audit the SUBMITTED key set — i.e. every settings field the form
	// posted, regardless of whether the value actually changed. We
	// don't echo values: some (public_base_url, allowlist) are operator
	// data and the set could grow secret in future, so the audit row
	// records "what the operator could have touched on this save",
	// which mirrors what the rendered form already discloses to anyone
	// with admin access.
	submittedKeys := make([]string, 0, len(pairs))
	for k := range pairs {
		submittedKeys = append(submittedKeys, k)
	}
	sort.Strings(submittedKeys)
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "settings.save", "-",
		map[string]any{"submitted_keys": submittedKeys}, "success")

	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

// --- Model discovery API handler ---

// handleListModels fetches available models from an LLM connection by calling
// its /v1/models endpoint. Both Anthropic and OpenAI use this standard path.
func (s *Server) handleListModels(w http.ResponseWriter, r *http.Request) {
	connID := r.URL.Query().Get("connection_id")
	if connID == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"models": []any{}})
		return
	}

	conn, err := s.connections.GetWithConfig(connID)
	if err != nil {
		if errors.Is(err, secrets.ErrKeyringNotLoaded) {
			http.Error(w, "service locked: passphrase required", http.StatusServiceUnavailable)
			return
		}
		if errors.Is(err, secrets.ErrKeyringRotating) {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "rotation in progress, retry shortly", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "connection not found", http.StatusNotFound)
		return
	}

	targetURL, _ := conn.Config["target_url"].(string)
	authHeader, _ := conn.Config["auth_header"].(string)
	authValue, _ := conn.Config["auth_value"].(string)

	if targetURL == "" || authValue == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"models": []any{}})
		return
	}

	// Call /v1/models on the target API.
	modelsURL := strings.TrimRight(targetURL, "/") + "/v1/models"
	req, err := http.NewRequest("GET", modelsURL, nil)
	if err != nil {
		http.Error(w, "failed to create request", http.StatusInternalServerError)
		return
	}

	if authHeader != "" {
		req.Header.Set(authHeader, authValue)
	}

	// Anthropic requires anthropic-version header.
	if strings.Contains(targetURL, "anthropic.com") {
		req.Header.Set("anthropic-version", "2023-06-01")
	}

	// Add any extra headers from config.
	if extra, ok := conn.Config["extra_headers"].(map[string]any); ok {
		for k, v := range extra {
			if vs, ok := v.(string); ok {
				req.Header.Set(k, vs)
			}
		}
	}

	resp, err := llmModelsHealthClient.Do(req)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"models": []any{}, "error": err.Error()})
		return
	}
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"models": []any{}})
		return
	}

	// Both Anthropic and OpenAI return {"data": [...]} with model objects.
	var models []map[string]any
	if data, ok := body["data"].([]any); ok {
		for _, item := range data {
			if m, ok := item.(map[string]any); ok {
				id, _ := m["id"].(string)
				displayName, _ := m["display_name"].(string)
				if displayName == "" {
					displayName = id
				}
				models = append(models, map[string]any{
					"id":           id,
					"display_name": displayName,
				})
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"models": models})
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

	// Filename validation: single-segment safe filename only. No path
	// separators, no ".." segments, no leading "." (hidden files), no
	// empty name. The pre-fix code accepted the operator's filename
	// after a loose allowlist filter — an arbitrary-file-write path
	// that would have worked under a writable policies/ mount.
	if msg := validateScriptFilename(req.Filename); msg != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid filename: " + msg})
		return
	}
	safe := req.Filename
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
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "script.save", safe, nil, "success")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"path": "./" + path})
}

// validateScriptFilename enforces single-segment safe-filename
// semantics for /api/save-script. Returns the empty
// string when the name is acceptable, or a human-readable reason
// otherwise. Caller surfaces the reason in the 400 response body.
func validateScriptFilename(name string) string {
	if name == "" {
		return "filename is empty"
	}
	if strings.ContainsAny(name, `/\`) {
		return "filename must be a single path segment (no separators)"
	}
	if name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return "filename must not start with '.'"
	}
	if strings.Contains(name, "..") {
		return "filename must not contain '..'"
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '_' || c == '-' || c == '.') {
			return "filename contains a disallowed character"
		}
	}
	return ""
}

// listDocSlugs returns the slugs of every.md file in docs/, in any order.
// Used as the filesystem input to BuildIndex.
func listDocSlugs() ([]string, error) {
	entries, err := os.ReadDir("docs")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".md"))
	}
	return out, nil
}

func docTitleForSlug(slug string) string {
	// Defence in depth — docTitleForSlug is reached today only via
	// listDocSlugs() (filesystem-derived names), but a future call from
	// a request-derived slug would otherwise bypass the validateDocSlug
	// check at the handler layer. Refuse the lookup but return the
	// slug as-is so navigation labels remain stable.
	if msg := validateDocSlug(slug); msg != "" {
		return slug
	}
	t := docTitle(fmt.Sprintf("docs/%s.md", slug))
	if t == "" {
		return slug
	}
	return t
}

func readDocBody(slug string) (string, error) {
	if msg := validateDocSlug(slug); msg != "" {
		return "", fmt.Errorf("invalid doc slug: %s", msg)
	}
	b, err := os.ReadFile(fmt.Sprintf("docs/%s.md", slug))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// validateDocSlug guards readDocBody against path-traversal via the
// /docs/{name} route. Go's http.ServeMux URL-decodes path segments
// before delivering them to r.PathValue, so `/docs/..%2Fetc%2Fpasswd`
// reaches handleDocs as slug="../etc/passwd" — which `docs/%s.md`
// would resolve to `/etc/passwd.md`. /docs is also in
// authExemptPrefixes, so without this check the read is unauthenticated.
// Returns the empty string when the slug is safe.
func validateDocSlug(slug string) string {
	if slug == "" {
		return "empty"
	}
	if strings.ContainsAny(slug, `/\`) {
		return "must be a single path segment (no separators)"
	}
	if slug == "." || slug == ".." || strings.HasPrefix(slug, ".") {
		return "must not start with '.'"
	}
	if strings.Contains(slug, "..") {
		return "must not contain '..'"
	}
	for _, c := range slug {
		if !((c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '_' || c == '-') {
			return "contains a disallowed character"
		}
	}
	return ""
}

// buildDocsIndex composes the filesystem-derived slug list with the live
// manifest and the search corpus into a renderable navigation index.
func (s *Server) buildDocsIndex() (DocNavIndex, error) {
	slugs, err := listDocSlugs()
	if err != nil {
		return DocNavIndex{}, err
	}
	m := Manifest()
	idx := BuildIndex(m, slugs, docTitleForSlug)
	corpus, err := BuildSearchIndex(idx, m, readDocBody)
	if err == nil {
		// Plain string — embedded into <script type="application/json">
		// in docs.html and consumed via JSON.parse(textContent). corpus
		// is already json.Marshal output; the consumer template applies
		// the same </ and U+2028/U+2029 escaping as the `json` FuncMap
		// helper via the docs template's inline encoder, since the
		// corpus goes through Go's html/template auto-escaper inside
		// <script type="application/json"> — which is text-content,
		// not JS.
		idx.SearchIndexJSON = string(corpus)
	}
	return idx, nil
}

func (s *Server) handleDocsIndex(w http.ResponseWriter, r *http.Request) {
	idx, err := s.buildDocsIndex()
	if err != nil {
		http.Error(w, "docs directory not found", http.StatusNotFound)
		return
	}
	idx.Breadcrumbs = []Breadcrumb{{Label: "Documentation"}}
	s.render(w, r, "docs", map[string]any{
		"Active": "docs",
		"Index":  idx,
	})
}

// docTitle returns the first markdown H1 from path, or "" if none is found.
func docTitle(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "#"))
		}
	}
	return ""
}

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if msg := validateDocSlug(name); msg != "" {
		http.Error(w, "doc not found", http.StatusNotFound)
		return
	}
	body, err := readDocBody(name)
	if err != nil {
		http.Error(w, "doc not found", http.StatusNotFound)
		return
	}

	idx, err := s.buildDocsIndex()
	if err != nil {
		http.Error(w, "docs directory not found", http.StatusNotFound)
		return
	}

	title := docTitleForSlug(name)
	m := Manifest()
	catID := categoryFor(name, m)

	current := DocPage{
		Slug:        name,
		Title:       title,
		Description: m.Descriptions[name],
		CategoryID:  catID,
		Hidden:      m.Hidden[name],
		Body:        body,
	}
	idx.Current = &current

	// Resolve breadcrumb category label from the index (so the operator sees
	// the same category title rendered everywhere). Falls back to the manifest
	// if the category was pruned (zero visible pages, e.g. only this hidden
	// page lives in it).
	catLabel, catHref := categoryLabelAndHref(idx, m, catID)
	idx.Breadcrumbs = []Breadcrumb{
		{Label: "Documentation", Href: "/docs"},
		{Label: catLabel, Href: catHref},
		{Label: title},
	}

	s.render(w, r, "docs", map[string]any{
		"Active": "docs",
		"Index":  idx,
	})
}

func (s *Server) handleDocsCategory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	idx, err := s.buildDocsIndex()
	if err != nil {
		http.Error(w, "docs directory not found", http.StatusNotFound)
		return
	}
	view := idx.findCategory(id)
	if view == nil {
		http.Error(w, "category not found", http.StatusNotFound)
		return
	}
	cat := view.Category
	idx.CurrentCategory = &cat
	idx.Breadcrumbs = []Breadcrumb{
		{Label: "Documentation", Href: "/docs"},
		{Label: cat.Title},
	}
	s.render(w, r, "docs", map[string]any{
		"Active": "docs",
		"Index":  idx,
	})
}

func categoryLabelAndHref(idx DocNavIndex, m DocManifest, id string) (string, string) {
	if v := idx.findCategory(id); v != nil {
		return v.Category.Title, fmt.Sprintf("/docs/category/%s", v.Category.ID)
	}
	for _, c := range m.Categories {
		if c.ID == id {
			return c.Title, fmt.Sprintf("/docs/category/%s", c.ID)
		}
	}
	if id == m.FallbackID {
		return m.FallbackTitle, fmt.Sprintf("/docs/category/%s", m.FallbackID)
	}
	return "Documentation", "/docs"
}
