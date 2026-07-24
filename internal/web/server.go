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

	// oauthClients holds the shipped/launch-configured OAuth app client IDs
	// (and, where applicable, non-confidential secrets) for providers whose
	// public app Sieve distributes. Populated by SetOAuthClients from CLI flags
	// / env at startup; empty in tests. See resolveGoogle*/slackOAuthCreds for
	// the precedence (launch value > env > build-time default).
	oauthClients OAuthClientConfig

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
		// linkify turns URLs and bare hostnames in operator-facing help text
		// / descriptions into clickable links (all other text HTML-escaped).
		"linkify": linkifyText,
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
		"strInSlice": func(haystack []string, needle string) bool {
			for _, s := range haystack {
				if s == needle {
					return true
				}
			}
			return false
		},
		"joinNames": func(m map[string]string, ids []string) string {
			parts := make([]string, 0, len(ids))
			for _, id := range ids {
				if v, ok := m[id]; ok {
					parts = append(parts, v)
				} else {
					parts = append(parts, id)
				}
			}
			return strings.Join(parts, ", ")
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
	pages := []string{"connections", "connection_edit", "tokens", "tokens_edit", "approvals", "audit", "settings", "iam", "iam_edit", "iam_filter_edit", "docs"}
	for _, page := range pages {
		t := template.Must(
			template.New("").Funcs(funcMap()).ParseFS(templateFS,
				"templates/nav.html",
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

// OAuthClientConfig carries the OAuth app client credentials Sieve is launched
// with — the public client_id (and, for a Google Desktop client, its
// non-confidential secret) of the app Sieve distributes so users don't register
// their own. Populated from CLI flags / env in cmd/sieve/main.go. A client_id
// with no secret runs that provider as a PKCE public client (see pkce.go).
type OAuthClientConfig struct {
	GoogleClientID     string
	GoogleClientSecret string
	SlackClientID      string
	SlackClientSecret  string
	NotionClientID     string
	NotionClientSecret string
	AsanaClientID      string
	AsanaClientSecret  string
}

// SetOAuthClients records the launch-configured OAuth app client credentials.
// Safe to call with a zero value (tests / installs that only use the encrypted
// Slack row, a BYO Google credentials file, or env vars).
func (s *Server) SetOAuthClients(c OAuthClientConfig) {
	s.oauthClients = c
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
	// Rotate the PAT on an existing github connection in place (distinct 4-segment
	// pattern; the {id} path param keeps it separate from the create route above).
	mux.HandleFunc("POST /connections/{id}/github/pat", s.handleGitHubPATRotate)
	// Slack connector flows.
	mux.HandleFunc("POST /connections/slack/oauth/configure", s.handleSlackOAuthConfigure)
	mux.HandleFunc("POST /connections/slack/oauth/clear", s.handleSlackOAuthClearConfig)
	mux.HandleFunc("POST /connections/slack/oauth/start", s.handleSlackOAuthStart)
	mux.HandleFunc("POST /connections/slack/oauth/user/start", s.handleSlackUserOAuthStart)
	mux.HandleFunc("POST /connections/slack/token", s.handleSlackToken)
	mux.HandleFunc("POST /connections/slack/user-token", s.handleSlackUserToken)
	mux.HandleFunc("POST /connections/slack/{id}/reauth", s.handleSlackReauth)
	mux.HandleFunc("POST /connections/notion/oauth/configure", s.handleNotionOAuthConfigure)
	mux.HandleFunc("POST /connections/notion/oauth/clear", s.handleNotionOAuthClearConfig)
	mux.HandleFunc("POST /connections/notion/oauth/start", s.handleNotionOAuthStart)
	mux.HandleFunc("POST /connections/notion/token", s.handleNotionToken)
	mux.HandleFunc("POST /connections/notion/{id}/reauth", s.handleNotionReauth)
	mux.HandleFunc("POST /connections/asana/oauth/configure", s.handleAsanaOAuthConfigure)
	mux.HandleFunc("POST /connections/asana/oauth/clear", s.handleAsanaOAuthClearConfig)
	mux.HandleFunc("POST /connections/asana/oauth/start", s.handleAsanaOAuthStart)
	mux.HandleFunc("POST /connections/asana/token", s.handleAsanaToken)
	mux.HandleFunc("POST /connections/asana/{id}/reauth", s.handleAsanaReauth)
	mux.HandleFunc("POST /connections/github/app/start", s.handleGitHubAppStart)
	mux.HandleFunc("GET /connections/github/app/created", s.handleGitHubAppCreated)
	mux.HandleFunc("GET /connections/github/app/installed", s.handleGitHubAppInstalled)

	// Tokens
	mux.HandleFunc("GET /tokens", s.handleTokens)
	mux.HandleFunc("POST /tokens/create", s.handleTokenCreate)
	mux.HandleFunc("GET /tokens/{id}/edit", s.handleTokenEditPage)
	mux.HandleFunc("POST /tokens/{id}/roles", s.handleTokenUpdateRoles)
	mux.HandleFunc("POST /tokens/{id}/revoke", s.handleTokenRevoke)

	// Roles + rules + guardrails are managed on the /iam admin page (IAM is the
	// sole authorization engine; the legacy /policies + /roles editors are gone).

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
	mux.HandleFunc("POST /iam/roles/{id}/rename", s.handleIAMRoleRename)
	mux.HandleFunc("POST /iam/roles/{id}/delete", s.handleIAMRoleDelete)
	mux.HandleFunc("POST /iam/policies", s.handleIAMPolicyCreate)
	mux.HandleFunc("GET /iam/policies/{id}/edit", s.handleIAMPolicyEditPage)
	mux.HandleFunc("POST /iam/policies/{id}/update", s.handleIAMPolicyUpdate)
	mux.HandleFunc("POST /iam/policies/{id}/delete", s.handleIAMPolicyDelete)
	mux.HandleFunc("POST /iam/policies/{id}/enabled", s.handleIAMPolicySetEnabled)
	mux.HandleFunc("POST /iam/filters", s.handleIAMFilterCreate)
	mux.HandleFunc("GET /iam/filters/{name}/edit", s.handleIAMFilterEditPage)
	mux.HandleFunc("POST /iam/filters/{name}/update", s.handleIAMFilterUpdate)
	mux.HandleFunc("POST /iam/filters/{name}/delete", s.handleIAMFilterDelete)
	mux.HandleFunc("POST /iam/transforms", s.handleIAMTransformCreate)
	mux.HandleFunc("POST /iam/transforms/{id}/delete", s.handleIAMTransformDelete)
	mux.HandleFunc("POST /iam/transforms/{id}/enabled", s.handleIAMTransformSetEnabled)
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

	// Create-time field view-models per connector type, so the generic
	// catalog card can render the connector's declared SetupFields (e.g.
	// Linear's api_key). Without this the generic form only collected
	// alias + display_name, so any data-driven connector that needs a
	// credential typed in failed validation with no field to fill.
	// Reuses the same editFieldView projection + connection_edit_field
	// partial as the edit page. Connectors with bespoke create forms
	// (http_proxy/github/gitlab/slack) don't consult this; OAuth-only
	// fields (google) are filtered out by fieldInMode.
	createFields := make(map[string][]editFieldView)
	for _, metas := range catalog {
		for _, m := range metas {
			var fields []editFieldView
			for _, f := range m.SetupFields {
				if fieldInMode(f, formModeCreate) {
					fields = append(fields, fieldViewFromStored(f, nil))
				}
			}
			createFields[m.Type] = fields
		}
	}

	data := map[string]any{
		"Active":       active,
		"Connections":  conns,
		"ConnLabels":   connLabels,
		"Catalog":      catalog,
		"CreateFields": createFields,
		"ConnType":     connType,
		// Per-connector UI capability flags. Slack OAuth requires
		// operator-supplied client credentials. The UI shows different
		// content depending on whether they're configured: the install
		// button when set, the configure-form when not. Same lookup
		// chain (settings → env) the install handler uses, so the
		// flag and runtime behavior never diverge.
		"SlackOAuthConfigured":  s.slackOAuthIsConfigured(),
		"NotionOAuthConfigured": s.notionOAuthIsConfigured(),
		"AsanaOAuthConfigured":  s.asanaOAuthIsConfigured(),
		// The exact redirect URI to register in the provider's OAuth app —
		// derived from how the operator reached this page, so the setup cards
		// can show it verbatim instead of telling operators to guess.
		"OAuthCallbackURL": s.oauthRedirectBaseURL(r) + "/oauth/callback",
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
	CodeVerifier        string // PKCE (RFC 7636) verifier; only its S256 challenge left this process. See pkce.go.

	// GoogleClientID / GoogleClientSecret carry the per-connection Google OAuth
	// client chosen for THIS install (empty ⇒ use the server's global client).
	// Set from the add form for a fresh install, or read back from the existing
	// connection's stored config on reauth so a connection always re-authorizes
	// against the same GCP project/client it was created with. See
	// googleOAuthConfigFor and docs/oauth-pkce.md § Per-connection Google client.
	GoogleClientID     string
	GoogleClientSecret string
}

// writeConnectionError centralizes keyring-state → HTTP mapping for the admin
// web surface, mirroring api.Router.writeConnectionError so a config read/write
// can't drift into the wrong status. A locked keyring is a transient service
// state (503), and a rotation in progress is 503 + Retry-After; anything else
// falls through to the caller's default status/message. Keeping this in one
// place is what stops the "one more handler forgot the 503 branch" class of bug.
func (s *Server) writeConnectionError(w http.ResponseWriter, defaultStatus int, defaultMessage string, err error) {
	switch {
	case errors.Is(err, secrets.ErrKeyringNotLoaded):
		http.Error(w, "service locked: passphrase required", http.StatusServiceUnavailable)
	case errors.Is(err, secrets.ErrKeyringRotating):
		w.Header().Set("Retry-After", "5")
		http.Error(w, "rotation in progress, retry shortly", http.StatusServiceUnavailable)
	default:
		http.Error(w, defaultMessage, defaultStatus)
	}
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
			s.writeConnectionError(w, http.StatusInternalServerError, err.Error(), err)
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
		// Optional per-connection OAuth client (e.g. this org's Internal-app
		// client, pasted from its credentials.json). Empty ⇒ use the server's
		// global client. Lets one instance serve multiple Workspace orgs.
		gClientID := strings.TrimSpace(r.FormValue("google_client_id"))
		gClientSecret := strings.TrimSpace(r.FormValue("google_client_secret"))

		conf, err := s.googleOAuthConfigFor(r, gClientID, gClientSecret)
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

		verifier := newPKCEVerifier()
		s.oauthMu.Lock()
		s.oauthPending[state] = pendingOAuth{
			ID:                  id,
			ConnectorType:       connectorType,
			DisplayName:         displayName,
			CreatedAt:           time.Now(),
			OperatorSessionHash: operatorSessionHash(r),
			CodeVerifier:        verifier,
			GoogleClientID:      gClientID,
			GoogleClientSecret:  gClientSecret,
		}
		s.oauthMu.Unlock()

		url := conf.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce, oauth2.S256ChallengeOption(verifier))
		http.Redirect(w, r, url, http.StatusFound)
		return
	}

	// Non-OAuth connectors: save directly.
	if err := s.connections.Add(id, connectorType, displayName, map[string]any{}); err != nil {
		s.writeConnectionError(w, http.StatusInternalServerError, err.Error(), err)
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
	// Read the stored config so we can re-authorize against the SAME OAuth client
	// the connection was created with — critical for multi-org: a connection from
	// one Workspace org must reauth via that org's client, not the global one.
	conn, err := s.connections.GetWithConfig(id)
	if err != nil {
		if errors.Is(err, secrets.ErrKeyringNotLoaded) {
			http.Error(w, "service locked: passphrase required", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "connection not found", http.StatusNotFound)
		return
	}
	if conn.ConnectorType != "google" {
		http.Error(w, "re-auth not supported for connector type "+conn.ConnectorType, http.StatusBadRequest)
		return
	}

	// Reauth reuses the connection's stored client by DEFAULT so it stays on the
	// same org's OAuth client — a connection from one org must not silently jump
	// to the global client of another org (that would re-trigger org_internal).
	// To deliberately MIGRATE a connection to a different client (e.g. off an old
	// project whose APIs were never enabled), the operator can supply a new client
	// on the reauth form; a non-empty client_id there overrides the stored one.
	gClientID := strings.TrimSpace(r.FormValue("google_client_id"))
	gClientSecret := strings.TrimSpace(r.FormValue("google_client_secret"))
	if gClientID == "" {
		gClientID, _ = conn.Config["client_id"].(string)
		gClientSecret, _ = conn.Config["client_secret"].(string)
	}

	conf, err := s.googleOAuthConfigFor(r, gClientID, gClientSecret)
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

	verifier := newPKCEVerifier()
	s.oauthMu.Lock()
	s.oauthPending[state] = pendingOAuth{
		ID:                  id,
		ConnectorType:       conn.ConnectorType,
		DisplayName:         conn.DisplayName,
		CreatedAt:           time.Now(),
		IsReauth:            true,
		OperatorSessionHash: operatorSessionHash(r),
		CodeVerifier:        verifier,
		GoogleClientID:      gClientID,
		GoogleClientSecret:  gClientSecret,
	}
	s.oauthMu.Unlock()

	_ = s.audit.LogOperator(operatorDisplayName(r, s), "connection.reauth_start", id,
		map[string]any{"connector_type": conn.ConnectorType},
		"success")

	url := conf.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce, oauth2.S256ChallengeOption(verifier))
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
// publicBaseURL is the scheme://host Sieve treats as its own externally-visible
// admin base for URLs that DEFINE trust with a third party and therefore must
// NOT be influenced by the inbound request — notably the GitHub App manifest's
// callback/redirect/setup URLs, which are created (not matched) at submission
// time. It uses the operator-configured public_base_url and otherwise the
// loopback default; it deliberately ignores Host / X-Forwarded-* headers.
//
// For OAuth authorization-code redirect URIs (which must round-trip through the
// operator's browser and are gated by the provider's pre-registered redirect
// allowlist) use oauthRedirectBaseURL instead — it derives from the request so
// the flow works from whatever host the operator actually uses.
func (s *Server) publicBaseURL(_ *http.Request) string {
	if s.settings != nil {
		if u := s.settings.PublicBaseURL(); u != "" {
			return strings.TrimRight(u, "/")
		}
	}
	return "https://localhost:19816"
}

// oauthRedirectBaseURL is the scheme://host used to build OAuth
// authorization-code redirect URIs (and the "register this redirect URI" hint
// shown to operators). Explicit public_base_url wins (reverse-proxy
// deployments). Otherwise it DERIVES FROM THE REQUEST — scheme from the actual
// TLS state and host from r.Host — so the redirect matches however the operator
// reached the admin UI (localhost, a LAN hostname, …) instead of a hidden
// 127.0.0.1 default that silently breaks every non-loopback install.
//
// Safe despite r.Host being attacker-influenceable in theory: the OAuth
// provider only ever redirects to a redirect_uri the operator PRE-REGISTERED on
// their app, so a spoofed Host yields an unregistered URI the provider rejects
// — it cannot exfiltrate a code. The /start endpoints are also behind operator
// auth + CSRF. It intentionally trusts ONLY r.Host + r.TLS, never the
// forgeable X-Forwarded-* headers; reverse-proxy users set public_base_url.
func (s *Server) oauthRedirectBaseURL(r *http.Request) string {
	// Read the RAW setting (not PublicBaseURL(), which substitutes a
	// 127.0.0.1 default for an unset value) so an operator who never
	// configured public_base_url falls through to request derivation instead
	// of a hidden loopback default.
	if s.settings != nil {
		if raw, _ := s.settings.Get(settings.KeyPublicBaseURL); strings.TrimSpace(raw) != "" {
			return strings.TrimRight(strings.TrimSpace(raw), "/")
		}
	}
	if r != nil && r.Host != "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		return scheme + "://" + r.Host
	}
	return "https://localhost:19816"
}

// --- OAuth handlers ---

// defaultGoogleClient{ID,Secret} hold Sieve's shipped Google "Desktop app"
// OAuth client, populated at release/build time (e.g.
// `-ldflags "-X github.com/trilitech/Sieve/internal/web.defaultGoogleClientID=..."`).
// Shipping one client means users never register their own Google Cloud
// project — the zero-setup path. A Desktop client's secret is non-confidential
// by Google's own definition, so embedding it is sanctioned; combined with PKCE
// (see pkce.go) it authenticates the loopback code exchange. Empty in source.
var (
	defaultGoogleClientID     string
	defaultGoogleClientSecret string
)

// googleOAuthClientID / googleOAuthClientSecret resolve the shipped Desktop
// client. Precedence: the launch-configured value (--google-oauth-client-id,
// via SetOAuthClients) > the GOOGLE_OAUTH_CLIENT_ID/SECRET env var > the
// build-time default (defaultGoogleClientID, injected via -ldflags).
func (s *Server) googleOAuthClientID() string {
	if v := strings.TrimSpace(s.oauthClients.GoogleClientID); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("GOOGLE_OAUTH_CLIENT_ID")); v != "" {
		return v
	}
	return defaultGoogleClientID
}

func (s *Server) googleOAuthClientSecret() string {
	if v := strings.TrimSpace(s.oauthClients.GoogleClientSecret); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET")); v != "" {
		return v
	}
	return defaultGoogleClientSecret
}

// googleOAuthScopes are the Google API scopes Sieve requests. NOTE: gmail.modify
// and drive are Google RESTRICTED scopes — a publicly distributed app requesting
// them must pass OAuth verification + a CASA security assessment. Keep this list
// as tight as the product actually needs to minimize that review.
var googleOAuthScopes = []string{
	"https://www.googleapis.com/auth/gmail.modify",
	"https://www.googleapis.com/auth/drive",
	"https://www.googleapis.com/auth/calendar",
	"https://www.googleapis.com/auth/contacts",
	"https://www.googleapis.com/auth/spreadsheets",
	"https://www.googleapis.com/auth/documents",
}

// googleOAuthConfig builds the OAuth2 config for the Google/Gmail install flow.
// Preference order:
//  1. Sieve's shipped "Desktop app" client (client_id [+ non-confidential
//     secret] from the build-time defaults or GOOGLE_OAUTH_CLIENT_ID/SECRET).
//     This is the zero-setup path — the user never registers their own Google
//     project; PKCE (pkce.go) secures the loopback code exchange.
//  2. BYO fallback: an operator-supplied credentials.json (Web or Desktop
//     client). Retained for self-hosters and air-gapped deployments.
//
// The redirect_uri is always derived from publicBaseURL, never r.Host — an
// attacker reaching the admin listener could otherwise forge the Host header and
// redirect the OAuth callback to a server they control.
func (s *Server) googleOAuthConfig(r *http.Request) (*oauth2.Config, error) {
	return s.googleOAuthConfigFor(r, "", "")
}

// googleOAuthConfigFor builds the Google OAuth2 config, preferring an explicit
// per-connection client (clientID/clientSecret) when one is supplied. This is
// what lets a single Sieve instance connect accounts from several Workspace orgs
// — each connection carries its own Internal-app client, in its own GCP project,
// instead of everyone sharing one global client (which an Internal consent
// screen would restrict to a single domain). When clientID is empty it falls
// back to the server-wide resolution in order: shipped/flag/env client → BYO
// credentials file. A per-connection client with no secret runs that install as
// a PKCE public client (see pkce.go), though Google token refresh generally
// needs the (non-confidential) Desktop secret.
func (s *Server) googleOAuthConfigFor(r *http.Request, clientID, clientSecret string) (*oauth2.Config, error) {
	redirectURL := s.publicBaseURL(r) + "/oauth/callback"

	// Per-connection client wins: this connection was created against (or is
	// re-authing against) a specific GCP project's OAuth client.
	if clientID != "" {
		return &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       googleOAuthScopes,
			Endpoint:     google.Endpoint,
			RedirectURL:  redirectURL,
		}, nil
	}

	// Preferred: Sieve's shipped Desktop client (no per-user credentials file).
	if id := s.googleOAuthClientID(); id != "" {
		return &oauth2.Config{
			ClientID:     id,
			ClientSecret: s.googleOAuthClientSecret(),
			Scopes:       googleOAuthScopes,
			Endpoint:     google.Endpoint,
			RedirectURL:  redirectURL,
		}, nil
	}

	// BYO fallback: operator-provided client credentials file.
	if s.googleCredentialsFile == "" {
		return nil, fmt.Errorf("Google OAuth not configured: set GOOGLE_OAUTH_CLIENT_ID (Sieve's shipped desktop client) or provide a client credentials file")
	}
	data, err := os.ReadFile(s.googleCredentialsFile)
	if err != nil {
		return nil, fmt.Errorf("read credentials file: %w", err)
	}
	conf, err := google.ConfigFromJSON(data, googleOAuthScopes...)
	if err != nil {
		return nil, fmt.Errorf("parse credentials file: %w", err)
	}
	conf.RedirectURL = redirectURL
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
	if pending.ConnectorType == "notion" {
		s.completeNotionOAuth(w, r, pending, code)
		return
	}
	if pending.ConnectorType == "asana" {
		s.completeAsanaOAuth(w, r, pending, code)
		return
	}

	// Use the same OAuth client this flow started with (per-connection when set,
	// else the global client) so the exchange and the persisted refresh client
	// match what the authorize step used.
	conf, err := s.googleOAuthConfigFor(r, pending.GoogleClientID, pending.GoogleClientSecret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Exchange the authorization code for a token. Replay the PKCE verifier
	// minted at /start (see pkce.go) so the token endpoint can bind the code to
	// this flow. Guard on non-empty for flows started before this field existed.
	exchangeOpts := []oauth2.AuthCodeOption{}
	if pending.CodeVerifier != "" {
		exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(pending.CodeVerifier))
	}
	token, err := conf.Exchange(context.Background(), code, exchangeOpts...)
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
			s.writeConnectionError(w, http.StatusInternalServerError, fmt.Sprintf("failed to update connection: %v", err), err)
			return
		}
	} else {
		if err := s.connections.Add(pending.ID, pending.ConnectorType, pending.DisplayName, connConfig); err != nil {
			s.writeConnectionError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save connection: %v", err), err)
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

	// Capability rollup: for each token, the union of its roles' rule summaries —
	// so the operator can see what a token can actually DO, not just role names.
	caps := s.tokenCaps(toks)

	data := map[string]any{
		"Active":    "tokens",
		"Tokens":    toks,
		"Roles":     rolesList,
		"RoleNames": roleNames,
		"Caps":      caps,
		"Filter":    filter,
	}
	s.render(w, r, "tokens", data)
}

// tokenCaps builds the per-token capability rollup the tokens.html template reads
// via `index $.Caps .ID`: for each token, the deduped union of its roles' rule
// summaries. Both the list page and the create-success render must supply it —
// tokens.html evaluates `index $.Caps .ID`, which errors on a nil map.
func (s *Server) tokenCaps(toks []tokens.Token) map[string][]string {
	byRole := s.ruleSummariesByRole()
	caps := make(map[string][]string, len(toks))
	for _, t := range toks {
		seen := map[string]bool{}
		var lines []string
		for _, rid := range t.RoleIDs {
			for _, sum := range byRole[rid] {
				if !seen[sum] {
					seen[sum] = true
					lines = append(lines, sum)
				}
			}
		}
		caps[t.ID] = lines
	}
	return caps
}

// parseExpiry parses a token-expiry duration. It accepts standard Go durations
// (e.g. "12h", "720h") plus "Nd" for N days, which Go's ParseDuration rejects.
func parseExpiry(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(days))
		if err == nil && n >= 0 {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	return time.ParseDuration(s)
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	// A token composes one or more roles (RBAC). The multi-select posts role_id
	// repeatedly; accept the legacy single value too.
	roleIDs := nonEmptyStrings(r.Form["role_id"])

	if len(roleIDs) == 0 {
		http.Error(w, "at least one role is required", http.StatusBadRequest)
		return
	}

	// Expiry precedence: an explicit date wins, else a freeform duration, else
	// the preset. (Go's ParseDuration has no "days", so parseExpiry adds Nd.)
	var expiresIn time.Duration
	if dateStr := r.FormValue("expires_date"); dateStr != "" {
		t, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid expiry date: %v", err), http.StatusBadRequest)
			return
		}
		// Token is valid through the end of the chosen day.
		expiresIn = time.Until(t.Add(24 * time.Hour))
		if expiresIn <= 0 {
			http.Error(w, "expiry date must be in the future", http.StatusBadRequest)
			return
		}
	} else {
		expStr := r.FormValue("expires_custom")
		if expStr == "" {
			expStr = r.FormValue("expires_preset")
		}
		if expStr != "" {
			d, err := parseExpiry(expStr)
			if err != nil {
				http.Error(w, fmt.Sprintf("invalid expiry duration %q (try e.g. 45d, 12h)", expStr), http.StatusBadRequest)
				return
			}
			expiresIn = d
		}
	}

	result, err := s.tokens.Create(&tokens.CreateRequest{
		Name:      name,
		RoleIDs:   roleIDs,
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
		map[string]any{"name": name, "role_ids": roleIDs}, "success")

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

	rolesList, err := s.roles.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// tokens.html reads RoleNames + Caps (index $.Caps .ID); both must be supplied
	// here too, or the create-success render errors once any token exists.
	roleNames := make(map[string]string, len(rolesList))
	for _, role := range rolesList {
		roleNames[role.ID] = role.Name
	}

	data := map[string]any{
		"Active":         "tokens",
		"Tokens":         toks,
		"Connections":    connList,
		"Roles":          rolesList,
		"RoleNames":      roleNames,
		"Caps":           s.tokenCaps(toks),
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

// handleTokenEditPage renders the edit-roles form for one token
// (GET /tokens/{id}/edit). The token secret is never shown or regenerated — only
// its role set is editable.
func (s *Server) handleTokenEditPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tok, err := s.tokens.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	rolesList, err := s.roles.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	current := make(map[string]bool, len(tok.RoleIDs))
	for _, rid := range tok.RoleIDs {
		current[rid] = true
	}
	data := map[string]any{
		"Active":  "tokens",
		"Token":   tok,
		"Roles":   rolesList,
		"Current": current,
	}
	s.render(w, r, "tokens_edit", data)
}

// handleTokenUpdateRoles replaces a token's role set (POST /tokens/{id}/roles)
// without regenerating the secret.
func (s *Server) handleTokenUpdateRoles(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	roleIDs := nonEmptyStrings(r.Form["role_id"])
	if len(roleIDs) == 0 {
		http.Error(w, "at least one role is required", http.StatusBadRequest)
		return
	}
	if err := s.tokens.UpdateRoles(id, roleIDs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "token.update_roles", id,
		map[string]any{"role_ids": roleIDs}, "success")
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
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
		"Active":        "settings",
		"Connections":   llmConns,
		"LLMConnection": allSettings[settings.KeyLLMConnection],
		"LLMModel":      allSettings[settings.KeyLLMModel],
		"LLMMaxTokens":  maxTokens,
		"PublicBaseURL": allSettings[settings.KeyPublicBaseURL],
		// Derived from PublicBaseURL via publicBaseURL() (the strict helper,
		// matching Google's loopback flow + the GitHub App manifest). The Slack
		// and Notion setup cards show the request-derived redirect URI directly
		// on the connections page, which is where those OAuth apps are wired up.
		"OAuthCallbackURL": s.publicBaseURL(r) + "/oauth/callback",
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
		s.writeConnectionError(w, http.StatusNotFound, "connection not found", err)
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
