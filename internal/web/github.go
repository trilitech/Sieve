package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trilitech/Sieve/internal/connectors/github"
)

// githubHTTPClient is the hardened client used for all GitHub calls made
// outside the Connector (manifest code exchange, installation-scope lookup,
// PAT probe). Shared with the connector's internal client shape so the whole
// package speaks to GitHub with consistent timeouts and redirect behavior.
var githubHTTPClient = github.NewHardenedClient()

// pendingGitHubApp holds in-flight state between the two GitHub App manifest
// callbacks: the redirect_url callback (App created, code exchange) and the
// setup_url callback (installation complete). A single pending entry spans
// both redirects because we need the App's private key from step 1 to
// call /app/installations/{id} in step 2.
// OperatorSessionHash binds the pending entry to the operator session that
// initiated /start. Both callback legs are in authExemptPaths (they receive
// the GitHub redirect, not a logged-in admin click), so without this binding
// anyone who can reach /start could pre-mint a state and race a legitimate
// operator's two-leg callback flow.
type pendingGitHubApp struct {
	ID          string
	DisplayName string
	CreatedAt   time.Time

	// Populated after the redirect_url callback exchanges the code.
	AppID         int64
	Slug          string
	PrivateKeyPEM string

	OperatorSessionHash string
}

const pendingGitHubAppTTL = 15 * time.Minute // longer than OAuth because two redirects

// gitHubAppState holds the Server-scoped pending-App map. Kept as a separate
// struct from oauthPending so the field semantics don't blur.
type gitHubAppState struct {
	mu      sync.Mutex
	pending map[string]pendingGitHubApp
}

func newGitHubAppState() *gitHubAppState {
	return &gitHubAppState{pending: map[string]pendingGitHubApp{}}
}

func (g *gitHubAppState) put(state string, p pendingGitHubApp) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pending[state] = p
}

// take atomically removes and returns the pending entry for state, returning
// ok=false if absent or expired.
func (g *gitHubAppState) take(state string, now time.Time) (pendingGitHubApp, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p, ok := g.pending[state]
	if !ok {
		return pendingGitHubApp{}, false
	}
	delete(g.pending, state)
	if now.Sub(p.CreatedAt) > pendingGitHubAppTTL {
		return pendingGitHubApp{}, false
	}
	return p, true
}

// update replaces an existing pending entry with updated App credentials.
// Used between the two redirects; resets CreatedAt to extend the window.
func (g *gitHubAppState) update(state string, mutate func(*pendingGitHubApp)) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	p, ok := g.pending[state]
	if !ok {
		return false
	}
	mutate(&p)
	p.CreatedAt = time.Now() // restart TTL between redirect legs
	g.pending[state] = p
	return true
}

// has reports whether a non-expired pending entry exists for state, deleting
// it if found to be expired. Used by the redirect_url callback to validate
// state before doing the (potentially slow) manifest code exchange.
func (g *gitHubAppState) has(state string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	p, ok := g.pending[state]
	if !ok {
		return false
	}
	if now.Sub(p.CreatedAt) > pendingGitHubAppTTL {
		delete(g.pending, state)
		return false
	}
	return true
}

// sessionHash returns the OperatorSessionHash recorded on the pending
// entry for state, or "" if the state is unknown or expired. Used by the
// callback handlers to verify the session that initiated /start is the
// same one returning through the GitHub redirect.
func (g *gitHubAppState) sessionHash(state string, now time.Time) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	p, ok := g.pending[state]
	if !ok {
		return ""
	}
	if now.Sub(p.CreatedAt) > pendingGitHubAppTTL {
		return ""
	}
	return p.OperatorSessionHash
}

func (g *gitHubAppState) sweep(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, p := range g.pending {
		if now.Sub(p.CreatedAt) > pendingGitHubAppTTL {
			delete(g.pending, k)
		}
	}
}

// --- handlers ---

// handleGitHubPAT validates a fine-grained PAT against GitHub's /user or
// /orgs/{name} endpoint and persists a new `github` connection on success.
func (s *Server) handleGitHubPAT(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.FormValue("id")
	displayName := r.FormValue("display_name")
	scopeType := r.FormValue("scope_type")
	scopeName := strings.TrimSpace(r.FormValue("scope_name"))
	token := r.FormValue("token")

	if id == "" || displayName == "" || scopeType == "" || scopeName == "" || token == "" {
		http.Error(w, "all fields are required", http.StatusBadRequest)
		return
	}
	if scopeType != github.ScopeUser && scopeType != github.ScopeOrg {
		http.Error(w, "scope_type must be 'user' or 'org'", http.StatusBadRequest)
		return
	}
	if exists, _ := s.connections.Exists(id); exists {
		http.Error(w, fmt.Sprintf("connection %q already exists", id), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := github.ValidatePAT(ctx, githubHTTPClient, "", token, scopeType, scopeName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	defaultIdx := 0
	cfg := map[string]any{
		"credentials": []any{
			map[string]any{
				"kind":  github.KindFPAT,
				"scope": map[string]any{"type": scopeType, "name": scopeName},
				"token": token,
			},
		},
		"default_credential_index": defaultIdx,
	}
	if err := s.connections.Add(id, "github", displayName, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// handleGitHubAppStart renders an intermediate page that auto-submits a
// GitHub App manifest to github.com/settings/apps/new. GitHub requires the
// manifest to arrive as a POST form field, so we can't express this as a
// simple redirect. The user clicks through the App creation confirmation
// on GitHub, and GitHub redirects back to /connections/github/app/created
// with a code that we exchange for the App credentials.
func (s *Server) handleGitHubAppStart(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.FormValue("id")
	displayName := r.FormValue("display_name")
	orgSlug := strings.TrimSpace(r.FormValue("org_slug"))

	if id == "" || displayName == "" {
		http.Error(w, "alias and display name are required", http.StatusBadRequest)
		return
	}
	if exists, _ := s.connections.Exists(id); exists {
		http.Error(w, fmt.Sprintf("connection %q already exists", id), http.StatusBadRequest)
		return
	}

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}
	state := hex.EncodeToString(stateBytes)

	s.githubApp.put(state, pendingGitHubApp{
		ID:                  id,
		DisplayName:         displayName,
		CreatedAt:           time.Now(),
		OperatorSessionHash: operatorSessionHash(r),
	})

	// Manifest URLs are derived from the operator-configured public base URL,
	// never from r.Host / X-Forwarded-Host / X-Forwarded-Proto — GitHub
	// registers the callback URLs at App creation time, so its own redirect-
	// URI allowlist cannot protect Sieve here. A forged Host header would
	// otherwise let an attacker steer the App's redirect target at install.
	base := s.publicBaseURL(r)
	redirectURL := base + "/connections/github/app/created"
	setupURL := base + "/connections/github/app/installed"

	manifest := map[string]any{
		"name":         displayName + " (Sieve)",
		"url":          base,
		"redirect_url": redirectURL,
		"setup_url":    setupURL,
		"callback_urls": []string{redirectURL},
		"hook_attributes": map[string]any{
			"url":    base + "/connections/github/app/webhook-unused",
			"active": false,
		},
		"public": false,
		"default_permissions": map[string]string{
			"metadata":      "read",
			"contents":      "write",
			"issues":        "write",
			"pull_requests": "write",
		},
		// Tell GitHub to redirect to setup_url after install even if the App is
		// owned by the same user — required for our install-callback flow.
		"setup_on_update": true,
	}

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		http.Error(w, "encode manifest: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// GitHub accepts an optional owner segment in the POST URL to scope
	// creation under an org. `orgSlug` is user-controlled form input, so
	// escape it defensively even though the redirect targets the user's own
	// browser.
	postURL := "https://github.com/settings/apps/new?state=" + url.QueryEscape(state)
	if orgSlug != "" {
		postURL = "https://github.com/organizations/" + url.PathEscape(orgSlug) +
			"/settings/apps/new?state=" + url.QueryEscape(state)
	}

	data := map[string]any{
		"PostURL":  postURL,
		"Manifest": string(manifestJSON),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := githubAppStartTemplate.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

var githubAppStartTemplate = template.Must(template.New("ghapp-start").Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Creating GitHub App…</title></head>
<body style="font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:40px">
  <h2>Redirecting to GitHub to create your App…</h2>
  <p>If nothing happens in a few seconds, <button type="submit" form="ghapp-form" style="padding:8px 16px;background:#6366f1;color:white;border:none;border-radius:4px;cursor:pointer">click here</button>.</p>
  <form id="ghapp-form" method="POST" action="{{.PostURL}}">
    <input type="hidden" name="manifest" value='{{.Manifest}}'>
  </form>
  <script>document.getElementById('ghapp-form').submit();</script>
</body></html>`))

// handleGitHubAppCreated is the `redirect_url` callback after the user
// confirms App creation on GitHub. We exchange the one-time code for the
// App's ID + private key + slug, then redirect the user to the install URL.
func (s *Server) handleGitHubAppCreated(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	if !s.githubApp.has(state, time.Now()) {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}
	// State-confusion guard: the callback must come back through the same
	// operator session that initiated /start. See server.go's
	// handleOAuthCallback for the matching check on the Slack/Google paths.
	if want := s.githubApp.sessionHash(state, time.Now()); want != "" {
		if !operatorSessionHashesEqual(want, operatorSessionHash(r)) {
			http.Error(w, "callback rejected: session mismatch — restart the GitHub App flow from the same browser session", http.StatusForbidden)
			return
		}
	}

	// Exchange the code: POST https://api.github.com/app-manifests/{code}/conversions
	// This endpoint is unauthenticated; the code itself is the credential.
	// PathEscape `code` defensively — GitHub documents it as opaque.
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.github.com/app-manifests/"+url.PathEscape(code)+"/conversions", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "Sieve")
	resp, err := githubHTTPClient.Do(req)
	if err != nil {
		http.Error(w, "manifest exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		http.Error(w, fmt.Sprintf("manifest exchange status %d: %s",
			resp.StatusCode, github.Truncate(string(body), 500)), http.StatusBadGateway)
		return
	}
	var out struct {
		ID   int64  `json:"id"`
		Slug string `json:"slug"`
		PEM  string `json:"pem"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		http.Error(w, "decode manifest response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if out.ID == 0 || out.Slug == "" || out.PEM == "" {
		http.Error(w, "manifest response missing required fields", http.StatusBadGateway)
		return
	}

	// Persist App credentials into the pending entry. update also extends
	// CreatedAt so the install callback has a fresh TTL window.
	if ok := s.githubApp.update(state, func(p *pendingGitHubApp) {
		p.AppID = out.ID
		p.Slug = out.Slug
		p.PrivateKeyPEM = out.PEM
	}); !ok {
		http.Error(w, "state expired during exchange — restart the flow", http.StatusBadRequest)
		return
	}

	// Send the user to the installation flow. The setup_url we declared in the
	// manifest is what GitHub will redirect to once installation completes.
	installURL := "https://github.com/apps/" + url.PathEscape(out.Slug) +
		"/installations/new?state=" + url.QueryEscape(state)
	http.Redirect(w, r, installURL, http.StatusFound)
}

// handleGitHubAppInstalled is the `setup_url` callback after the user
// finishes installing the App on an account/org. We inspect the installation
// to learn its scope and persist the final connection.
func (s *Server) handleGitHubAppInstalled(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	installStr := r.URL.Query().Get("installation_id")
	if state == "" || installStr == "" {
		http.Error(w, "missing state or installation_id", http.StatusBadRequest)
		return
	}
	installationID, err := strconv.ParseInt(installStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid installation_id", http.StatusBadRequest)
		return
	}

	p, ok := s.githubApp.take(state, time.Now())
	if !ok {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}
	if p.AppID == 0 || p.PrivateKeyPEM == "" {
		http.Error(w, "pending install is missing App credentials — restart the flow", http.StatusBadRequest)
		return
	}
	// State-confusion guard: same browser session as /start. The pending
	// entry is already consumed at this point — a mismatch means we throw
	// the credentials away rather than persist them.
	if p.OperatorSessionHash != "" {
		if !operatorSessionHashesEqual(p.OperatorSessionHash, operatorSessionHash(r)) {
			http.Error(w, "callback rejected: session mismatch — restart the GitHub App flow from the same browser session", http.StatusForbidden)
			return
		}
	}

	// Query the installation to discover its scope (account login + type).
	scopeType, scopeName, err := fetchInstallationScope(r.Context(), p.AppID, installationID, p.PrivateKeyPEM)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	defaultIdx := 0
	cfg := map[string]any{
		"credentials": []any{
			map[string]any{
				"kind":            github.KindAppInstallation,
				"scope":           map[string]any{"type": scopeType, "name": scopeName},
				"app_id":          p.AppID,
				"installation_id": installationID,
				"private_key_pem": p.PrivateKeyPEM,
			},
		},
		"default_credential_index": defaultIdx,
	}
	if err := s.connections.Add(p.ID, "github", p.DisplayName, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// fetchInstallationScope signs an App JWT and queries GET /app/installations/{id}
// to learn the account (user or org) that the installation is scoped to.
// We can't use the github.Connector directly here because it requires a
// fully-populated connection config, which we don't have yet. The default
// client + apiBase are the production values; tests override them.
func fetchInstallationScope(ctx context.Context, appID, installationID int64, privateKeyPEM string) (string, string, error) {
	return fetchInstallationScopeWith(ctx, githubHTTPClient, "https://api.github.com", appID, installationID, privateKeyPEM)
}

func fetchInstallationScopeWith(ctx context.Context, client *http.Client, apiBase string, appID, installationID int64, privateKeyPEM string) (string, string, error) {
	jwt, err := github.SignAppJWT(appID, privateKeyPEM, time.Now())
	if err != nil {
		return "", "", fmt.Errorf("sign app jwt: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		apiBase+"/app/installations/"+strconv.FormatInt(installationID, 10), nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "Sieve")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("fetch installation: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("fetch installation: status %d: %s",
			resp.StatusCode, github.Truncate(string(body), 500))
	}
	var out struct {
		Account struct {
			Login string `json:"login"`
			Type  string `json:"type"` // "User" or "Organization"
		} `json:"account"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", fmt.Errorf("decode installation: %w", err)
	}
	if out.Account.Login == "" {
		return "", "", errors.New("installation response missing account login")
	}
	scopeType := github.ScopeOrg
	if strings.EqualFold(out.Account.Type, "User") {
		scopeType = github.ScopeUser
	}
	return scopeType, out.Account.Login, nil
}
