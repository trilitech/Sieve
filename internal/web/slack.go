package web

// Per-connector handlers for Slack admin flows. Three entry points:
//
//   - POST /connections/slack/oauth/start — admin clicks "Install via OAuth"
//     in the connection picker. Generates state, stashes the pending
//     connection in oauthPending (10-minute TTL), redirects to Slack.
//     The shared /oauth/callback dispatches back to slackOAuthExchange
//     based on pending.ConnectorType (see server.go).
//
//   - POST /connections/slack/token — admin pastes a pre-existing bot
//     token. Validates against Slack auth.test before persisting.
//
//   - POST /connections/slack/{id}/reauth — admin clicks "Re-install"
//     on a reauth_required row to clear the status by completing a
//     fresh OAuth flow. Reuses the same pendingOAuth machinery so the
//     callback path is shared.
//
// All three are gated by rejectIfAgentToken — agents must never reach
// admin-side connection mutation paths (FR-013).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/trilitech/Sieve/internal/connections"
	slackconn "github.com/trilitech/Sieve/internal/connectors/slack"
	"github.com/trilitech/Sieve/internal/settings"
)

// Slack OAuth endpoints. Constants here so the test suite can swap
// them out via slackOAuthEndpointOverride below.
const (
	slackAuthorizeURL = "https://slack.com/oauth/v2/authorize"
	slackTokenURL     = "https://slack.com/api/oauth.v2.access"
	slackAuthTestURL  = "https://slack.com/api/auth.test"

	// Default bot scopes for v1 (classic non-rotating per Q2
	// 2026-05-01). Expanded scopes — search:read, user-token install
	// — are deferred along with Enterprise Grid.
	slackDefaultBotScopes = "channels:read,groups:read,users:read,users.profile:read,channels:history,groups:history,chat:write"
)

// slackOAuthEndpointOverride lets tests point Slack OAuth at a mock
// server. When non-empty, slackAuthorizeURL/slackTokenURL/slackAuthTestURL
// are replaced with the override + the trailing path. Production is
// always nil-string.
var slackOAuthEndpointOverride string

func slackEndpoint(production string) string {
	if slackOAuthEndpointOverride == "" {
		return production
	}
	// Replace https://slack.com with the override base URL.
	return strings.Replace(production, "https://slack.com", strings.TrimRight(slackOAuthEndpointOverride, "/"), 1)
}

// slackOAuthClientID and slackOAuthClientSecret resolve the operator's
// Slack OAuth app credentials. Lookup order:
//
//   1. The settings table (settings.KeySlackClientID /
//      KeySlackClientSecret) — operator-set via the connections
//      page's "Set up Slack OAuth" form. This is the recommended
//      path because it persists across restarts and survives
//      Docker container recreations.
//   2. SLACK_CLIENT_ID / SLACK_CLIENT_SECRET environment variables
//      — fallback for operators who prefer 12-factor config or
//      automated deployments.
//
// If neither is set, the OAuth path is unavailable and the UI
// shows a configure-form instead of the install button. This
// matches the Google connector's behavior when no credentials
// JSON is present.
func (s *Server) slackOAuthClientID() string {
	if v, _ := s.settings.Get(settings.KeySlackClientID); v != "" {
		return v
	}
	return os.Getenv("SLACK_CLIENT_ID")
}

func (s *Server) slackOAuthClientSecret() string {
	if v, _ := s.settings.Get(settings.KeySlackClientSecret); v != "" {
		return v
	}
	return os.Getenv("SLACK_CLIENT_SECRET")
}

// handleSlackOAuthStart kicks off the Slack OAuth v2 install flow for
// a fresh connection. Reads id + display_name from the form, validates,
// and delegates to beginSlackOAuth.
func (s *Server) handleSlackOAuthStart(w http.ResponseWriter, r *http.Request) {
	if rejectIfAgentToken(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	if id == "" || displayName == "" {
		http.Error(w, "id and display_name are required", http.StatusBadRequest)
		return
	}
	if exists, _ := s.connections.Exists(id); exists {
		http.Error(w, fmt.Sprintf("connection %q already exists", id), http.StatusBadRequest)
		return
	}
	s.beginSlackOAuth(w, r, id, displayName)
}

// beginSlackOAuth stashes a pendingOAuth entry and redirects to the
// Slack v2 authorize endpoint. Callers (handleSlackOAuthStart for a
// fresh install, handleSlackReauth for re-installing an existing
// connection) supply the id + display name; this helper handles the
// state generation, TTL setup, and redirect uniformly.
func (s *Server) beginSlackOAuth(w http.ResponseWriter, r *http.Request, id, displayName string) {
	clientID := s.slackOAuthClientID()
	if clientID == "" {
		http.Error(w, "Slack OAuth not configured — paste your Slack app credentials at /connections (the 'Set up Slack OAuth' form), or use the bot-token entry path", http.StatusBadRequest)
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
		ID:            id,
		ConnectorType: "slack",
		DisplayName:   displayName,
		CreatedAt:     time.Now(),
	}
	s.oauthMu.Unlock()

	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("scope", slackDefaultBotScopes)
	q.Set("redirect_uri", fmt.Sprintf("http://%s/oauth/callback", r.Host))
	q.Set("state", state)
	target := slackEndpoint(slackAuthorizeURL) + "?" + q.Encode()
	http.Redirect(w, r, target, http.StatusFound)
}

// handleSlackToken handles the direct bot-token entry path. Admin
// pastes a pre-existing xoxb- token from a Slack app they own; we
// validate against auth.test and persist on success.
func (s *Server) handleSlackToken(w http.ResponseWriter, r *http.Request) {
	if rejectIfAgentToken(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	token := strings.TrimSpace(r.FormValue("bot_token"))
	if id == "" || displayName == "" || token == "" {
		http.Error(w, "id, display_name, and bot_token are required", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(token, "xoxb-") {
		http.Error(w, "bot_token must start with xoxb- (Slack bot token format)", http.StatusBadRequest)
		return
	}
	if exists, _ := s.connections.Exists(id); exists {
		http.Error(w, fmt.Sprintf("connection %q already exists", id), http.StatusBadRequest)
		return
	}

	teamID, teamName, botUserID, err := slackAuthTest(r.Context(), token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Slack auth.test failed: %v", err), http.StatusBadRequest)
		return
	}

	cfg := map[string]any{
		"auth_kind":   slackconn.KindToken,
		"bot_token":   token,
		"team_id":     teamID,
		"team_name":   teamName,
		"bot_user_id": botUserID,
	}
	if err := s.connections.Add(id, "slack", displayName, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// handleSlackReauth lets an admin clear a `reauth_required` row by
// re-running the OAuth flow OR re-pasting a bot token. The id is
// taken from the path; we delegate to the start/token handlers
// after stashing the existing display_name so the admin doesn't
// have to re-enter it.
func (s *Server) handleSlackReauth(w http.ResponseWriter, r *http.Request) {
	if rejectIfAgentToken(w, r) {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	existing, err := s.connections.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Reuse the OAuth-start path: kick a fresh flow with the same id +
	// display name. On callback success we'll UpdateConfig instead of
	// Add (the existing pendingOAuth + handleOAuthCallback flow handles
	// this — see slackOAuthExchange in server.go).
	if newToken := strings.TrimSpace(r.FormValue("bot_token")); newToken != "" {
		// Token-path reauth: validate + UpdateConfig + reset status.
		if !strings.HasPrefix(newToken, "xoxb-") {
			http.Error(w, "bot_token must start with xoxb-", http.StatusBadRequest)
			return
		}
		teamID, teamName, botUserID, err := slackAuthTest(r.Context(), newToken)
		if err != nil {
			http.Error(w, fmt.Sprintf("Slack auth.test failed: %v", err), http.StatusBadRequest)
			return
		}
		cfg := map[string]any{
			"auth_kind":   slackconn.KindToken,
			"bot_token":   newToken,
			"team_id":     teamID,
			"team_name":   teamName,
			"bot_user_id": botUserID,
		}
		if err := s.connections.UpdateConfig(id, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.connections.SetStatus(id, connections.StatusActive); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/connections", http.StatusSeeOther)
		return
	}
	// OAuth-path reauth: stash + redirect to Slack. handleOAuthCallback
	// notices that the connection id already exists and routes the
	// completion through UpdateConfig + SetStatus(active) instead of Add.
	s.beginSlackOAuth(w, r, id, existing.DisplayName)
}

// slackAuthTest calls Slack auth.test and returns the team / user
// metadata on success. Used by both the token-entry path and the
// OAuth-callback path to confirm the new credential works before
// persisting.
func slackAuthTest(ctx context.Context, token string) (teamID, teamName, botUserID string, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", slackEndpoint(slackAuthTestURL), nil)
	if err != nil {
		return "", "", "", fmt.Errorf("build auth.test request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("auth.test http: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		OK     bool   `json:"ok"`
		Error  string `json:"error"`
		TeamID string `json:"team_id"`
		Team   string `json:"team"`
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", "", fmt.Errorf("auth.test decode: %w", err)
	}
	if !out.OK {
		return "", "", "", fmt.Errorf("auth.test rejected token: %s", out.Error)
	}
	return out.TeamID, out.Team, out.UserID, nil
}

// handleSlackOAuthConfigure stores Slack OAuth app credentials
// (client_id + client_secret) so the operator doesn't have to set
// env vars and restart Sieve. Mirrors how the LLM provider cards
// let admins paste API keys directly. After save, the connections
// page reloads with the OAuth Install button enabled.
//
// This endpoint is admin-only (rejectIfAgentToken). Credentials are
// persisted in the settings table; the DB file is chmod 0600 — same
// exposure class as Google's `*client_secret*.json` file path.
func (s *Server) handleSlackOAuthConfigure(w http.ResponseWriter, r *http.Request) {
	if rejectIfAgentToken(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := strings.TrimSpace(r.FormValue("client_secret"))
	if clientID == "" || clientSecret == "" {
		http.Error(w, "client_id and client_secret are both required", http.StatusBadRequest)
		return
	}
	// Light shape validation. Slack client IDs look like
	// "1234567890.1234567890" and secrets are 32-char hex; not worth
	// strict regex (Slack can change format), but reject obvious junk.
	if !strings.ContainsRune(clientID, '.') || len(clientID) < 10 {
		http.Error(w, "client_id doesn't look like a Slack OAuth client ID (expected format: 1234567890.1234567890)", http.StatusBadRequest)
		return
	}
	if len(clientSecret) < 16 {
		http.Error(w, "client_secret too short — copy the full value from your Slack app's Basic Information page", http.StatusBadRequest)
		return
	}
	if err := s.settings.Set(settings.KeySlackClientID, clientID); err != nil {
		http.Error(w, "save client_id: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.settings.Set(settings.KeySlackClientSecret, clientSecret); err != nil {
		http.Error(w, "save client_secret: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// handleSlackOAuthClearConfig wipes the persisted Slack OAuth app
// credentials. Useful when rotating the Slack app or moving away
// from OAuth toward bot-token-only installs.
func (s *Server) handleSlackOAuthClearConfig(w http.ResponseWriter, r *http.Request) {
	if rejectIfAgentToken(w, r) {
		return
	}
	if err := s.settings.Delete(settings.KeySlackClientID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.settings.Delete(settings.KeySlackClientSecret); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// completeSlackOAuth handles the post-callback completion for Slack
// installs (both fresh-add and reauth flows). Called from
// handleOAuthCallback after state validation. Persists via Add for a
// new install or via UpdateConfig+SetStatus(active) for a reauth.
func (s *Server) completeSlackOAuth(w http.ResponseWriter, r *http.Request, pending pendingOAuth, code string) {
	cfg, err := s.slackOAuthExchange(r.Context(), r.Host, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Reauth path: connection already exists, UpdateConfig + reset
	// status to active. Fresh-install path: Add a new row.
	if exists, _ := s.connections.Exists(pending.ID); exists {
		if err := s.connections.UpdateConfig(pending.ID, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.connections.SetStatus(pending.ID, connections.StatusActive); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := s.connections.Add(pending.ID, "slack", pending.DisplayName, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// slackOAuthExchange completes the OAuth callback for a Slack pending
// install. Called from handleOAuthCallback once the dispatcher has
// confirmed pending.ConnectorType == "slack". Returns the connection
// config that handleOAuthCallback then persists via Add or UpdateConfig.
func (s *Server) slackOAuthExchange(ctx context.Context, host, code string) (map[string]any, error) {
	clientID := s.slackOAuthClientID()
	clientSecret := s.slackOAuthClientSecret()
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("Slack OAuth credentials missing")
	}

	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("client_secret", clientSecret)
	q.Set("code", code)
	q.Set("redirect_uri", fmt.Sprintf("http://%s/oauth/callback", host))
	req, err := http.NewRequestWithContext(ctx, "POST", slackEndpoint(slackTokenURL), strings.NewReader(q.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build oauth.v2.access: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth.v2.access http: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		OK          bool   `json:"ok"`
		Error       string `json:"error"`
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		BotUserID   string `json:"bot_user_id"`
		Team        struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"team"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("oauth.v2.access decode: %w", err)
	}
	if !out.OK {
		return nil, fmt.Errorf("oauth.v2.access rejected: %s", out.Error)
	}

	scopes := []any{}
	for _, sc := range strings.Split(out.Scope, ",") {
		if sc = strings.TrimSpace(sc); sc != "" {
			scopes = append(scopes, sc)
		}
	}

	cfg := map[string]any{
		"auth_kind":   slackconn.KindOAuth,
		"team_id":     out.Team.ID,
		"team_name":   out.Team.Name,
		"bot_user_id": out.BotUserID,
		"scopes":      scopes,
		"oauth_token": map[string]any{
			"access_token": out.AccessToken,
			"token_type":   out.TokenType,
		},
	}
	return cfg, nil
}
