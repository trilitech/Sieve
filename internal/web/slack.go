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

// slackOAuthClientID and slackOAuthClientSecret read the operator's
// Slack OAuth app credentials from environment. Per spec FR
// "OAuth app credentials live in the operator's config surface, not
// the keyring", env vars are an acceptable surface for non-secret
// (client_id) and lower-sensitivity-than-passphrase (client_secret)
// values. The keyring passphrase is the strict env-var-forbidden
// case (Constitution Principle I).
//
// If credentials are absent, the OAuth path is unavailable — the UI
// surfaces the token-entry path only. This matches the existing
// pattern for the Google connector which is similarly optional.
func slackOAuthClientID() string {
	return os.Getenv("SLACK_CLIENT_ID")
}

func slackOAuthClientSecret() string {
	return os.Getenv("SLACK_CLIENT_SECRET")
}

// handleSlackOAuthStart kicks off the Slack OAuth v2 install flow.
// Adapter shape mirrors handleConnectionAdd's "google" branch: stash
// pending state with TTL, redirect to Slack with the random state.
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
	clientID := slackOAuthClientID()
	if clientID == "" {
		http.Error(w, "Slack OAuth not configured (set SLACK_CLIENT_ID/SLACK_CLIENT_SECRET in the environment, or use the bot-token entry path)", http.StatusBadRequest)
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
	// OAuth-path reauth: stash and redirect.
	r.Form.Set("id", id)
	r.Form.Set("display_name", existing.DisplayName)
	s.handleSlackOAuthStart(w, r)
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

// completeSlackOAuth handles the post-callback completion for Slack
// installs (both fresh-add and reauth flows). Called from
// handleOAuthCallback after state validation. Persists via Add for a
// new install or via UpdateConfig+SetStatus(active) for a reauth.
func (s *Server) completeSlackOAuth(w http.ResponseWriter, r *http.Request, pending pendingOAuth, code string) {
	cfg, err := slackOAuthExchange(r.Context(), r.Host, code)
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
func slackOAuthExchange(ctx context.Context, host, code string) (map[string]any, error) {
	clientID := slackOAuthClientID()
	clientSecret := slackOAuthClientSecret()
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
