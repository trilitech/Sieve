package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/httpguard"
	"github.com/trilitech/Sieve/internal/secrets"
)

// Notion OAuth (confidential, BYO public-integration).
//
// Notion's OAuth token endpoint requires the client_secret (HTTP Basic
// client_id:client_secret) — there is no PKCE public-client option — so this
// mirrors Sieve's Slack *bot* OAuth, not the PKCE path from #37. Crucially, a
// Notion OAuth "bot" access token is used IDENTICALLY to a pasted internal
// integration token (Authorization: Bearer <token>) and never expires / has no
// refresh token. So the flow simply stores the resulting token in the
// connector's api_key field — the connector itself is unchanged. The workspace
// id/name from the exchange are stored so a reauth can enforce workspace
// continuity (the same guard as the Slack team_id repoint fix).
const (
	notionAuthorizeURL = "https://api.notion.com/v1/oauth/authorize"
	notionTokenURL     = "https://api.notion.com/v1/oauth/token"
	notionUsersMeURL   = "https://api.notion.com/v1/users/me"
	notionAPIVersion   = "2022-06-28"
)

// notionOAuthEndpointOverride lets tests point Notion OAuth at a mock server.
// When non-empty, the api.notion.com host in the URLs above is rewritten to it.
var notionOAuthEndpointOverride string

func notionEndpoint(production string) string {
	if notionOAuthEndpointOverride == "" {
		return production
	}
	return strings.Replace(production, "https://api.notion.com", strings.TrimRight(notionOAuthEndpointOverride, "/"), 1)
}

// notionOAuthHTTPClient is the SSRF-guarded client for the token exchange +
// token validation. Loopback is allowlisted so tests can point at a
// 127.0.0.1 httptest server; production reaches api.notion.com (public).
var notionOAuthHTTPClient = httpguard.Client(httpguard.ClientOptions{
	Allowlist: mustParseCIDRs([]string{"127.0.0.0/8", "::1/128"}),
	Timeout:   30 * time.Second,
})

// notionOAuthCreds resolves the operator's Notion public-integration OAuth
// credentials: the encrypted _oauth_app:notion row first, then the
// launch-configured client (--notion-client-id, via SetOAuthClients), then the
// NOTION_CLIENT_ID / NOTION_CLIENT_SECRET env vars. Returns
// secrets.ErrKeyringNotLoaded when a stored row exists but the keyring is
// locked (callers map it to 503).
func (s *Server) notionOAuthCreds() (clientID, clientSecret string, err error) {
	creds, err := s.connections.GetOAuthApp("notion")
	if err == nil && creds != nil {
		return creds.ClientID, creds.ClientSecret, nil
	}
	if err != nil {
		// Real error (including keyring-locked) — surface; don't silently fall
		// back to env when a stored row is present but undecryptable.
		return "", "", err
	}
	id := s.oauthClients.NotionClientID
	if id == "" {
		id = os.Getenv("NOTION_CLIENT_ID")
	}
	secret := s.oauthClients.NotionClientSecret
	if secret == "" {
		secret = os.Getenv("NOTION_CLIENT_SECRET")
	}
	return id, secret, nil
}

// notionOAuthIsConfigured reports whether BOTH client_id and client_secret are
// resolvable (Notion's token exchange is confidential — it needs the secret).
// Drives the connections card (install button vs configure form). Returns
// false when the keyring is locked (operator sees the configure form, which
// 503s on submit until unlocked).
func (s *Server) notionOAuthIsConfigured() bool {
	id, secret, err := s.notionOAuthCreds()
	if err != nil {
		return false
	}
	return id != "" && secret != ""
}

// handleNotionOAuthStart kicks off a fresh Notion OAuth install.
func (s *Server) handleNotionOAuthStart(w http.ResponseWriter, r *http.Request) {
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
	s.beginNotionOAuth(w, r, id, displayName, false)
}

// handleNotionReauth restarts the OAuth flow for an existing connection (e.g.
// after the operator revoked the integration in Notion). completeNotionOAuth
// enforces workspace continuity on the way back.
func (s *Server) handleNotionReauth(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	conn, err := s.connections.Get(id)
	if err != nil {
		s.writeConnectionError(w, http.StatusNotFound, "connection not found", err)
		return
	}
	if conn.ConnectorType != "notion" {
		http.Error(w, "not a Notion connection", http.StatusBadRequest)
		return
	}
	s.beginNotionOAuth(w, r, id, conn.DisplayName, true)
}

func (s *Server) beginNotionOAuth(w http.ResponseWriter, r *http.Request, id, displayName string, isReauth bool) {
	clientID, clientSecret, err := s.notionOAuthCreds()
	if err != nil {
		if errors.Is(err, secrets.ErrKeyringNotLoaded) {
			http.Error(w, "service locked: passphrase required", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if clientID == "" || clientSecret == "" {
		http.Error(w, "Notion OAuth not configured — paste your Notion integration's Client ID and Secret at /connections (the 'Set up Notion OAuth' form), or paste an integration token", http.StatusBadRequest)
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
		ConnectorType:       "notion",
		DisplayName:         displayName,
		CreatedAt:           time.Now(),
		IsReauth:            isReauth,
		OperatorSessionHash: operatorSessionHash(r),
	}
	s.oauthMu.Unlock()

	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("owner", "user")
	// redirect_uri comes from oauthRedirectBaseURL (request-derived unless
	// public_base_url is set) so it matches however the operator reached the
	// admin UI. Notion validates that the value presented at token exchange
	// equals this one; completeNotionOAuth derives it the same way. Safe
	// because Notion only redirects to a redirect_uri pre-registered on the
	// integration. See oauthRedirectBaseURL.
	q.Set("redirect_uri", s.oauthRedirectBaseURL(r)+"/oauth/callback")
	q.Set("state", state)
	http.Redirect(w, r, notionEndpoint(notionAuthorizeURL)+"?"+q.Encode(), http.StatusFound)
}

// completeNotionOAuth runs after handleOAuthCallback validates state/session.
// Exchanges the code for a bot token and persists it (Add for a fresh install,
// UpdateConfig+active for a reauth, with workspace continuity enforced).
func (s *Server) completeNotionOAuth(w http.ResponseWriter, r *http.Request, pending pendingOAuth, code string) {
	cfg, err := s.notionOAuthExchange(r.Context(), s.oauthRedirectBaseURL(r), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if exists, _ := s.connections.Exists(pending.ID); exists {
		full, ferr := s.connections.GetWithConfig(pending.ID)
		if ferr != nil {
			s.writeConnectionError(w, http.StatusInternalServerError, ferr.Error(), ferr)
			return
		}
		storedWS, _ := full.Config["workspace_id"].(string)
		newWS, _ := cfg["workspace_id"].(string)
		if storedWS != "" && newWS != "" && newWS != storedWS {
			http.Error(w, fmt.Sprintf("token is for a different Notion workspace (%s, expected %s); reauth must stay on the same workspace", newWS, storedWS), http.StatusBadRequest)
			return
		}
		if err := s.connections.UpdateConfig(pending.ID, cfg); err != nil {
			s.writeConnectionError(w, http.StatusInternalServerError, err.Error(), err)
			return
		}
		if err := s.connections.SetStatus(pending.ID, connections.StatusActive); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := s.connections.Add(pending.ID, "notion", pending.DisplayName, cfg); err != nil {
			s.writeConnectionError(w, http.StatusInternalServerError, err.Error(), err)
			return
		}
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// notionOAuthExchange POSTs the authorization code to Notion's token endpoint
// (HTTP Basic client_id:client_secret) and returns the connection config
// {api_key: <bot token>, workspace_id, workspace_name}.
func (s *Server) notionOAuthExchange(ctx context.Context, baseURL, code string) (map[string]any, error) {
	clientID, clientSecret, err := s.notionOAuthCreds()
	if err != nil {
		return nil, fmt.Errorf("Notion OAuth credentials: %w", err)
	}
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("Notion OAuth credentials missing")
	}

	payload, _ := json.Marshal(map[string]any{
		"grant_type":   "authorization_code",
		"code":         code,
		"redirect_uri": strings.TrimRight(baseURL, "/") + "/oauth/callback",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, notionEndpoint(notionTokenURL), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	basic := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	req.Header.Set("Authorization", "Basic "+basic)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Notion-Version", notionAPIVersion)

	resp, err := notionOAuthHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Notion token exchange http: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var out struct {
		AccessToken   string `json:"access_token"`
		TokenType     string `json:"token_type"`
		WorkspaceID   string `json:"workspace_id"`
		WorkspaceName string `json:"workspace_name"`
		Error         string `json:"error"`
		ErrorDesc     string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("Notion token exchange decode failed (status %d)", resp.StatusCode)
	}
	if out.AccessToken == "" {
		msg := strings.TrimSpace(out.Error + " " + out.ErrorDesc)
		if msg == "" {
			msg = fmt.Sprintf("no access_token in response (status %d)", resp.StatusCode)
		}
		return nil, fmt.Errorf("Notion token exchange failed: %s", msg)
	}

	cfg := map[string]any{"api_key": out.AccessToken}
	if out.WorkspaceID != "" {
		cfg["workspace_id"] = out.WorkspaceID
	}
	if out.WorkspaceName != "" {
		cfg["workspace_name"] = out.WorkspaceName
	}
	return cfg, nil
}

// handleNotionToken is the paste-a-token fallback: the operator supplies an
// integration token (internal, or an OAuth bot token obtained elsewhere). We
// validate it against GET /v1/users/me and persist.
func (s *Server) handleNotionToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	token := strings.TrimSpace(r.FormValue("token"))
	if id == "" || displayName == "" || token == "" {
		http.Error(w, "id, display_name, and token are required", http.StatusBadRequest)
		return
	}
	if exists, _ := s.connections.Exists(id); exists {
		http.Error(w, fmt.Sprintf("connection %q already exists", id), http.StatusBadRequest)
		return
	}
	if err := notionValidateToken(r.Context(), token); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.connections.Add(id, "notion", displayName, map[string]any{"api_key": token}); err != nil {
		s.writeConnectionError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// notionValidateToken checks a token against GET /v1/users/me. 401/403 → reject.
func notionValidateToken(ctx context.Context, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, notionEndpoint(notionUsersMeURL), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Notion-Version", notionAPIVersion)
	resp, err := notionOAuthHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("Notion token check failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("Notion rejected the token (status %d) — check it's a valid integration token", resp.StatusCode)
	}
	return nil
}

// handleNotionOAuthConfigure persists the operator's Notion public-integration
// client credentials (encrypted _oauth_app:notion row).
func (s *Server) handleNotionOAuthConfigure(w http.ResponseWriter, r *http.Request) {
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
	if err := s.connections.PutOAuthApp("notion", connections.OAuthAppCredentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}); err != nil {
		s.writeConnectionError(w, http.StatusInternalServerError, "save Notion OAuth credentials: "+err.Error(), err)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// handleNotionOAuthClearConfig wipes the persisted Notion OAuth app credentials.
func (s *Server) handleNotionOAuthClearConfig(w http.ResponseWriter, r *http.Request) {
	if err := s.connections.DeleteOAuthApp("notion"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}
