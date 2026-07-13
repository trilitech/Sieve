package web

import (
	"context"
	"crypto/rand"
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

// Asana OAuth (confidential, BYO app).
//
// Standard OAuth2 authorization-code flow with client_id/client_secret. Unlike
// Notion, Asana access tokens EXPIRE (~1h) and come with a refresh token, so
// the exchange stores the full token bundle (access + refresh + expiry) PLUS
// the client credentials the connector needs to refresh it at execute time
// (see the asana connector's persistingTokenSource). A pasted PAT never
// expires and is stored in api_key instead.
const (
	asanaAuthorizeURL = "https://app.asana.com/-/oauth_authorize"
	asanaTokenURL     = "https://app.asana.com/-/oauth_token"
	asanaMeURL        = "https://app.asana.com/api/1.0/users/me"
)

// asanaOAuthEndpointOverride lets tests point Asana OAuth at a mock server.
var asanaOAuthEndpointOverride string

func asanaEndpoint(production string) string {
	if asanaOAuthEndpointOverride == "" {
		return production
	}
	return strings.Replace(production, "https://app.asana.com", strings.TrimRight(asanaOAuthEndpointOverride, "/"), 1)
}

var asanaOAuthHTTPClient = httpguard.Client(httpguard.ClientOptions{
	Allowlist: mustParseCIDRs([]string{"127.0.0.0/8", "::1/128"}),
	Timeout:   30 * time.Second,
})

// asanaOAuthCreds resolves the operator's Asana app OAuth credentials: the
// encrypted _oauth_app:asana row first, then the launch-configured client
// (--asana-client-id), then the ASANA_CLIENT_ID / ASANA_CLIENT_SECRET env vars.
func (s *Server) asanaOAuthCreds() (clientID, clientSecret string, err error) {
	creds, err := s.connections.GetOAuthApp("asana")
	if err == nil && creds != nil {
		return creds.ClientID, creds.ClientSecret, nil
	}
	if err != nil {
		return "", "", err
	}
	id := s.oauthClients.AsanaClientID
	if id == "" {
		id = os.Getenv("ASANA_CLIENT_ID")
	}
	secret := s.oauthClients.AsanaClientSecret
	if secret == "" {
		secret = os.Getenv("ASANA_CLIENT_SECRET")
	}
	return id, secret, nil
}

func (s *Server) asanaOAuthIsConfigured() bool {
	id, secret, err := s.asanaOAuthCreds()
	if err != nil {
		return false
	}
	return id != "" && secret != ""
}

func (s *Server) handleAsanaOAuthStart(w http.ResponseWriter, r *http.Request) {
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
	s.beginAsanaOAuth(w, r, id, displayName, false)
}

func (s *Server) handleAsanaReauth(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	conn, err := s.connections.Get(id)
	if err != nil {
		s.writeConnectionError(w, http.StatusNotFound, "connection not found", err)
		return
	}
	if conn.ConnectorType != "asana" {
		http.Error(w, "not an Asana connection", http.StatusBadRequest)
		return
	}
	s.beginAsanaOAuth(w, r, id, conn.DisplayName, true)
}

func (s *Server) beginAsanaOAuth(w http.ResponseWriter, r *http.Request, id, displayName string, isReauth bool) {
	clientID, clientSecret, err := s.asanaOAuthCreds()
	if err != nil {
		if errors.Is(err, secrets.ErrKeyringNotLoaded) {
			http.Error(w, "service locked: passphrase required", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if clientID == "" || clientSecret == "" {
		http.Error(w, "Asana OAuth not configured — paste your Asana app's Client ID and Secret at /connections (the 'Set up Asana OAuth' form), or paste a personal access token", http.StatusBadRequest)
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
		ConnectorType:       "asana",
		DisplayName:         displayName,
		CreatedAt:           time.Now(),
		IsReauth:            isReauth,
		OperatorSessionHash: operatorSessionHash(r),
	}
	s.oauthMu.Unlock()

	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	// redirect_uri comes from oauthRedirectBaseURL (request-derived unless
	// public_base_url is set); Asana validates it matches at token exchange.
	q.Set("redirect_uri", s.oauthRedirectBaseURL(r)+"/oauth/callback")
	q.Set("state", state)
	http.Redirect(w, r, asanaEndpoint(asanaAuthorizeURL)+"?"+q.Encode(), http.StatusFound)
}

func (s *Server) completeAsanaOAuth(w http.ResponseWriter, r *http.Request, pending pendingOAuth, code string) {
	cfg, err := s.asanaOAuthExchange(r.Context(), s.oauthRedirectBaseURL(r), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if exists, _ := s.connections.Exists(pending.ID); exists {
		if err := s.connections.UpdateConfig(pending.ID, cfg); err != nil {
			s.writeConnectionError(w, http.StatusInternalServerError, err.Error(), err)
			return
		}
		if err := s.connections.SetStatus(pending.ID, connections.StatusActive); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := s.connections.Add(pending.ID, "asana", pending.DisplayName, cfg); err != nil {
			s.writeConnectionError(w, http.StatusInternalServerError, err.Error(), err)
			return
		}
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

// asanaOAuthExchange POSTs the authorization code to Asana's token endpoint
// (form-encoded) and returns the connection config with the OAuth token bundle
// plus the client credentials the connector needs to refresh it.
func (s *Server) asanaOAuthExchange(ctx context.Context, baseURL, code string) (map[string]any, error) {
	clientID, clientSecret, err := s.asanaOAuthCreds()
	if err != nil {
		return nil, fmt.Errorf("Asana OAuth credentials: %w", err)
	}
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("Asana OAuth credentials missing")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", strings.TrimRight(baseURL, "/")+"/oauth/callback")
	form.Set("code", code)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, asanaEndpoint(asanaTokenURL), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := asanaOAuthHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Asana token exchange http: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("Asana token exchange decode failed (status %d)", resp.StatusCode)
	}
	if out.AccessToken == "" {
		msg := strings.TrimSpace(out.Error + " " + out.ErrorDesc)
		if msg == "" {
			msg = fmt.Sprintf("no access_token in response (status %d)", resp.StatusCode)
		}
		return nil, fmt.Errorf("Asana token exchange failed: %s", msg)
	}

	oauthToken := map[string]any{
		"access_token": out.AccessToken,
		"token_type":   out.TokenType,
	}
	if out.RefreshToken != "" {
		oauthToken["refresh_token"] = out.RefreshToken
	}
	if out.ExpiresIn > 0 {
		oauthToken["expiry"] = time.Now().UTC().Add(time.Duration(out.ExpiresIn) * time.Second).Format(time.RFC3339)
	}
	return map[string]any{
		"oauth_token":   oauthToken,
		"client_id":     clientID,
		"client_secret": clientSecret,
	}, nil
}

// handleAsanaToken is the paste-a-token fallback (a Personal Access Token).
func (s *Server) handleAsanaToken(w http.ResponseWriter, r *http.Request) {
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
	if err := asanaValidateToken(r.Context(), token); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.connections.Add(id, "asana", displayName, map[string]any{"api_key": token}); err != nil {
		s.writeConnectionError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

func asanaValidateToken(ctx context.Context, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asanaEndpoint(asanaMeURL), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := asanaOAuthHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("Asana token check failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("Asana rejected the token (status %d) — check it's a valid personal access token", resp.StatusCode)
	}
	return nil
}

func (s *Server) handleAsanaOAuthConfigure(w http.ResponseWriter, r *http.Request) {
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
	if err := s.connections.PutOAuthApp("asana", connections.OAuthAppCredentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}); err != nil {
		s.writeConnectionError(w, http.StatusInternalServerError, "save Asana OAuth credentials: "+err.Error(), err)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

func (s *Server) handleAsanaOAuthClearConfig(w http.ResponseWriter, r *http.Request) {
	if err := s.connections.DeleteOAuthApp("asana"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}
