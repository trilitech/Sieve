package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/trilitech/Sieve/internal/connector"
)

// buildTokenSource selects the right oauth2.TokenSource for a Slack config:
//
//   - KindUserOAuth with a refresh_token (Slack Token Rotation enabled) →
//     a refreshingTokenSource that renews the short-lived user access token
//     via oauth.v2.access?grant_type=refresh_token and persists the rotated
//     pair through the _on_token_refresh callback.
//   - everything else (bot tokens, non-rotating user tokens) → a static
//     source, identical to the pre-existing behavior.
//
// client_id/client_secret + the lifecycle callbacks are read from the raw
// config map, which the web OAuth-callback layer populates for user installs
// (mirroring how the Gmail connector receives its client credentials).
func buildTokenSource(cfg *Config, baseURL string, raw map[string]any) (oauth2.TokenSource, error) {
	access := cfg.accessToken()
	if access == "" {
		return nil, fmt.Errorf("slack: empty access token")
	}
	if cfg.AuthKind == KindUserOAuth && cfg.refreshToken() != "" {
		clientID, _ := raw["client_id"].(string)
		clientSecret, _ := raw["client_secret"].(string)
		if clientID == "" || clientSecret == "" {
			// Without app credentials we cannot refresh. Fall back to static
			// so reads keep working until the token expires, at which point
			// the live-call terminal-auth path flips the connection to
			// reauth_required.
			return oauth2.StaticTokenSource(cfg.oauth2Token()), nil
		}
		onRefresh, _ := raw["_on_token_refresh"].(func(*oauth2.Token))
		onRefreshFailure, _ := raw["_on_token_refresh_failure"].(func(string))
		return &refreshingTokenSource{
			cur:              cfg.oauth2Token(),
			baseURL:          baseURL,
			httpClient:       http.DefaultClient,
			clientID:         clientID,
			clientSecret:     clientSecret,
			onRefresh:        onRefresh,
			onRefreshFailure: onRefreshFailure,
		}, nil
	}
	return oauth2.StaticTokenSource(cfg.oauth2Token()), nil
}

// refreshingTokenSource renews a rotating Slack user token. Slack's refresh
// endpoint is oauth.v2.access with grant_type=refresh_token; its response is
// the Slack envelope (HTTP 200 + {"ok":bool}), NOT a standard OAuth2 token
// response, so we cannot reuse oauth2.Config.TokenSource (it mis-parses the
// body). This source POSTs the refresh, validates `ok`, maps terminal Slack
// error codes onto the reauth path, and persists the rotated pair.
type refreshingTokenSource struct {
	mu  sync.Mutex
	cur *oauth2.Token

	baseURL      string
	httpClient   *http.Client
	clientID     string
	clientSecret string

	onRefresh        func(*oauth2.Token)
	onRefreshFailure func(string)
}

// Token returns a valid access token, refreshing lazily when the current one
// has expired (or is within oauth2's default expiry delta). On a terminal
// refresh failure it fires onRefreshFailure and returns connector.ErrNeedsReauth
// so the API/MCP layers surface the re-auth contract; transient failures are
// returned as-is (no status change) and retried on the next call.
func (s *refreshingTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cur.Valid() {
		return s.cur, nil
	}

	tok, terminal, err := s.refresh()
	if err != nil {
		if terminal {
			if s.onRefreshFailure != nil {
				s.onRefreshFailure(err.Error())
			}
			return nil, fmt.Errorf("%w: %v", connector.ErrNeedsReauth, err)
		}
		return nil, err
	}
	s.cur = tok
	if s.onRefresh != nil {
		s.onRefresh(tok)
	}
	return tok, nil
}

// refresh performs the oauth.v2.access?grant_type=refresh_token round trip.
// Returns (token, terminal, err): terminal=true means the refresh token is
// dead and re-authentication is required.
func (s *refreshingTokenSource) refresh() (*oauth2.Token, bool, error) {
	v := url.Values{}
	v.Set("grant_type", "refresh_token")
	v.Set("refresh_token", s.cur.RefreshToken)
	v.Set("client_id", s.clientID)
	v.Set("client_secret", s.clientSecret)

	endpoint := strings.TrimRight(s.baseURL, "/") + "/api/oauth.v2.access"
	req, err := http.NewRequestWithContext(context.Background(), "POST", endpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, false, fmt.Errorf("slack: build refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("slack: refresh http: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// HTTP 401 on refresh is Slack's terminal signal for a dead refresh token.
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, true, fmt.Errorf("slack: refresh rejected (http 401)")
	}

	var out struct {
		OK           bool   `json:"ok"`
		Error        string `json:"error"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		// Slack may nest the rotated user token under authed_user on some
		// responses; accept either shape.
		AuthedUser struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int    `json:"expires_in"`
		} `json:"authed_user"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, false, fmt.Errorf("slack: decode refresh response: %w", err)
	}
	if !out.OK {
		if terminalAuthErrors[out.Error] {
			return nil, true, fmt.Errorf("slack: refresh failed: %s", out.Error)
		}
		return nil, false, fmt.Errorf("slack: refresh failed: %s", out.Error)
	}

	access, refresh, tokType, expiresIn := out.AccessToken, out.RefreshToken, out.TokenType, out.ExpiresIn
	if access == "" && out.AuthedUser.AccessToken != "" {
		access, refresh, tokType, expiresIn = out.AuthedUser.AccessToken, out.AuthedUser.RefreshToken, out.AuthedUser.TokenType, out.AuthedUser.ExpiresIn
	}
	if access == "" {
		return nil, true, fmt.Errorf("slack: refresh response missing access_token")
	}

	tok := &oauth2.Token{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    tokType,
	}
	if refresh == "" {
		// Slack returns a fresh refresh token on each rotation; if absent,
		// keep the prior one so the next refresh still has a credential.
		tok.RefreshToken = s.cur.RefreshToken
	}
	if expiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
	return tok, false, nil
}
