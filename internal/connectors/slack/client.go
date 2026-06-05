package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

// defaultBaseURL is the production Slack Web API root. Tests override
// via the `_base_url` config key — the mock server in
// internal/testing/mockslack returns that URL.
const defaultBaseURL = "https://slack.com"

// client is the per-connection Slack HTTP wrapper. One client per
// Connector instance (held by the factory output). It owns the bearer
// token and the terminal-auth callback so each method call doesn't have
// to thread them.
type client struct {
	httpClient  *http.Client
	baseURL     string
	tokenSource oauth2.TokenSource

	// onTerminalAuth fires when the classifier flags the response as a
	// terminal-auth failure (token revoked, account deactivated, etc.).
	// The factory wires this to connections.Service.SetStatus(id,
	// "reauth_required") via the `_on_terminal_auth` config callback.
	// Nil-safe: nil means "do nothing" (test-only path).
	onTerminalAuth func()
}

// newClient builds a client from a resolved token source plus the optional
// `_base_url` and `_on_terminal_auth` injections. The token source is either
// static (bot tokens, non-rotating user tokens) or refreshing (rotating user
// tokens) — see buildTokenSource. Holding a source rather than a fixed string
// means a renewed user token is picked up on the next call automatically.
func newClient(ts oauth2.TokenSource, baseURL string, onTerminalAuth func()) (*client, error) {
	if ts == nil {
		return nil, fmt.Errorf("slack: nil token source")
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	// Normalize: drop a trailing slash so we can concatenate /api/...
	baseURL = strings.TrimRight(baseURL, "/")
	return &client{
		httpClient:     http.DefaultClient,
		baseURL:        baseURL,
		tokenSource:    ts,
		onTerminalAuth: onTerminalAuth,
	}, nil
}

// bearer resolves the current access token from the token source. For a
// rotating user token this may trigger a refresh; a terminal refresh failure
// surfaces here as connector.ErrNeedsReauth, which post/get propagate so the
// API/MCP layers can return the re-auth contract.
func (c *client) bearer() (string, error) {
	tok, err := c.tokenSource.Token()
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

// post issues a Slack Web API call. The Slack docs accept either form-
// encoded or JSON bodies; we use form encoding because it matches the
// mock server's parsing path and is what every Slack curl example uses.
//
// On a terminal-auth response, post fires onTerminalAuth (best-effort)
// before returning the structured error. Callers see the same error
// shape regardless — the side effect is the status transition.
func (c *client) post(ctx context.Context, method string, params url.Values) (map[string]any, error) {
	tok, err := c.bearer()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/"+method, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("slack: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("slack: %s: %w", method, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("slack: read %s response: %w", method, err)
	}

	// Decode twice: once into the typed envelope for the classifier,
	// once into a generic map for callers. The double-decode cost is
	// trivial (response bodies are tens of KB at most) and keeps the
	// classifier's contract narrow.
	var env errorEnvelope
	_ = json.Unmarshal(body, &env)
	if isTerminalAuthError(resp.StatusCode, env) {
		if c.onTerminalAuth != nil {
			c.onTerminalAuth()
		}
		return nil, fmt.Errorf("slack: terminal auth error: %s (http %d)", env.Error, resp.StatusCode)
	}
	if !env.OK {
		return nil, fmt.Errorf("slack: %s failed: %s", method, env.Error)
	}

	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("slack: decode %s response: %w", method, err)
	}
	return out, nil
}

// get is the GET variant for endpoints that don't accept POST.
// Slack permits GET on every Web API method but we use POST for
// writes; only auth.test in this codebase uses GET so far.
func (c *client) get(ctx context.Context, method string, params url.Values) (map[string]any, error) {
	tok, err := c.bearer()
	if err != nil {
		return nil, err
	}
	u := c.baseURL + "/api/" + method
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("slack: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("slack: %s: %w", method, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("slack: read %s response: %w", method, err)
	}
	var env errorEnvelope
	_ = json.Unmarshal(body, &env)
	if isTerminalAuthError(resp.StatusCode, env) {
		if c.onTerminalAuth != nil {
			c.onTerminalAuth()
		}
		return nil, fmt.Errorf("slack: terminal auth error: %s (http %d)", env.Error, resp.StatusCode)
	}
	if !env.OK {
		return nil, fmt.Errorf("slack: %s failed: %s", method, env.Error)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("slack: decode %s response: %w", method, err)
	}
	return out, nil
}
