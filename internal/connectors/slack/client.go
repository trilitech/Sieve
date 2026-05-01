package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
	httpClient *http.Client
	baseURL    string
	token      string

	// onTerminalAuth fires when the classifier flags the response as a
	// terminal-auth failure (token revoked, account deactivated, etc.).
	// The factory wires this to connections.Service.SetStatus(id,
	// "reauth_required") via the `_on_terminal_auth` config callback.
	// Nil-safe: nil means "do nothing" (test-only path).
	onTerminalAuth func()
}

// newClient builds a client from the validated Config plus the
// optional `_base_url` and `_on_terminal_auth` injections. Returns
// an error if the config has no usable bearer token.
func newClient(cfg *Config, baseURL string, onTerminalAuth func()) (*client, error) {
	tok := cfg.accessToken()
	if tok == "" {
		return nil, fmt.Errorf("slack: empty access token")
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	// Normalize: drop a trailing slash so we can concatenate /api/...
	baseURL = strings.TrimRight(baseURL, "/")
	return &client{
		httpClient:     http.DefaultClient,
		baseURL:        baseURL,
		token:          tok,
		onTerminalAuth: onTerminalAuth,
	}, nil
}

// post issues a Slack Web API call. The Slack docs accept either form-
// encoded or JSON bodies; we use form encoding because it matches the
// mock server's parsing path and is what every Slack curl example uses.
//
// On a terminal-auth response, post fires onTerminalAuth (best-effort)
// before returning the structured error. Callers see the same error
// shape regardless — the side effect is the status transition.
func (c *client) post(ctx context.Context, method string, params url.Values) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/"+method, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("slack: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
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
	u := c.baseURL + "/api/" + method
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("slack: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("slack: %s: %w", method, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
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
