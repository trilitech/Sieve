package asana

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/trilitech/Sieve/internal/httpguard"
)

const (
	maxResponseBytes  = 5 << 20 // 5 MiB; matches gitlab/github/notion connectors
	clientTimeoutSecs = 60
	apiPrefix         = "/api/1.0"
)

// httpResponse is the structured wrapper every asana operation returns — both
// the curated ops and the asana_request escape hatch. The agent receives
// {status, headers, body}; Body is the raw upstream JSON (Asana wraps its
// payloads under a "data" key: {data:{...}} for a single object, {data:[...],
// next_page:{...}} for a list). Same envelope shape github/gitlab/notion use,
// so the response filters recognize the list under body.data.
type httpResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
}

// doRequest attaches the Bearer token, runs the request against the configured
// base URL under /api/1.0, and returns the parsed status, selected response
// headers, and raw response body.
//
// `path` must be a '/'-prefixed API path RELATIVE to /api/1.0 (e.g. "/tasks").
// Callers percent-encode embedded gids (the ops.go helpers do this).
func (a *Connector) doRequest(ctx context.Context, method, path string, query url.Values, body any) (*httpResponse, error) {
	if path == "" || path[0] != '/' {
		return nil, fmt.Errorf("asana: path must start with '/', got %q", path)
	}
	if err := validateRelativePath(path); err != nil {
		return nil, err
	}

	target := a.config.BaseURL + apiPrefix + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("asana: marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return nil, err
	}
	// Bearer token from the token source: a static PAT, or a refreshing OAuth
	// token (which may return connector.ErrNeedsReauth if the refresh token is
	// dead). Refreshing here means an expired OAuth token is renewed
	// transparently on the request that needs it.
	tok, err := a.tokenSource.Token()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Sieve-Asana-Connector")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("asana: request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("asana: read response: %w", err)
	}
	if int64(len(raw)) > maxResponseBytes {
		return nil, fmt.Errorf("asana: response exceeded %d byte cap", maxResponseBytes)
	}

	headers := map[string]string{}
	for _, h := range []string{"Content-Type", "Retry-After", "X-RateLimit-Remaining", "X-RateLimit-Reset"} {
		if v := resp.Header.Get(h); v != "" {
			headers[h] = v
		}
	}

	bodyJSON := json.RawMessage(raw)
	if len(raw) == 0 {
		bodyJSON = json.RawMessage("null")
	} else if !json.Valid(raw) {
		bodyJSON, _ = json.Marshal(map[string]any{"raw": string(raw)})
	}

	return &httpResponse{Status: resp.StatusCode, Headers: headers, Body: bodyJSON}, nil
}

// validateRelativePath rejects path traversal, backslashes, and encoded dot
// segments. Mirrors the notion/gitlab hardening. Asana gids are numeric with no
// embedded slashes, so there is no legitimate encoded-slash case to preserve.
func validateRelativePath(p string) error {
	const maxUnescapePasses = 5

	decoded := p
	for i := 0; i < maxUnescapePasses; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil {
			return fmt.Errorf("asana: invalid path encoding: %w", err)
		}
		if next == decoded {
			break
		}
		decoded = next
	}

	lower := strings.ToLower(decoded)
	if strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return errors.New("asana: path contains dangerous encoded sequences")
	}
	if strings.Contains(decoded, "\\") {
		return errors.New("asana: backslash in path")
	}
	for i, seg := range strings.Split(decoded, "/") {
		if seg == ".." {
			return errors.New("asana: '..' segment in path")
		}
		if seg == "" && i != 0 {
			return errors.New("asana: empty path segment")
		}
	}
	return nil
}

// newHTTPClient returns the connector's http.Client, wrapped by httpguard so
// dial-time SSRF protection applies on the first request and every redirect.
func newHTTPClient(allowlist []netip.Prefix) *http.Client {
	return httpguard.Client(httpguard.ClientOptions{
		Allowlist: allowlist,
		Timeout:   clientTimeoutSecs * time.Second,
	})
}
