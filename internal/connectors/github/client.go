package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultAPIBase    = "https://api.github.com"
	maxResponseBytes  = 5 << 20 // 5 MiB; matches LLM evaluator cap
	clientTimeoutSecs = 60
)

// httpResponse is the structured form returned to agents by both curated ops
// (after they unmarshal) and the github_request escape hatch.
type httpResponse struct {
	Status  int             `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage `json:"body"`
}

// doRequest routes a request through the auth router, picks the right
// credential, attaches the bearer, and executes against api.github.com.
// `path` must be an absolute API path (e.g. /repos/{owner}/{repo}/issues).
// `body` is JSON-marshalled if non-nil. Returns the parsed status, response
// headers (filtered), and raw response body.
func (g *Connector) doRequest(ctx context.Context, method, path string, query url.Values, body any) (*httpResponse, error) {
	if path == "" || path[0] != '/' {
		return nil, fmt.Errorf("github: path must start with '/', got %q", path)
	}
	if err := validateRelativePath(path); err != nil {
		return nil, err
	}

	owner := extractOwner(path)
	cred, err := g.config.pickCredential(owner)
	if err != nil {
		return nil, err
	}

	bearer, err := g.bearerFor(ctx, cred)
	if err != nil {
		return nil, err
	}

	target := g.apiBase + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("github: marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "Sieve-GitHub-Connector")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("github: read response: %w", err)
	}
	if int64(len(raw)) > maxResponseBytes {
		return nil, fmt.Errorf("github: response exceeded %d byte cap", maxResponseBytes)
	}

	headers := map[string]string{}
	for _, h := range []string{"Content-Type", "Link", "X-RateLimit-Remaining", "X-RateLimit-Reset"} {
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

// bearerFor returns the bearer token to attach for the given credential. PATs
// are returned verbatim; App credentials are minted/refreshed via the cache.
func (g *Connector) bearerFor(ctx context.Context, cred *Credential) (string, error) {
	switch cred.Kind {
	case KindFPAT:
		return cred.Token, nil
	case KindAppInstallation:
		return g.appTokens.installationToken(ctx, cred)
	default:
		return "", fmt.Errorf("github: unknown credential kind %q", cred.Kind)
	}
}

// validateRelativePath rejects path traversal, backslashes, and encoded dot
// segments. It iteratively percent-decodes the path (up to maxUnescapePasses
// times) until stable, then checks for dangerous sequences and ".." segments.
// This mirrors the hardening pattern in httpproxy.validateProxyPath, including
// defence against double-encoded traversal like "%252e%252e%252f".
func validateRelativePath(p string) error {
	// 5 passes collapses any realistic multi-layer encoding while bounding cost.
	// e.g. "%252e" requires 2 passes: "%252e" → "%2e" → ".".
	const maxUnescapePasses = 5

	decoded := p
	for i := 0; i < maxUnescapePasses; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil {
			return fmt.Errorf("github: invalid path encoding: %w", err)
		}
		if next == decoded {
			break
		}
		decoded = next
	}

	// After iterative decoding, reject any remaining dangerous percent-encoded
	// sequences. These would only survive if the input contained a staggering
	// depth of nesting beyond maxUnescapePasses, which we treat as invalid.
	lower := strings.ToLower(decoded)
	if strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return errors.New("github: path contains dangerous encoded sequences")
	}

	if strings.Contains(decoded, "\\") {
		return errors.New("github: backslash in path")
	}
	segs := strings.Split(decoded, "/")
	for i, seg := range segs {
		if seg == ".." {
			return errors.New("github: '..' segment in path")
		}
		// Reject empty interior segments (consecutive '//'). The leading '/'
		// produces an empty segs[0], which is expected and ignored.
		if seg == "" && i != 0 {
			return errors.New("github: empty path segment")
		}
	}
	return nil
}

// newHTTPClient returns the http.Client used by the connector. Redirects are
// disabled — GitHub APIs don't redirect outside expected pre-signed download
// URLs that the caller is expected to fetch separately.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: clientTimeoutSecs * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// NewHardenedClient returns an http.Client with the same hardening the
// connector uses internally (no redirects, connection-level timeout). Exposed
// so that out-of-band setup flows (e.g. the web UI's manifest exchange and
// installation lookup) share one client rather than falling back to
// http.DefaultClient.
func NewHardenedClient() *http.Client {
	return newHTTPClient()
}
