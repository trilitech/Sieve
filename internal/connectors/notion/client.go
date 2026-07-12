package notion

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
	maxResponseBytes  = 5 << 20 // 5 MiB; matches gitlab/github/linear connectors
	clientTimeoutSecs = 60
	apiPrefix         = "/v1"
	// notionVersion is the API version pinned in the required Notion-Version
	// header. Notion is version-gated: omitting or sending an unknown version
	// is rejected. Bump deliberately after checking the changelog — response
	// shapes can change across versions.
	notionVersion = "2022-06-28"
)

// httpResponse is the structured wrapper every notion operation returns — both
// the curated ops (which pass doRequest's result through verbatim) and the
// notion_request escape hatch. The agent receives {status, headers, body};
// Body is the raw upstream JSON (or a {"raw": "..."} wrapper for a non-JSON
// payload). This is the same envelope shape github/gitlab use, so the response
// filters (redact/exclude) recognize Notion's list results under body.results.
type httpResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
}

// doRequest attaches the Bearer token + Notion-Version header, runs the request
// against the configured base URL under /v1, and returns the parsed status,
// selected response headers, and raw response body.
//
// `path` must be a '/'-prefixed API path RELATIVE to /v1 (e.g. "/pages/<id>").
// Callers percent-encode embedded identifiers (the ops.go helpers do this).
func (n *Connector) doRequest(ctx context.Context, method, path string, query url.Values, body any) (*httpResponse, error) {
	if path == "" || path[0] != '/' {
		return nil, fmt.Errorf("notion: path must start with '/', got %q", path)
	}
	if err := validateRelativePath(path); err != nil {
		return nil, err
	}

	target := n.config.BaseURL + apiPrefix + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("notion: marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+n.config.APIKey)
	req.Header.Set("Notion-Version", notionVersion)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Sieve-Notion-Connector")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("notion: request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("notion: read response: %w", err)
	}
	if int64(len(raw)) > maxResponseBytes {
		return nil, fmt.Errorf("notion: response exceeded %d byte cap", maxResponseBytes)
	}

	headers := map[string]string{}
	for _, h := range []string{"Content-Type", "Retry-After"} {
		if v := resp.Header.Get(h); v != "" {
			headers[h] = v
		}
	}

	bodyJSON := json.RawMessage(raw)
	if len(raw) == 0 {
		bodyJSON = json.RawMessage("null")
	} else if !json.Valid(raw) {
		// Non-JSON upstream (CDN error pages, 502s). Wrap so the escape hatch
		// still hands back something structured.
		bodyJSON, _ = json.Marshal(map[string]any{"raw": string(raw)})
	}

	return &httpResponse{Status: resp.StatusCode, Headers: headers, Body: bodyJSON}, nil
}

// validateRelativePath rejects path traversal, backslashes, and encoded dot
// segments. Mirrors the gitlab/github hardening: iteratively percent-decode
// (bounded) until stable, then reject dangerous sequences and ".." segments.
// Notion resource ids are UUIDs (hex + dashes) with no embedded slashes, so —
// unlike gitlab — there is no legitimate encoded-slash case to preserve.
func validateRelativePath(p string) error {
	const maxUnescapePasses = 5

	decoded := p
	for i := 0; i < maxUnescapePasses; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil {
			return fmt.Errorf("notion: invalid path encoding: %w", err)
		}
		if next == decoded {
			break
		}
		decoded = next
	}

	lower := strings.ToLower(decoded)
	if strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return errors.New("notion: path contains dangerous encoded sequences")
	}
	if strings.Contains(decoded, "\\") {
		return errors.New("notion: backslash in path")
	}
	for i, seg := range strings.Split(decoded, "/") {
		if seg == ".." {
			return errors.New("notion: '..' segment in path")
		}
		if seg == "" && i != 0 {
			return errors.New("notion: empty path segment")
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
