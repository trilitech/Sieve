package gitlab

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
	maxResponseBytes  = 5 << 20 // 5 MiB; matches LLM evaluator + github cap
	clientTimeoutSecs = 60
	apiPrefix         = "/api/v4"
)

// httpResponse is the structured form returned to agents by both curated
// ops (after they unmarshal) and the gitlab_request escape hatch.
type httpResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
}

// doRequest attaches the PRIVATE-TOKEN header, runs the request against
// the configured base URL, and returns the parsed status, response
// headers (filtered), and raw response body.
//
// `path` must be an absolute /api/v4-relative API path beginning with
// '/'. The caller is responsible for percent-encoding embedded
// identifiers (the helpers in ops.go do this for project paths).
func (g *Connector) doRequest(ctx context.Context, method, path string, query url.Values, body any) (*httpResponse, error) {
	if path == "" || path[0] != '/' {
		return nil, fmt.Errorf("gitlab: path must start with '/', got %q", path)
	}
	if err := validateRelativePath(path); err != nil {
		return nil, err
	}

	target := g.config.BaseURL + apiPrefix + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("gitlab: marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return nil, err
	}
	// GitLab accepts PATs via PRIVATE-TOKEN (recommended for PATs) or
	// Authorization: Bearer (for OAuth2 tokens). PRIVATE-TOKEN is the
	// canonical PAT header and is unambiguous in the audit log.
	req.Header.Set("PRIVATE-TOKEN", g.config.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Sieve-GitLab-Connector")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gitlab: request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("gitlab: read response: %w", err)
	}
	if int64(len(raw)) > maxResponseBytes {
		return nil, fmt.Errorf("gitlab: response exceeded %d byte cap", maxResponseBytes)
	}

	headers := map[string]string{}
	for _, h := range []string{
		"Content-Type",
		"Link",
		"RateLimit-Remaining",
		"RateLimit-Reset",
		"X-Next-Page",
		"X-Page",
		"X-Per-Page",
		"X-Total",
		"X-Total-Pages",
	} {
		if v := resp.Header.Get(h); v != "" {
			headers[h] = v
		}
	}

	bodyJSON := json.RawMessage(raw)
	if len(raw) == 0 {
		bodyJSON = json.RawMessage("null")
	} else if !json.Valid(raw) {
		// GitLab's /repository/files/.../raw endpoint returns the raw
		// file bytes rather than JSON. Wrap so the escape hatch can
		// still hand back something structured.
		bodyJSON, _ = json.Marshal(map[string]any{"raw": string(raw)})
	}

	return &httpResponse{Status: resp.StatusCode, Headers: headers, Body: bodyJSON}, nil
}

// validateRelativePath rejects path traversal, backslashes, and encoded
// dot segments. Mirrors the hardening in github.validateRelativePath:
// iteratively percent-decodes the path (up to maxUnescapePasses times)
// until stable, then checks for dangerous sequences and ".." segments.
// Defends against double-encoded traversal like "%252e%252e%252f".
//
// GitLab's API uses URL-encoded `namespace/project` identifiers inside
// path segments (e.g. /projects/group%2Fproject/...), so the encoded
// '%2F' for embedded slashes is legitimate. The check here works on the
// FULLY decoded path; well-formed encoded slashes inside path segments
// flatten to literal '/', which is then validated as ordinary path
// structure. The validator catches the dangerous patterns regardless.
func validateRelativePath(p string) error {
	const maxUnescapePasses = 5

	decoded := p
	for i := 0; i < maxUnescapePasses; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil {
			return fmt.Errorf("gitlab: invalid path encoding: %w", err)
		}
		if next == decoded {
			break
		}
		decoded = next
	}

	// After iterative decoding, reject any remaining dangerous
	// percent-encoded sequences. These would only survive if the
	// input contained encoding depth beyond maxUnescapePasses, which
	// we treat as invalid.
	//
	// %2f is included alongside %2e and %5c (matching the github
	// connector's hardening). Legitimate single-pass %2f use — the
	// embedded-slash encoding inside project identifiers and file
	// paths constructed by encodeProject / encodeRefOrPath — fully
	// decodes in one iteration and does NOT carry %2f into the
	// `decoded` string we test here. Only a maliciously over-encoded
	// input survives with %2f intact.
	lower := strings.ToLower(decoded)
	if strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return errors.New("gitlab: path contains dangerous encoded sequences")
	}

	if strings.Contains(decoded, "\\") {
		return errors.New("gitlab: backslash in path")
	}
	segs := strings.Split(decoded, "/")
	for i, seg := range segs {
		if seg == ".." {
			return errors.New("gitlab: '..' segment in path")
		}
		if seg == "" && i != 0 {
			return errors.New("gitlab: empty path segment")
		}
	}
	return nil
}

// newHTTPClient returns the http.Client used by the connector. Redirects
// are disabled — GitLab API endpoints don't redirect outside expected
// download URLs (which the caller would fetch separately).
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: clientTimeoutSecs * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
