// Package httpproxy implements a generic HTTP proxy connector for Sieve.
//
// This is the universal connector: it forwards HTTP requests to any API,
// substituting the agent's Sieve token for real credentials. The agent
// never sees the real API key. You can revoke the Sieve token instantly
// without rotating the underlying credential.
//
// The proxy is transparent — it doesn't parse or modify request/response
// bodies. It just handles auth substitution and forwarding. This means it
// works with ANY HTTP API (Anthropic, OpenAI, Gemini, Stripe, Twilio, etc.)
// without provider-specific code.
//
// Connection config:
//
//	{
//	  "target_url": "https://api.anthropic.com",
//	  "auth_header": "x-api-key",
//	  "auth_value": "sk-ant-api03-...",
//	  "allowed_paths": ["/v1/messages", "/v1/models"],  // optional whitelist
//	  "extra_headers": {"anthropic-version": "2023-06-01"}  // optional
//	}
//
// The agent accesses this via: GET/POST http://localhost:19817/proxy/{connection}/{path}
// Sieve strips the Sieve bearer token, injects the real auth, forwards to target.
package httpproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/policy"
)

// ErrHeaderDenied indicates that a request header (agent-supplied via
// params["headers"] on Execute, or arriving on the transparent proxy
// surface) collided with the connector's deny-list. Callers map this to
// audit policy_result "http_proxy.header_denied" and HTTP 400.
var ErrHeaderDenied = errors.New("http_proxy: header denied")

// deniedHeaderKeys is the static set of header keys the connector
// refuses to accept from the agent. Keys are stored lowercased.
// In addition to this set, isDeniedHeader rejects:
//   - any header key starting with "x-forwarded-" (prefix match), and
//   - the connection's configured auth_header (case-insensitive).
//
// The set covers credential-bearing keys (Authorization, Cookie),
// routing keys (Host, X-Forwarded-*), and the RFC 7230 hop-by-hop set.
// It is intentionally not operator-configurable per spec 006 Phase 0
// R-1; per-connection extensions are handled separately via the
// connection's optional additional_denied_headers config field (US4).
var deniedHeaderKeys = map[string]struct{}{
	"authorization":       {},
	"host":                {},
	"cookie":              {},
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailers":            {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

// isDeniedHeader reports whether the given header key is denied for a
// connection whose configured auth_header is authHeaderLower (already
// lowercased by the caller). The returned string is the lowercased
// form of key, useful in error messages.
func isDeniedHeader(key, authHeaderLower string) (bool, string) {
	lower := strings.ToLower(strings.TrimSpace(key))
	if lower == "" {
		return false, lower
	}
	if _, ok := deniedHeaderKeys[lower]; ok {
		return true, lower
	}
	if strings.HasPrefix(lower, "x-forwarded-") {
		return true, lower
	}
	if authHeaderLower != "" && lower == authHeaderLower {
		return true, lower
	}
	return false, lower
}

var Meta = connector.ConnectorMeta{
	Type:        "http_proxy",
	Name:        "HTTP Proxy",
	Description: "Generic HTTP proxy — forward requests to any API with credential substitution",
	Category:    "Generic",
	SetupFields: []connector.Field{
		{Name: "target_url", Label: "Target Base URL", Type: "text", Required: true, Placeholder: "https://api.anthropic.com"},
		{Name: "auth_header", Label: "Auth Header Name", Type: "text", Required: true, Placeholder: "x-api-key"},
		{Name: "auth_value", Label: "Auth Value (real API key)", Type: "password", Required: true, Placeholder: "sk-ant-..."},
	},
}

// ProxyConnector implements connector.Connector for generic HTTP proxying.
// Unlike other connectors, it doesn't define discrete operations — it proxies
// raw HTTP requests. The Execute method receives the HTTP method, path, headers,
// and body as params and returns the proxied response.
type ProxyConnector struct {
	targetURL       string
	authHeader      string
	authHeaderLower string // lowercased once at construction; used by header deny-check
	authValue       string
	authValueScrub  bool // when true (default), upstream response bodies are scrubbed of literal authValue
	extraHeaders    map[string]string
	client          *http.Client
}

func Factory(config map[string]any) (connector.Connector, error) {
	targetURL, _ := config["target_url"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("http_proxy: missing target_url")
	}
	targetURL = strings.TrimRight(targetURL, "/")

	authHeader, _ := config["auth_header"].(string)
	if authHeader == "" {
		return nil, fmt.Errorf("http_proxy: missing auth_header")
	}

	authValue, _ := config["auth_value"].(string)
	if authValue == "" {
		return nil, fmt.Errorf("http_proxy: missing auth_value")
	}
	// Convenience: when the auth header is "Authorization" and the value
	// looks like a bare token (no space, so no scheme prefix), prepend
	// "Bearer ". RFC 7235 requires a scheme; modern bearer-token APIs
	// (Voyage, OpenAI, GitHub PATs over REST, etc.) all expect this form.
	// A user who pasted "Bearer xxx" or "Basic xxx" already has a space
	// and is left untouched, so existing setups don't change.
	if strings.EqualFold(authHeader, "Authorization") && !strings.Contains(authValue, " ") {
		authValue = "Bearer " + authValue
	}

	// auth_value_scrub defaults to true. Operators may opt out per-connection
	// (typically when an external scrubber is in front of Sieve, or when the
	// configured auth_value is a short common word that produces false-positive
	// matches in legitimate response bodies). Missing or non-bool field = true.
	authValueScrub := true
	if v, ok := config["auth_value_scrub"].(bool); ok {
		authValueScrub = v
	}

	// Path restrictions are handled by the policy engine, not the connector.
	// The connector just proxies — what's allowed is a policy decision.

	extraHeaders := make(map[string]string)
	if extra, ok := config["extra_headers"].(map[string]any); ok {
		for k, v := range extra {
			if s, ok := v.(string); ok {
				extraHeaders[k] = s
			}
		}
	}

	return &ProxyConnector{
		targetURL:       targetURL,
		authHeader:      authHeader,
		authHeaderLower: strings.ToLower(strings.TrimSpace(authHeader)),
		authValue:       authValue,
		authValueScrub:  authValueScrub,
		extraHeaders:    extraHeaders,
		client: &http.Client{
			Timeout: 5 * time.Minute,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (p *ProxyConnector) Type() string { return "http_proxy" }

// AuthValueScrubFilter returns the response filter that scrubs the configured
// auth_value (literal-match) from upstream response bodies, or nil when the
// operator has opted out via auth_value_scrub: false. The API router calls
// this to auto-attach the filter to every http_proxy decision so the agent
// never sees the literal credential, even on 4xx/5xx responses where some
// upstreams echo Authorization back.
//
// The filter uses regexp.QuoteMeta so any regex-special characters in the
// configured auth_value (dots in keys, plus signs from base64, etc.) match
// literally rather than as regex.
func (p *ProxyConnector) AuthValueScrubFilter() *policy.ResponseFilter {
	if !p.authValueScrub || p.authValue == "" {
		return nil
	}
	return &policy.ResponseFilter{
		RedactPatterns: []string{regexp.QuoteMeta(p.authValue)},
	}
}

// Operations returns a single "proxy" operation. The real routing happens
// at the HTTP level via the proxy handler in the API router.
func (p *ProxyConnector) Operations() []connector.OperationDef {
	return []connector.OperationDef{
		{
			Name:        "proxy_request",
			Description: "Forward an HTTP request to the target API",
			Params: map[string]connector.ParamDef{
				"method": {Type: "string", Description: "HTTP method", Required: true},
				"path":   {Type: "string", Description: "URL path", Required: true},
				"body":   {Type: "string", Description: "Request body", Required: false},
			},
		},
	}
}

// Execute proxies a single HTTP request. Params must include "method" and "path".
// Optional: "body" (string), "headers" (map[string]string).
func (p *ProxyConnector) Execute(ctx context.Context, op string, params map[string]any) (any, error) {
	method, _ := params["method"].(string)
	path, _ := params["path"].(string)
	if method == "" || path == "" {
		return nil, fmt.Errorf("http_proxy: method and path required")
	}

	// Reject agent-supplied headers that target authorisation or routing
	// BEFORE any upstream contact. The deny-check runs on the params map's
	// "headers" entry only — the operator-configured auth_header / auth_value
	// / extra_headers continue to flow through unchanged.
	if headers, ok := params["headers"].(map[string]any); ok {
		for k := range headers {
			if denied, lower := isDeniedHeader(k, p.authHeaderLower); denied {
				return nil, fmt.Errorf("%w: %q not allowed", ErrHeaderDenied, lower)
			}
		}
	}

	url := p.targetURL + path

	var bodyReader io.Reader
	if body, ok := params["body"].(string); ok && body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("http_proxy: create request: %w", err)
	}

	// Inject real auth credential.
	req.Header.Set(p.authHeader, p.authValue)

	// Inject extra headers (e.g., anthropic-version).
	for k, v := range p.extraHeaders {
		req.Header.Set(k, v)
	}

	// Forward content-type if provided.
	if ct, ok := params["content_type"].(string); ok {
		req.Header.Set("Content-Type", ct)
	} else if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Forward additional headers from params if provided. The deny-check
	// above guarantees no key in this loop is in the deny-set.
	if headers, ok := params["headers"].(map[string]any); ok {
		for k, v := range headers {
			if s, ok := v.(string); ok {
				req.Header.Set(k, s)
			}
		}
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http_proxy: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("http_proxy: read response: %w", err)
	}

	// Scrub the configured auth_value from the response body (curated surface).
	// The transparent ProxyHTTP path uses the auto-attached ResponseFilter from
	// the API router instead; here we apply the same scrub inline because the
	// curated Execute path bypasses handleProxy.
	if p.authValueScrub && p.authValue != "" {
		scrubFilter := policy.ResponseFilter{
			RedactPatterns: []string{regexp.QuoteMeta(p.authValue)},
		}
		scrubbed, _ := policy.ApplyResponseFilters(respBody, []policy.ResponseFilter{scrubFilter})
		respBody = scrubbed
	}

	return map[string]any{
		"status":      resp.StatusCode,
		"status_text": resp.Status,
		"headers":     flattenHeaders(resp.Header),
		"body":        string(respBody),
	}, nil
}

func (p *ProxyConnector) Validate(ctx context.Context) error {
	// Try a HEAD request to the target to verify it's reachable.
	req, err := http.NewRequestWithContext(ctx, "HEAD", p.targetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set(p.authHeader, p.authValue)
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("http_proxy: target unreachable: %w", err)
	}
	resp.Body.Close()
	return nil
}

// validateProxyPath canonicalizes and validates a proxy path to prevent
// path-traversal attacks including double-encoded sequences like %252e%252e%252f.
//
// It iteratively percent-decodes the path (up to maxUnescapePasses times) until
// it stabilizes, then rejects any remaining dangerous percent-encoded sequences
// and checks for ".." segments. The cleaned path is returned on success.
func validateProxyPath(proxyPath string) (string, error) {
	// 5 passes is sufficient to fully collapse any realistic multi-layer encoding
	// (e.g. %2525252e requires ≤5 rounds) while bounding the iteration cost.
	const maxUnescapePasses = 5

	decoded := proxyPath
	for i := 0; i < maxUnescapePasses; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil {
			return "", fmt.Errorf("invalid path encoding: %w", err)
		}
		if next == decoded {
			break
		}
		decoded = next
	}

	// Reject any dangerous percent-encodings that survive the decode passes
	// (e.g. a deliberately capped iteration would still leave encoded traversal tokens).
	lower := strings.ToLower(decoded)
	if strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", fmt.Errorf("path contains dangerous encoded sequences")
	}

	// Reject literal backslashes: %5c decodes to '\', and some upstreams treat
	// '\' as a path separator (IIS, .NET, Windows file servers). Normalising to
	// '/' would silently change the path semantics, so we reject outright.
	if strings.Contains(decoded, "\\") {
		return "", fmt.Errorf("path contains backslash")
	}

	// Reject paths containing ".." segments.
	for _, seg := range strings.Split(decoded, "/") {
		if seg == ".." {
			return "", fmt.Errorf("path contains traversal sequences")
		}
	}

	// Normalize using path.Clean and reject if the cleaned path escapes the root.
	cleaned := path.Clean(decoded)
	if !strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("path escapes root directory")
	}

	return cleaned, nil
}

// maxFilteredBodySize is the maximum number of bytes buffered when response
// filters are active.  Responses larger than this are rejected to prevent OOM.
const maxFilteredBodySize = 32 * 1024 * 1024 // 32 MiB

// headersInvalidatedByFiltering lists response headers that must be removed
// after the body has been modified by response filters, because their values
// would no longer be consistent with the new body.
var headersInvalidatedByFiltering = map[string]bool{
	"content-encoding":  true,
	"transfer-encoding": true,
	"etag":              true,
	"content-md5":       true,
	"content-length":    true,
}

// ProxyHTTP handles a raw HTTP request by forwarding it to the target,
// substituting auth credentials. Path restrictions are enforced by the
// policy engine before this method is called.
//
// When filters is non-empty, the response body is captured and run through
// policy.ApplyResponseFilters before being written to the client.
//
// Returns the filter-summary string (the second return value of
// ApplyResponseFilters; empty when no filters were applied or when the
// streaming fast-path was taken) and a non-nil error when the request was
// rejected locally (e.g. invalid path, denied header). The HTTP error
// response has already been written to w in that case. Callers use the
// summary to choose the audit-log policy_result identifier.
func (p *ProxyConnector) ProxyHTTP(w http.ResponseWriter, r *http.Request, proxyPath string, filters []policy.ResponseFilter) (string, error) {
	cleaned, err := validateProxyPath(proxyPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return "", fmt.Errorf("invalid proxy path: %w", err)
	}

	// Reject deny-listed inbound headers BEFORE constructing the upstream
	// request — except Authorization, which is the agent's Sieve bearer
	// token, present on every legitimate agent request and stripped a few
	// lines below before forwarding. Per spec 006 FR-010, Authorization is
	// the only deny-list entry exempted from the inbound check on the
	// transparent surface; everything else is rejected.
	for key := range r.Header {
		if strings.EqualFold(key, "Authorization") {
			continue
		}
		if denied, lower := isDeniedHeader(key, p.authHeaderLower); denied {
			http.Error(w, fmt.Sprintf("header %q not allowed", lower), http.StatusBadRequest)
			return "", fmt.Errorf("%w: %q", ErrHeaderDenied, lower)
		}
	}

	// Build the target URL properly using URL parsing, not string concatenation.
	targetBase, err := url.Parse(p.targetURL)
	if err != nil {
		http.Error(w, "invalid target URL configuration", http.StatusInternalServerError)
		return "", fmt.Errorf("invalid target URL: %w", err)
	}
	// Use JoinPath to safely combine the base path with the proxy path.
	targetURL := targetBase.JoinPath(cleaned)
	targetURL.RawQuery = r.URL.RawQuery

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, "failed to create proxy request", http.StatusInternalServerError)
		return "", fmt.Errorf("create proxy request: %w", err)
	}

	// Copy original headers (except Authorization — we substitute it, and
	// except Accept-Encoding when filters are active so that Go's Transport
	// handles transparent decompression, ensuring filters see plain text).
	for key, values := range r.Header {
		if strings.EqualFold(key, "Authorization") {
			continue
		}
		if len(filters) > 0 && strings.EqualFold(key, "Accept-Encoding") {
			continue
		}
		for _, v := range values {
			proxyReq.Header.Add(key, v)
		}
	}

	// Inject real auth credential.
	proxyReq.Header.Set(p.authHeader, p.authValue)

	// Inject extra headers.
	for k, v := range p.extraHeaders {
		proxyReq.Header.Set(k, v)
	}

	resp, err := p.client.Do(proxyReq)
	if err != nil {
		http.Error(w, "proxy request failed: "+err.Error(), http.StatusBadGateway)
		return "", fmt.Errorf("upstream request: %w", err)
	}
	defer resp.Body.Close()

	// Fast path: when no filters are present, stream the response directly
	// to avoid buffering the entire body (important for large/streaming responses).
	if len(filters) == 0 {
		for key, values := range resp.Header {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return "", nil
	}

	// Slow path: buffer the response so we can apply filters.
	// Limit the read to maxFilteredBodySize to prevent OOM on large responses.
	limitedBody := io.LimitReader(resp.Body, maxFilteredBodySize+1)
	respBody, err := io.ReadAll(limitedBody)
	if err != nil {
		http.Error(w, "failed to read proxy response", http.StatusBadGateway)
		return "", fmt.Errorf("read proxy response: %w", err)
	}
	if int64(len(respBody)) > maxFilteredBodySize {
		http.Error(w, "response too large to filter", http.StatusBadGateway)
		return "", fmt.Errorf("response exceeds %d byte filter limit", maxFilteredBodySize)
	}

	respBody, filterSummary := policy.ApplyResponseFilters(respBody, filters)

	// Copy response headers, skipping headers that are no longer valid after
	// the body has been modified (Content-Length is re-added below).
	for key, values := range resp.Header {
		if headersInvalidatedByFiltering[strings.ToLower(key)] {
			continue
		}
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBody)))
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
	return filterSummary, nil
}

func flattenHeaders(h http.Header) map[string]string {
	flat := make(map[string]string, len(h))
	for k, v := range h {
		flat[k] = strings.Join(v, ", ")
	}
	return flat
}
