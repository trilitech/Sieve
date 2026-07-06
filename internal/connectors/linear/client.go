package linear

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/trilitech/Sieve/internal/httpguard"
)

const (
	maxResponseBytes  = 5 << 20 // 5 MiB; matches gitlab/github connectors
	clientTimeoutSecs = 60
	graphqlPath       = "/graphql"
)

// graphqlRequest is the wire shape Linear's API accepts at /graphql.
type graphqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

// graphqlResponse is the parsed GraphQL envelope. Errors is non-empty
// when the upstream rejected the query at the GraphQL layer (auth
// failures of OAuth tokens, validation errors, etc.). The connector
// surfaces both the raw envelope and the HTTP status — agents reading
// linear_request results need both.
type graphqlResponse struct {
	Data   json.RawMessage   `json:"data,omitempty"`
	Errors []graphqlErrorEnt `json:"errors,omitempty"`
}

type graphqlErrorEnt struct {
	Message    string         `json:"message"`
	Path       []any          `json:"path,omitempty"`
	Extensions map[string]any `json:"extensions,omitempty"`
}

// graphqlResult is what curated ops return to the agent: the parsed data
// (or null), any GraphQL errors, plus HTTP status + selected headers.
// linear_request returns this same shape so policy authors see the same
// surface regardless of which op they're inspecting.
type graphqlResult struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Data    json.RawMessage   `json:"data,omitempty"`
	Errors  []graphqlErrorEnt `json:"errors,omitempty"`
}

// doGraphQL POSTs a GraphQL query to Linear's /graphql endpoint with the
// configured API key in the Authorization header. Linear accepts Personal
// API Keys as `Authorization: <key>` (no Bearer prefix) — distinct from
// OAuth tokens which use `Authorization: Bearer <token>`. v1 only
// supports Personal API Keys.
func (l *Connector) doGraphQL(ctx context.Context, query string, vars map[string]any) (*graphqlResult, error) {
	if query == "" {
		return nil, errors.New("linear: empty graphql query")
	}

	payload, err := json.Marshal(graphqlRequest{Query: query, Variables: vars})
	if err != nil {
		return nil, fmt.Errorf("linear: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.config.BaseURL+graphqlPath, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", l.config.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Sieve-Linear-Connector")

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("linear: request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("linear: read response: %w", err)
	}
	if int64(len(raw)) > maxResponseBytes {
		return nil, fmt.Errorf("linear: response exceeded %d byte cap", maxResponseBytes)
	}

	headers := map[string]string{}
	for _, h := range []string{
		"Content-Type",
		"X-RateLimit-Requests-Limit",
		"X-RateLimit-Requests-Remaining",
		"X-RateLimit-Requests-Reset",
	} {
		if v := resp.Header.Get(h); v != "" {
			headers[h] = v
		}
	}

	out := &graphqlResult{Status: resp.StatusCode, Headers: headers}

	// Empty body (rare for GraphQL but possible on 5xx) — return what we
	// have without trying to decode.
	if len(raw) == 0 {
		return out, nil
	}

	var env graphqlResponse
	if err := json.Unmarshal(raw, &env); err != nil {
		// Linear may return non-JSON on infrastructure errors (CDN
		// pages, 502s). Wrap so the agent at least sees the payload.
		wrapped, _ := json.Marshal(map[string]any{"raw": string(raw)})
		out.Data = wrapped
		return out, nil
	}
	out.Data = env.Data
	out.Errors = env.Errors
	return out, nil
}

// newHTTPClient returns the http.Client used by the connector.
//
// Wraps httpguard.Client so dial-time SSRF protection applies on the
// first request and every redirect. Linear's GraphQL endpoint doesn't
// redirect in practice, but httpguard's redirect filter is the
// defense-in-depth layer that catches unexpected base_url override
// abuse.
func newHTTPClient(allowlist []netip.Prefix) *http.Client {
	return httpguard.Client(httpguard.ClientOptions{
		Allowlist: allowlist,
		Timeout:   clientTimeoutSecs * time.Second,
	})
}
