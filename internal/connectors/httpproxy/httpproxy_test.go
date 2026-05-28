package httpproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestFactory_AuthValueBearerAutoPrefix(t *testing.T) {
	cases := []struct {
		name       string
		authHeader string
		authValue  string
		wantValue  string
	}{
		{
			name:       "raw token + Authorization → prefix added",
			authHeader: "Authorization",
			authValue:  "pa-2TLWFkt8F5fUpacpDlUEgmoRnaPtOOcfqY6TwIfLXRu",
			wantValue:  "Bearer pa-2TLWFkt8F5fUpacpDlUEgmoRnaPtOOcfqY6TwIfLXRu",
		},
		{
			name:       "Bearer-prefixed value left untouched",
			authHeader: "Authorization",
			authValue:  "Bearer pa-existing",
			wantValue:  "Bearer pa-existing",
		},
		{
			name:       "Basic-prefixed value left untouched",
			authHeader: "Authorization",
			authValue:  "Basic dXNlcjpwYXNz",
			wantValue:  "Basic dXNlcjpwYXNz",
		},
		{
			name:       "non-Authorization header left untouched",
			authHeader: "x-api-key",
			authValue:  "sk-ant-api03-abc",
			wantValue:  "sk-ant-api03-abc",
		},
		{
			name:       "case-insensitive header match",
			authHeader: "AUTHORIZATION",
			authValue:  "ghp_xxx",
			wantValue:  "Bearer ghp_xxx",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c2, err := Factory(map[string]any{
				"target_url":  "https://api.example.com",
				"auth_header": c.authHeader,
				"auth_value":  c.authValue,
			})
			if err != nil {
				t.Fatal(err)
			}
			pc := c2.(*ProxyConnector)
			if pc.authValue != c.wantValue {
				t.Errorf("authValue = %q, want %q", pc.authValue, c.wantValue)
			}
		})
	}
}

// --- W1.1: header deny-list tests ---

// makeProxy builds a ProxyConnector pointing at the supplied test server, with
// the given auth_header/auth_value and scrub-on-by-default.
func makeProxy(t *testing.T, ts *httptest.Server, authHeader, authValue string) *ProxyConnector {
	t.Helper()
	c, err := Factory(map[string]any{
		"target_url":  ts.URL,
		"auth_header": authHeader,
		"auth_value":  authValue,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c.(*ProxyConnector)
}

func TestExecuteRejectsDeniedHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream MUST NOT be contacted on a denied-header rejection (got %s %s)", r.Method, r.URL.Path)
	}))
	defer upstream.Close()
	pc := makeProxy(t, upstream, "x-api-key", "sk-test-12345")

	cases := []struct {
		key string // exact case agent supplied
	}{
		{"Authorization"},
		{"authorization"},
		{"Host"},
		{"Cookie"},
		{"Connection"},
		{"Keep-Alive"},
		{"Proxy-Authenticate"},
		{"Proxy-Authorization"},
		{"TE"},
		{"Trailers"},
		{"Transfer-Encoding"},
		{"Upgrade"},
		{"X-Forwarded-For"},
		{"X-Forwarded-Host"},
		{"X-Forwarded-Proto"},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			_, err := pc.Execute(context.Background(), "proxy_request", map[string]any{
				"method":  "GET",
				"path":    "/v1/anything",
				"headers": map[string]any{c.key: "evil"},
			})
			if err == nil {
				t.Fatalf("expected error for header %q, got nil", c.key)
			}
			if !errors.Is(err, ErrHeaderDenied) {
				t.Errorf("expected errors.Is(err, ErrHeaderDenied), got %v", err)
			}
		})
	}
}

func TestExecuteRejectsAuthHeaderOverride(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream MUST NOT be contacted on auth_header-override rejection")
	}))
	defer upstream.Close()
	pc := makeProxy(t, upstream, "x-api-key", "sk-test-12345")

	for _, casing := range []string{"x-api-key", "X-API-KEY", "X-Api-Key", "X-api-KEY"} {
		t.Run(casing, func(t *testing.T) {
			_, err := pc.Execute(context.Background(), "proxy_request", map[string]any{
				"method":  "POST",
				"path":    "/v1/messages",
				"headers": map[string]any{casing: "attacker-supplied"},
			})
			if !errors.Is(err, ErrHeaderDenied) {
				t.Errorf("auth_header override via %q must be denied; got err = %v", casing, err)
			}
		})
	}
}

func TestExecuteAcceptsLegitimateHeaders(t *testing.T) {
	hit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		if got := r.Header.Get("Anthropic-Version"); got != "2023-06-01" {
			t.Errorf("expected anthropic-version forwarded, got %q", got)
		}
		if got := r.Header.Get("X-Custom-App"); got != "yes" {
			t.Errorf("expected X-Custom-App forwarded, got %q", got)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	pc := makeProxy(t, upstream, "x-api-key", "sk-test-12345")

	_, err := pc.Execute(context.Background(), "proxy_request", map[string]any{
		"method": "POST",
		"path":   "/v1/messages",
		"headers": map[string]any{
			"anthropic-version": "2023-06-01",
			"x-custom-app":      "yes",
		},
	})
	if err != nil {
		t.Fatalf("legitimate headers must be accepted; got err = %v", err)
	}
	if !hit {
		t.Errorf("upstream was not contacted; expected proxy_request to forward")
	}
}

func TestProxyHTTPRejectsDeniedHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream MUST NOT be contacted on a denied-header rejection")
	}))
	defer upstream.Close()
	pc := makeProxy(t, upstream, "x-api-key", "sk-test-12345")

	for _, key := range []string{"Host", "Cookie", "X-Forwarded-For", "Connection"} {
		t.Run(key, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/proxy/conn/v1/anything", nil)
			req.Header.Set("Authorization", "Bearer sieve_tok_test") // bearer carve-out
			req.Header.Set(key, "evil")
			rec := httptest.NewRecorder()
			summary, _, err := pc.ProxyHTTP(rec, req, "/v1/anything", nil)
			if !errors.Is(err, ErrHeaderDenied) {
				t.Errorf("expected ErrHeaderDenied for %q, got err=%v summary=%q", key, err, summary)
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected HTTP 400, got %d", rec.Code)
			}
		})
	}
}

func TestProxyHTTPCaseInsensitiveDeny(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream MUST NOT be contacted")
	}))
	defer upstream.Close()
	pc := makeProxy(t, upstream, "x-api-key", "sk-test-12345")

	for _, casing := range []string{"x-api-key", "X-API-KEY", "X-Api-Key"} {
		t.Run(casing, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/proxy/conn/v1/messages", nil)
			req.Header.Set("Authorization", "Bearer sieve_tok_test")
			req.Header.Set(casing, "attacker-supplied")
			rec := httptest.NewRecorder()
			_, _, err := pc.ProxyHTTP(rec, req, "/v1/messages", nil)
			if !errors.Is(err, ErrHeaderDenied) {
				t.Errorf("auth_header override via %q must be denied on transparent surface; got err=%v", casing, err)
			}
		})
	}
}

func TestProxyHTTPAuthorizationCarveOut(t *testing.T) {
	hit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		// Authorization MUST be stripped before reaching upstream.
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization should be stripped, got %q", got)
		}
		// Configured auth_header MUST be injected.
		if got := r.Header.Get("X-Api-Key"); got != "sk-real" {
			t.Errorf("auth_header not injected, got %q", got)
		}
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	pc := makeProxy(t, upstream, "x-api-key", "sk-real")

	req := httptest.NewRequest("GET", "/proxy/conn/v1/anything", nil)
	req.Header.Set("Authorization", "Bearer sieve_tok_test")
	rec := httptest.NewRecorder()
	_, _, err := pc.ProxyHTTP(rec, req, "/v1/anything", nil)
	if err != nil {
		t.Fatalf("Authorization presence must NOT trigger deny; got err=%v", err)
	}
	if !hit {
		t.Errorf("upstream was not contacted; the Authorization carve-out is broken")
	}
}

// --- W1.2: auth_value scrub tests ---

func TestAuthValueScrubInResponse(t *testing.T) {
	const secret = "sk-test-12345-do-not-leak"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate an upstream that echoes the configured auth_value back
		// in an error body. Real-world: misconfigured proxies, debug
		// endpoints, some self-hosted LLM gateways.
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"invalid token: `+secret+`"}}`)
	}))
	defer upstream.Close()
	pc := makeProxy(t, upstream, "x-api-key", secret)

	res, err := pc.Execute(context.Background(), "proxy_request", map[string]any{
		"method": "GET",
		"path":   "/v1/anything",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	body := res.(map[string]any)["body"].(string)
	if strings.Contains(body, secret) {
		t.Errorf("auth_value leaked verbatim in response body: %q", body)
	}
	if !strings.Contains(body, "[REDACTED]") {
		t.Errorf("expected [REDACTED] marker in scrubbed body, got %q", body)
	}
}

func TestAuthValueScrubOptOut(t *testing.T) {
	const secret = "sk-test-12345-do-not-leak"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"invalid token: `+secret+`"}`)
	}))
	defer upstream.Close()

	c, err := Factory(map[string]any{
		"target_url":       upstream.URL,
		"auth_header":      "x-api-key",
		"auth_value":       secret,
		"auth_value_scrub": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	pc := c.(*ProxyConnector)
	if pc.authValueScrub != false {
		t.Fatalf("auth_value_scrub: false should disable scrub, got %v", pc.authValueScrub)
	}

	res, err := pc.Execute(context.Background(), "proxy_request", map[string]any{
		"method": "GET",
		"path":   "/v1/anything",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	body := res.(map[string]any)["body"].(string)
	if !strings.Contains(body, secret) {
		t.Errorf("opt-out failed to disable scrub; body=%q", body)
	}
}

func TestAuthValueScrubRegexEscape(t *testing.T) {
	// Auth value with regex metacharacters; scrub MUST treat as literal.
	const secret = "key.with.dots+and+plus.signs"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		// Both the literal and a near-miss that the unescaped regex would match.
		io.WriteString(w, `{"echo":"`+secret+`","near":"keyXwithXdots+andYplus.signs"}`)
	}))
	defer upstream.Close()
	pc := makeProxy(t, upstream, "x-api-key", secret)

	res, err := pc.Execute(context.Background(), "proxy_request", map[string]any{
		"method": "GET",
		"path":   "/v1/anything",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	body := res.(map[string]any)["body"].(string)
	if strings.Contains(body, secret) {
		t.Errorf("literal auth_value must be scrubbed; body=%q", body)
	}
	// Near-miss SHOULD remain (literal-match, not regex-wildcard).
	if !strings.Contains(body, "keyXwithXdots") {
		t.Errorf("near-miss substring was over-scrubbed (regex.QuoteMeta failed); body=%q", body)
	}
}

func TestAuthValueScrubFilterReturnsNilWhenDisabled(t *testing.T) {
	c, err := Factory(map[string]any{
		"target_url":       "https://example.com",
		"auth_header":      "x-api-key",
		"auth_value":       "x",
		"auth_value_scrub": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	pc := c.(*ProxyConnector)
	if pc.AuthValueScrubFilter() != nil {
		t.Errorf("AuthValueScrubFilter MUST return nil when scrub is disabled")
	}
}

// --- additional_denied_headers (operator-extendable deny-list) ---

func TestExecuteRespectsAdditionalDeniedHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream MUST NOT be contacted on operator-extended deny")
	}))
	defer upstream.Close()
	c, err := Factory(map[string]any{
		"target_url":                upstream.URL,
		"auth_header":               "x-api-key",
		"auth_value":                "sk-test",
		"additional_denied_headers": []any{"X-Custom", "X-App-Internal"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pc := c.(*ProxyConnector)

	// Both extras are denied (case-insensitive). Baseline still applies.
	for _, casing := range []string{"X-Custom", "x-custom", "X-CUSTOM"} {
		t.Run(casing, func(t *testing.T) {
			_, err := pc.Execute(context.Background(), "proxy_request", map[string]any{
				"method":  "GET",
				"path":    "/v1/anything",
				"headers": map[string]any{casing: "x"},
			})
			if !errors.Is(err, ErrHeaderDenied) {
				t.Errorf("operator-extended deny via %q failed; got err=%v", casing, err)
			}
		})
	}

	// A non-denied header still passes the deny-check (would reach upstream
	// but our test server fails the test if it does — so we don't actually
	// call Execute with such a header here; just verify the negative.)
	if denied, _ := isDeniedHeader("anthropic-version", pc.authHeaderLower, pc.additionalDeniedLookup); denied {
		t.Errorf("non-denied header anthropic-version should pass")
	}
}

func TestAdditionalDenyDoesNotReduceBaseline(t *testing.T) {
	// Even if an operator passes an empty additional_denied_headers list,
	// the baseline (Authorization, Host, hop-by-hop, etc.) still fires.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream MUST NOT be contacted")
	}))
	defer upstream.Close()
	c, err := Factory(map[string]any{
		"target_url":                upstream.URL,
		"auth_header":               "x-api-key",
		"auth_value":                "sk-test",
		"additional_denied_headers": []any{}, // empty: no extras
	})
	if err != nil {
		t.Fatal(err)
	}
	pc := c.(*ProxyConnector)
	_, err = pc.Execute(context.Background(), "proxy_request", map[string]any{
		"method":  "POST",
		"path":    "/v1/messages",
		"headers": map[string]any{"Authorization": "evil"},
	})
	if !errors.Is(err, ErrHeaderDenied) {
		t.Errorf("baseline (Authorization) must still be denied with empty extras; got %v", err)
	}
}

func TestEmptyAdditionalDenyEntryRejected(t *testing.T) {
	_, err := Factory(map[string]any{
		"target_url":                "https://example.com",
		"auth_header":               "x-api-key",
		"auth_value":                "sk",
		"additional_denied_headers": []any{"X-Good", "  ", "X-Other"},
	})
	if err == nil {
		t.Fatal("Factory must reject empty trimmed entries in additional_denied_headers")
	}
	if !strings.Contains(err.Error(), "additional_denied_headers") {
		t.Errorf("error must clearly point at the offending field; got %q", err.Error())
	}
}

func TestAuthValueScrubFilterReturnsFilterWhenEnabled(t *testing.T) {
	c, err := Factory(map[string]any{
		"target_url":  "https://example.com",
		"auth_header": "x-api-key",
		"auth_value":  "sk-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	pc := c.(*ProxyConnector)
	f := pc.AuthValueScrubFilter()
	if f == nil {
		t.Fatal("AuthValueScrubFilter MUST return non-nil with default scrub on")
	}
	if len(f.RedactPatterns) != 1 {
		t.Errorf("expected 1 redact pattern, got %d", len(f.RedactPatterns))
	}
}

// --- auth_query_param injection ---

// makeQueryAuthProxy builds a ProxyConnector configured for query-string auth
// against the supplied test server. authValue defaults to "SECRET" if empty.
func makeQueryAuthProxy(t *testing.T, ts *httptest.Server, paramName, authValue string) *ProxyConnector {
	t.Helper()
	if authValue == "" {
		authValue = "SECRET"
	}
	c, err := Factory(map[string]any{
		"target_url":       ts.URL,
		"auth_header":      "X-Unused",
		"auth_value":       authValue,
		"auth_query_param": paramName,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c.(*ProxyConnector)
}

func TestExecuteInjectsAuthQueryParam(t *testing.T) {
	var observedRawQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedRawQuery = r.URL.RawQuery
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	pc := makeQueryAuthProxy(t, upstream, "appid", "WEATHER_KEY")

	_, err := pc.Execute(context.Background(), "proxy_request", map[string]any{
		"method": "GET",
		"path":   "/data/3.0/onecall",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if observedRawQuery != "appid=WEATHER_KEY" {
		t.Errorf("expected upstream to see ?appid=WEATHER_KEY, got %q", observedRawQuery)
	}
}

func TestExecuteInjectsAlongsideAgentParams(t *testing.T) {
	var observedQuery url.Values
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedQuery = r.URL.Query()
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()
	pc := makeQueryAuthProxy(t, upstream, "appid", "")

	_, err := pc.Execute(context.Background(), "proxy_request", map[string]any{
		"method": "GET",
		"path":   "/data/3.0/onecall?lat=51.5&lon=-0.12",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := observedQuery.Get("lat"); got != "51.5" {
		t.Errorf("agent param lat lost; got %q", got)
	}
	if got := observedQuery.Get("lon"); got != "-0.12" {
		t.Errorf("agent param lon lost; got %q", got)
	}
	if got := observedQuery.Get("appid"); got != "SECRET" {
		t.Errorf("auth param missing; got %q", got)
	}
	// Exactly 3 params, not duplicates.
	if len(observedQuery) != 3 {
		t.Errorf("expected 3 query params, got %d (%v)", len(observedQuery), observedQuery)
	}
}

func TestExecuteOverridesAgentSuppliedAuthParam(t *testing.T) {
	var observedQuery url.Values
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedQuery = r.URL.Query()
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()
	pc := makeQueryAuthProxy(t, upstream, "appid", "REAL_KEY")

	res, err := pc.Execute(context.Background(), "proxy_request", map[string]any{
		"method": "GET",
		"path":   "/data/3.0/onecall?appid=AGENT_INJECTED",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Upstream sees exactly one appid value, and that value is REAL_KEY.
	values := observedQuery["appid"]
	if len(values) != 1 || values[0] != "REAL_KEY" {
		t.Errorf("expected exactly one appid=REAL_KEY upstream; got %v", values)
	}
	if strings.Contains(observedQuery.Encode(), "AGENT_INJECTED") {
		t.Errorf("agent's value leaked to upstream: %q", observedQuery.Encode())
	}
	// Result map carries the private override signal.
	resultMap, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("result should be map[string]any, got %T", res)
	}
	overridden, _ := resultMap["_auth_query_overridden"].(bool)
	if !overridden {
		t.Errorf("result map missing _auth_query_overridden=true; got %v", resultMap)
	}
}

func TestExecuteUrlEncodesSpecialChars(t *testing.T) {
	const secret = "key+with=special&chars/and%spaces"
	var observedAppid string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// r.URL.Query() decodes — observedAppid receives the original byte sequence.
		observedAppid = r.URL.Query().Get("appid")
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()
	pc := makeQueryAuthProxy(t, upstream, "appid", secret)

	_, err := pc.Execute(context.Background(), "proxy_request", map[string]any{
		"method": "GET",
		"path":   "/anything",
	})
	if err != nil {
		t.Fatal(err)
	}
	if observedAppid != secret {
		t.Errorf("upstream saw %q after URL-decode; want byte-identical %q", observedAppid, secret)
	}
}

func TestProxyHTTPInjectsAuthQueryParam(t *testing.T) {
	var observedRawQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedRawQuery = r.URL.RawQuery
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	pc := makeQueryAuthProxy(t, upstream, "appid", "STREAM_KEY")

	req := httptest.NewRequest("GET", "/proxy/conn/data/3.0/onecall?lat=51.5", nil)
	req.Header.Set("Authorization", "Bearer sieve_tok_test")
	rec := httptest.NewRecorder()
	_, overridden, err := pc.ProxyHTTP(rec, req, "/data/3.0/onecall?lat=51.5", nil)
	if err != nil {
		t.Fatalf("ProxyHTTP failed: %v", err)
	}
	if overridden {
		t.Errorf("override flag should be false when agent didn't supply auth param; got true")
	}
	if !strings.Contains(observedRawQuery, "appid=STREAM_KEY") {
		t.Errorf("upstream raw query missing appid injection: %q", observedRawQuery)
	}
}

func TestProxyHTTPDetectsOverride(t *testing.T) {
	var observedAppid []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedAppid = r.URL.Query()["appid"]
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	pc := makeQueryAuthProxy(t, upstream, "appid", "REAL_KEY")

	req := httptest.NewRequest("GET", "/proxy/conn/x?appid=AGENT_INJECTED", nil)
	req.Header.Set("Authorization", "Bearer sieve_tok_test")
	rec := httptest.NewRecorder()
	_, overridden, err := pc.ProxyHTTP(rec, req, "/x?appid=AGENT_INJECTED", nil)
	if err != nil {
		t.Fatalf("ProxyHTTP failed: %v", err)
	}
	if !overridden {
		t.Errorf("override flag should be true when agent supplied auth param name")
	}
	if len(observedAppid) != 1 || observedAppid[0] != "REAL_KEY" {
		t.Errorf("upstream should see exactly one appid=REAL_KEY; got %v", observedAppid)
	}
}

func TestFactoryRejectsInvalidAuthQueryParam(t *testing.T) {
	cases := []string{
		"appid&injection",
		"appid=value",
		"app id",
		"appid?",
		"appid#frag",
		"appid+plus",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Factory(map[string]any{
				"target_url":       "https://example.com",
				"auth_header":      "x-api-key",
				"auth_value":       "k",
				"auth_query_param": name,
			})
			if err == nil {
				t.Fatalf("Factory must reject invalid auth_query_param %q", name)
			}
			if !strings.Contains(err.Error(), "auth_query_param") {
				t.Errorf("error must clearly point at the offending field; got %q", err.Error())
			}
		})
	}
}

func TestFactoryAcceptsEmptyAuthQueryParam(t *testing.T) {
	c, err := Factory(map[string]any{
		"target_url":  "https://example.com",
		"auth_header": "x-api-key",
		"auth_value":  "k",
		// no auth_query_param field
	})
	if err != nil {
		t.Fatal(err)
	}
	pc := c.(*ProxyConnector)
	if pc.authQueryParam != "" {
		t.Errorf("expected empty authQueryParam (legacy mode); got %q", pc.authQueryParam)
	}
	// Whitespace-only is also legitimate clear.
	c2, err := Factory(map[string]any{
		"target_url":       "https://example.com",
		"auth_header":      "x-api-key",
		"auth_value":       "k",
		"auth_query_param": "   ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c2.(*ProxyConnector).authQueryParam != "" {
		t.Errorf("whitespace-only auth_query_param should normalize to empty")
	}
}

func TestAuthValueScrubStillFiresWithQueryAuth(t *testing.T) {
	const secret = "REDACT_ME_IF_ECHOED"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Confirm injection landed AND echo it in the response body.
		if r.URL.Query().Get("appid") != secret {
			t.Errorf("auth value not injected; got %q", r.URL.Query().Get("appid"))
		}
		w.WriteHeader(401)
		fmt.Fprintf(w, `{"error":"invalid token: %s"}`, secret)
	}))
	defer upstream.Close()
	pc := makeQueryAuthProxy(t, upstream, "appid", secret)

	res, err := pc.Execute(context.Background(), "proxy_request", map[string]any{
		"method": "GET",
		"path":   "/anything",
	})
	if err != nil {
		t.Fatal(err)
	}
	body := res.(map[string]any)["body"].(string)
	if strings.Contains(body, secret) {
		t.Errorf("auth_value leaked to agent (W1.2 scrub did not fire on query-auth connection): %q", body)
	}
	if !strings.Contains(body, "[REDACTED]") {
		t.Errorf("expected [REDACTED] marker; got %q", body)
	}
}
