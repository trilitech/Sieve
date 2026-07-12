package notion

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
)

// recorder captures the last request the connector sent to the mock Notion API.
type recorder struct {
	method  string
	path    string
	rawURL  string
	headers http.Header
	body    string
}

// newTestConnector stands up a mock Notion endpoint and returns a connector
// pointed at it (loopback allowlisted). The handler records the request and
// replies with status/respBody.
func newTestConnector(t *testing.T, status int, respBody string, rec *recorder) *Connector {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.method = r.Method
		rec.path = r.URL.Path
		rec.rawURL = r.URL.String()
		rec.headers = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		rec.body = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)

	c, err := Factory()(map[string]any{
		"api_key":            "ntn_test-not-real",
		"base_url":           srv.URL,
		"outbound_allowlist": []string{"127.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	return c.(*Connector)
}

func execOK(t *testing.T, c *Connector, op string, params map[string]any) *httpResponse {
	t.Helper()
	out, err := c.Execute(context.Background(), op, params)
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	res, ok := out.(*httpResponse)
	if !ok {
		t.Fatalf("%s: result type %T, want *httpResponse", op, out)
	}
	return res
}

func TestParseConfig(t *testing.T) {
	if _, err := parseConfig(map[string]any{}); err == nil {
		t.Error("empty config must error (api_key required)")
	}
	if _, err := parseConfig(map[string]any{"api_key": "   "}); err == nil {
		t.Error("whitespace-only api_key must error")
	}
	c, err := parseConfig(map[string]any{"api_key": "ntn_x"})
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if c.BaseURL != defaultBaseURL {
		t.Errorf("BaseURL default = %q, want %q", c.BaseURL, defaultBaseURL)
	}
	if _, err := parseConfig(map[string]any{"api_key": "ntn_x", "base_url": "ftp://nope"}); err == nil {
		t.Error("non-http base_url must error")
	}
}

func TestConfigSchemaKeys(t *testing.T) {
	c := &Connector{}
	got := map[string]bool{}
	for _, k := range c.ConfigSchemaKeys() {
		got[k] = true
	}
	for _, want := range []string{"api_key", "base_url"} {
		if !got[want] {
			t.Errorf("ConfigSchemaKeys missing %q (got %v)", want, c.ConfigSchemaKeys())
		}
	}
}

// TestFactoryIgnoresInjectedRefreshCallbacks pins the reserved-key handling:
// connections.Service injects _on_token_refresh(_failure) func values into the
// config map; parseConfig must drop them before re-marshaling rather than fail
// on the func value.
func TestFactoryIgnoresInjectedRefreshCallbacks(t *testing.T) {
	_, err := Factory()(map[string]any{
		"api_key":                   "ntn_test",
		"_on_token_refresh":         func() {},
		"_on_token_refresh_failure": func() {},
	})
	if err != nil {
		t.Fatalf("Factory must ignore injected refresh callbacks; got: %v", err)
	}
}

func TestValidate(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusOK, `{"object":"user","type":"bot"}`, &rec)
	if err := c.Validate(context.Background()); err != nil {
		t.Fatalf("Validate on 200 must succeed: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/v1/users/me" {
		t.Errorf("Validate hit %s %s, want GET /v1/users/me", rec.method, rec.path)
	}

	c401 := newTestConnector(t, http.StatusUnauthorized, `{"object":"error","status":401}`, &recorder{})
	err := c401.Validate(context.Background())
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf("Validate on 401 must return ErrNeedsReauth, got: %v", err)
	}
}

func TestAuthAndVersionHeaders(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusOK, `{"object":"page"}`, &rec)
	execOK(t, c, "notion_get_page", map[string]any{"page_id": "abc-123"})

	if got := rec.headers.Get("Authorization"); got != "Bearer ntn_test-not-real" {
		t.Errorf("Authorization = %q, want Bearer token", got)
	}
	if got := rec.headers.Get("Notion-Version"); got != notionVersion {
		t.Errorf("Notion-Version = %q, want %q", got, notionVersion)
	}
	if rec.method != http.MethodGet || rec.path != "/v1/pages/abc-123" {
		t.Errorf("hit %s %s, want GET /v1/pages/abc-123", rec.method, rec.path)
	}
}

func TestSearchBuildsFilterObject(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusOK, `{"object":"list","results":[]}`, &rec)
	execOK(t, c, "notion_search", map[string]any{"query": "roadmap", "filter": "database", "page_size": 10})

	if rec.method != http.MethodPost || rec.path != "/v1/search" {
		t.Errorf("hit %s %s, want POST /v1/search", rec.method, rec.path)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(rec.body), &body); err != nil {
		t.Fatalf("search body not JSON: %v (%s)", err, rec.body)
	}
	if body["query"] != "roadmap" {
		t.Errorf("query = %v, want roadmap", body["query"])
	}
	f, ok := body["filter"].(map[string]any)
	if !ok || f["property"] != "object" || f["value"] != "database" {
		t.Errorf("filter = %v, want {property:object, value:database}", body["filter"])
	}
	if body["page_size"].(float64) != 10 {
		t.Errorf("page_size = %v, want 10", body["page_size"])
	}
}

func TestSearchRejectsBadFilter(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusOK, `{}`, &rec)
	if _, err := c.Execute(context.Background(), "notion_search", map[string]any{"filter": "widget"}); err == nil {
		t.Error("filter other than page/database must error")
	}
}

func TestQueryDatabaseForwardsJSONFilter(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusOK, `{"object":"list","results":[]}`, &rec)
	execOK(t, c, "notion_query_database", map[string]any{
		"database_id": "db-1",
		"filter":      `{"property":"Status","status":{"equals":"Done"}}`,
		"page_size":   5,
	})
	if rec.method != http.MethodPost || rec.path != "/v1/databases/db-1/query" {
		t.Errorf("hit %s %s, want POST /v1/databases/db-1/query", rec.method, rec.path)
	}
	if !strings.Contains(rec.body, `"property":"Status"`) {
		t.Errorf("filter not forwarded byte-exact: %s", rec.body)
	}
}

func TestCreatePageRequiresParentAndProperties(t *testing.T) {
	c := newTestConnector(t, http.StatusOK, `{}`, &recorder{})
	if _, err := c.Execute(context.Background(), "notion_create_page", map[string]any{
		"properties": `{"title":[]}`,
	}); err == nil {
		t.Error("missing parent must error")
	}
	if _, err := c.Execute(context.Background(), "notion_create_page", map[string]any{
		"parent": `{"database_id":"db-1"}`,
	}); err == nil {
		t.Error("missing properties must error")
	}
	if _, err := c.Execute(context.Background(), "notion_create_page", map[string]any{
		"parent":     `{not json`,
		"properties": `{}`,
	}); err == nil {
		t.Error("invalid JSON parent must error")
	}
}

func TestAppendBlockChildren(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusOK, `{"object":"list","results":[]}`, &rec)
	execOK(t, c, "notion_append_block_children", map[string]any{
		"block_id": "blk-9",
		"children": `[{"type":"paragraph","paragraph":{"rich_text":[]}}]`,
	})
	if rec.method != http.MethodPatch || rec.path != "/v1/blocks/blk-9/children" {
		t.Errorf("hit %s %s, want PATCH /v1/blocks/blk-9/children", rec.method, rec.path)
	}
	if !strings.Contains(rec.body, `"children":[`) {
		t.Errorf("children not forwarded: %s", rec.body)
	}
}

func TestGetCommentsSetsBlockIDQuery(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusOK, `{"object":"list","results":[]}`, &rec)
	execOK(t, c, "notion_get_comments", map[string]any{"block_id": "pg-1", "page_size": 20})
	if rec.method != http.MethodGet || rec.path != "/v1/comments" {
		t.Errorf("hit %s %s, want GET /v1/comments", rec.method, rec.path)
	}
	if !strings.Contains(rec.rawURL, "block_id=pg-1") || !strings.Contains(rec.rawURL, "page_size=20") {
		t.Errorf("query = %q, want block_id + page_size", rec.rawURL)
	}
}

func TestRequestNormalizesPrefixAndValidatesJSON(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusOK, `{"ok":true}`, &rec)
	// Agent typed the /v1 prefix explicitly — must not double up.
	execOK(t, c, "notion_request", map[string]any{"method": "get", "path": "/v1/users"})
	if rec.path != "/v1/users" {
		t.Errorf("path = %q, want /v1/users (prefix normalized)", rec.path)
	}

	// Invalid JSON body is rejected before dialing.
	if _, err := c.Execute(context.Background(), "notion_request", map[string]any{
		"method": "POST", "path": "/pages", "body": "{not json",
	}); err == nil {
		t.Error("invalid JSON body must error")
	}
}

func TestRequestRejectsTraversal(t *testing.T) {
	c := newTestConnector(t, http.StatusOK, `{}`, &recorder{})
	if _, err := c.Execute(context.Background(), "notion_request", map[string]any{
		"method": "GET", "path": "/../../etc/passwd",
	}); err == nil {
		t.Error("path traversal must be rejected")
	}
}

func TestUnknownOperation(t *testing.T) {
	c := newTestConnector(t, http.StatusOK, `{}`, &recorder{})
	if _, err := c.Execute(context.Background(), "notion_nope", nil); err == nil {
		t.Error("unknown op must error")
	}
}
