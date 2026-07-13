package asana

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/trilitech/Sieve/internal/connector"
)

type recorder struct {
	method  string
	path    string
	rawURL  string
	headers http.Header
	body    string
}

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
		"api_key":            "1/test-not-real",
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
	c, err := parseConfig(map[string]any{"api_key": "1/x"})
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if c.BaseURL != defaultBaseURL {
		t.Errorf("BaseURL default = %q, want %q", c.BaseURL, defaultBaseURL)
	}
	if _, err := parseConfig(map[string]any{"api_key": "1/x", "base_url": "ftp://nope"}); err == nil {
		t.Error("non-http base_url must error")
	}
}

func TestConfigSchemaKeys(t *testing.T) {
	got := map[string]bool{}
	for _, k := range (&Connector{}).ConfigSchemaKeys() {
		got[k] = true
	}
	for _, want := range []string{"api_key", "base_url"} {
		if !got[want] {
			t.Errorf("ConfigSchemaKeys missing %q", want)
		}
	}
}

func TestFactoryIgnoresInjectedRefreshCallbacks(t *testing.T) {
	_, err := Factory()(map[string]any{
		"api_key":                   "1/test",
		"_on_token_refresh":         func() {},
		"_on_token_refresh_failure": func() {},
	})
	if err != nil {
		t.Fatalf("Factory must ignore injected refresh callbacks; got: %v", err)
	}
}

func TestValidate(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusOK, `{"data":{"gid":"1"}}`, &rec)
	if err := c.Validate(context.Background()); err != nil {
		t.Fatalf("Validate on 200 must succeed: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/1.0/users/me" {
		t.Errorf("Validate hit %s %s, want GET /api/1.0/users/me", rec.method, rec.path)
	}

	c401 := newTestConnector(t, http.StatusUnauthorized, `{"errors":[]}`, &recorder{})
	if err := c401.Validate(context.Background()); !errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf("Validate on 401 must return ErrNeedsReauth, got: %v", err)
	}
}

func TestAuthHeaderAndPrefix(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusOK, `{"data":[]}`, &rec)
	execOK(t, c, "asana_list_workspaces", map[string]any{"limit": 5})
	if got := rec.headers.Get("Authorization"); got != "Bearer 1/test-not-real" {
		t.Errorf("Authorization = %q, want Bearer token", got)
	}
	if rec.method != http.MethodGet || rec.path != "/api/1.0/workspaces" {
		t.Errorf("hit %s %s, want GET /api/1.0/workspaces", rec.method, rec.path)
	}
	if !strings.Contains(rec.rawURL, "limit=5") {
		t.Errorf("query missing limit: %s", rec.rawURL)
	}
}

func TestGetTask(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusOK, `{"data":{"gid":"42","name":"Ship it"}}`, &rec)
	execOK(t, c, "asana_get_task", map[string]any{"task_gid": "42", "opt_fields": "name,notes"})
	if rec.method != http.MethodGet || rec.path != "/api/1.0/tasks/42" {
		t.Errorf("hit %s %s, want GET /api/1.0/tasks/42", rec.method, rec.path)
	}
	if !strings.Contains(rec.rawURL, "opt_fields=name%2Cnotes") {
		t.Errorf("opt_fields not forwarded: %s", rec.rawURL)
	}
}

func TestCreateTaskWrapsData(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusCreated, `{"data":{"gid":"99"}}`, &rec)
	execOK(t, c, "asana_create_task", map[string]any{
		"name": "New task", "notes": "details", "project": "p1", "assignee": "me",
	})
	if rec.method != http.MethodPost || rec.path != "/api/1.0/tasks" {
		t.Errorf("hit %s %s, want POST /api/1.0/tasks", rec.method, rec.path)
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(rec.body), &body); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, rec.body)
	}
	if body.Data == nil {
		t.Fatalf("body not wrapped in data: %s", rec.body)
	}
	if body.Data["name"] != "New task" {
		t.Errorf("data.name = %v, want New task", body.Data["name"])
	}
	if projs, ok := body.Data["projects"].([]any); !ok || len(projs) != 1 || projs[0] != "p1" {
		t.Errorf("data.projects = %v, want [p1]", body.Data["projects"])
	}
}

func TestCreateTaskRequiresProjectOrWorkspace(t *testing.T) {
	c := newTestConnector(t, http.StatusOK, `{}`, &recorder{})
	if _, err := c.Execute(context.Background(), "asana_create_task", map[string]any{"name": "x"}); err == nil {
		t.Error("create_task without project or workspace must error")
	}
}

func TestUpdateTask(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusOK, `{"data":{"gid":"42"}}`, &rec)
	execOK(t, c, "asana_update_task", map[string]any{"task_gid": "42", "completed": true, "name": "done"})
	if rec.method != http.MethodPut || rec.path != "/api/1.0/tasks/42" {
		t.Errorf("hit %s %s, want PUT /api/1.0/tasks/42", rec.method, rec.path)
	}
	if !strings.Contains(rec.body, `"completed":true`) || !strings.Contains(rec.body, `"name":"done"`) {
		t.Errorf("update body missing fields: %s", rec.body)
	}
	if !strings.HasPrefix(strings.TrimSpace(rec.body), `{"data":`) {
		t.Errorf("update body not wrapped in data: %s", rec.body)
	}
}

func TestCreateStory(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusCreated, `{"data":{"gid":"7"}}`, &rec)
	execOK(t, c, "asana_create_story", map[string]any{"task_gid": "42", "text": "looks good"})
	if rec.method != http.MethodPost || rec.path != "/api/1.0/tasks/42/stories" {
		t.Errorf("hit %s %s, want POST /api/1.0/tasks/42/stories", rec.method, rec.path)
	}
	if !strings.Contains(rec.body, `"text":"looks good"`) {
		t.Errorf("story text not forwarded: %s", rec.body)
	}
}

func TestListTasksFilters(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusOK, `{"data":[]}`, &rec)
	execOK(t, c, "asana_list_tasks", map[string]any{"assignee": "u1", "workspace": "w1", "limit": 10})
	if rec.path != "/api/1.0/tasks" {
		t.Errorf("path = %q, want /api/1.0/tasks", rec.path)
	}
	for _, want := range []string{"assignee=u1", "workspace=w1", "limit=10"} {
		if !strings.Contains(rec.rawURL, want) {
			t.Errorf("query missing %q: %s", want, rec.rawURL)
		}
	}
}

func TestRequestNormalizesPrefixAndValidatesJSON(t *testing.T) {
	var rec recorder
	c := newTestConnector(t, http.StatusOK, `{"data":{}}`, &rec)
	execOK(t, c, "asana_request", map[string]any{"method": "get", "path": "/api/1.0/users/me"})
	if rec.path != "/api/1.0/users/me" {
		t.Errorf("path = %q, want /api/1.0/users/me (prefix normalized)", rec.path)
	}
	if _, err := c.Execute(context.Background(), "asana_request", map[string]any{
		"method": "POST", "path": "/tasks", "body": "{not json",
	}); err == nil {
		t.Error("invalid JSON body must error")
	}
}

func TestRequestRejectsTraversal(t *testing.T) {
	c := newTestConnector(t, http.StatusOK, `{}`, &recorder{})
	if _, err := c.Execute(context.Background(), "asana_request", map[string]any{
		"method": "GET", "path": "/../../etc/passwd",
	}); err == nil {
		t.Error("path traversal must be rejected")
	}
}

func TestUnknownOperation(t *testing.T) {
	c := newTestConnector(t, http.StatusOK, `{}`, &recorder{})
	if _, err := c.Execute(context.Background(), "asana_nope", nil); err == nil {
		t.Error("unknown op must error")
	}
}

// TestOAuthModeRefreshesExpiredToken proves the OAuth path: an expired access
// token is transparently refreshed via /-/oauth_token on the request that needs
// it, the API call then carries the NEW token, and the rotated token is handed
// to _on_token_refresh for persistence.
func TestOAuthModeRefreshesExpiredToken(t *testing.T) {
	var refreshed bool
	var apiAuth string
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/-/oauth_token" {
			refreshed = true
			_, _ = io.WriteString(w, `{"access_token":"acc-2","token_type":"bearer","expires_in":3600,"refresh_token":"ref-2"}`)
			return
		}
		apiAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	t.Cleanup(mock.Close)

	var persisted *oauth2.Token
	c, err := Factory()(map[string]any{
		"base_url":           mock.URL,
		"outbound_allowlist": []string{"127.0.0.0/8"},
		"client_id":          "cid",
		"client_secret":      "sec",
		"oauth_token": map[string]any{
			"access_token":  "acc-1",
			"refresh_token": "ref-1",
			"token_type":    "bearer",
			"expiry":        "2000-01-01T00:00:00Z", // long expired
		},
		"_on_token_refresh": func(tok *oauth2.Token) { persisted = tok },
	})
	if err != nil {
		t.Fatalf("Factory (oauth mode): %v", err)
	}

	if _, err := c.Execute(context.Background(), "asana_list_workspaces", nil); err != nil {
		t.Fatalf("list_workspaces: %v", err)
	}
	if !refreshed {
		t.Error("expected a refresh against /-/oauth_token for the expired token")
	}
	if apiAuth != "Bearer acc-2" {
		t.Errorf("API call Authorization = %q, want Bearer acc-2 (refreshed token)", apiAuth)
	}
	if persisted == nil || persisted.AccessToken != "acc-2" {
		t.Errorf("_on_token_refresh not called with the rotated token: %+v", persisted)
	}
}

// TestOAuthModeStaticWhenNoClientCreds: an OAuth token with no client creds to
// refresh with is used statically (still authenticates).
func TestOAuthModeStaticWhenNoClientCreds(t *testing.T) {
	var rec recorder
	c := oauthConnector(t, &rec, map[string]any{
		"access_token": "acc-static", "token_type": "bearer",
		"expiry": time.Now().Add(time.Hour).Format(time.RFC3339),
	}, "", "")
	execOK(t, c, "asana_list_workspaces", nil)
	if got := rec.headers.Get("Authorization"); got != "Bearer acc-static" {
		t.Errorf("Authorization = %q, want Bearer acc-static", got)
	}
}

func oauthConnector(t *testing.T, rec *recorder, oauthToken map[string]any, clientID, clientSecret string) *Connector {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.headers = r.Header.Clone()
		rec.path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	t.Cleanup(srv.Close)
	cfg := map[string]any{
		"base_url":           srv.URL,
		"outbound_allowlist": []string{"127.0.0.0/8"},
		"oauth_token":        oauthToken,
	}
	if clientID != "" {
		cfg["client_id"] = clientID
		cfg["client_secret"] = clientSecret
	}
	c, err := Factory()(cfg)
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	return c.(*Connector)
}
