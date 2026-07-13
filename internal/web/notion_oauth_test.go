package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connections"
	notionconn "github.com/trilitech/Sieve/internal/connectors/notion"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// notionExchange records what the mock Notion token endpoint received.
type notionExchange struct {
	authHeader string
	body       string
}

// notionTestServer wires an admin server with the notion connector registered
// and (optionally) Notion OAuth client creds stored, plus a mock Notion API
// (token exchange + /v1/users/me) via the endpoint override.
func notionTestServer(t *testing.T, withOAuthCreds bool) (http.Handler, *testenv.Env, *notionExchange) {
	t.Helper()
	// Ensure env-var fallbacks don't leak a client into "unconfigured" tests.
	t.Setenv("NOTION_CLIENT_ID", "")
	t.Setenv("NOTION_CLIENT_SECRET", "")

	env := testenv.New(t).WithOperator("test-pass", "test-op")
	env.Registry.Register(notionconn.Meta(), notionconn.Factory())
	if withOAuthCreds {
		if err := env.Connections.PutOAuthApp("notion", connections.OAuthAppCredentials{
			ClientID:     "notion-client-id",
			ClientSecret: "notion-client-secret",
		}); err != nil {
			t.Fatal(err)
		}
	}

	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := NewServer(
		env.Tokens, env.Connections, env.Roles,
		env.Registry, env.Approval, env.Audit,
		"", env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "127.0.0.1:0",
	)
	srv.SetAuth(env.Operator, env.Session)
	t.Cleanup(srv.Close)

	rec := &notionExchange{}
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/oauth/token":
			rec.authHeader = r.Header.Get("Authorization")
			b, _ := io.ReadAll(r.Body)
			rec.body = string(b)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ntn_installed-token", "token_type": "bearer",
				"workspace_id": "ws-1", "workspace_name": "Acme",
			})
		case "/v1/users/me":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"object":"user","type":"bot"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(mock.Close)
	notionOAuthEndpointOverride = mock.URL
	t.Cleanup(func() { notionOAuthEndpointOverride = "" })

	return srv.Handler(), env, rec
}

func notionPost(t *testing.T, h http.Handler, env *testenv.Env, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c := env.SessionCookie(); c != nil {
		req.AddCookie(c)
	}
	if tok := env.CSRFToken(); tok != "" {
		req.Header.Set("X-CSRF-Token", tok)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestNotion_OAuthInstallCreatesConnection(t *testing.T) {
	h, env, rec := notionTestServer(t, true)

	// Start: redirect to Notion authorize with the expected params.
	start := notionPost(t, h, env, "/connections/notion/oauth/start", url.Values{
		"id": {"team-notion"}, "display_name": {"Team Notion"},
	})
	if start.Code != http.StatusFound {
		t.Fatalf("start: want 302, got %d (%s)", start.Code, start.Body.String())
	}
	loc, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if q.Get("client_id") != "notion-client-id" || q.Get("response_type") != "code" {
		t.Errorf("authorize query missing client_id/response_type: %v", q)
	}
	if !strings.HasSuffix(q.Get("redirect_uri"), "/oauth/callback") {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	state := q.Get("state")
	if state == "" {
		t.Fatal("no state in authorize redirect")
	}

	// Callback: exchange the code and persist the connection.
	cbReq := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=auth-code-xyz&state="+state, nil)
	if c := env.SessionCookie(); c != nil {
		cbReq.AddCookie(c)
	}
	cb := httptest.NewRecorder()
	h.ServeHTTP(cb, cbReq)
	if cb.Code != http.StatusSeeOther {
		t.Fatalf("callback: want 303, got %d (%s)", cb.Code, cb.Body.String())
	}

	// Token exchange used HTTP Basic and carried the code.
	if !strings.HasPrefix(rec.authHeader, "Basic ") {
		t.Errorf("token exchange Authorization = %q, want Basic", rec.authHeader)
	}
	if !strings.Contains(rec.body, "auth-code-xyz") {
		t.Errorf("token exchange body missing code: %s", rec.body)
	}

	// Connection stored with the bot token + workspace identity.
	conn, err := env.Connections.GetWithConfig("team-notion")
	if err != nil {
		t.Fatalf("connection not created: %v", err)
	}
	if got, _ := conn.Config["api_key"].(string); got != "ntn_installed-token" {
		t.Errorf("api_key = %q, want the exchanged bot token", got)
	}
	if got, _ := conn.Config["workspace_id"].(string); got != "ws-1" {
		t.Errorf("workspace_id = %q, want ws-1", got)
	}
}

func TestNotion_TokenPasteCreatesConnection(t *testing.T) {
	h, env, _ := notionTestServer(t, false) // paste path doesn't need OAuth creds
	rr := notionPost(t, h, env, "/connections/notion/token", url.Values{
		"id": {"pasted-notion"}, "display_name": {"Pasted"}, "token": {"ntn_pasted-token"},
	})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("token paste: want 303, got %d (%s)", rr.Code, rr.Body.String())
	}
	conn, err := env.Connections.GetWithConfig("pasted-notion")
	if err != nil {
		t.Fatalf("connection not created: %v", err)
	}
	if got, _ := conn.Config["api_key"].(string); got != "ntn_pasted-token" {
		t.Errorf("api_key = %q, want the pasted token", got)
	}
}

func TestNotion_OAuthStartRejectedWhenUnconfigured(t *testing.T) {
	h, env, _ := notionTestServer(t, false)
	rr := notionPost(t, h, env, "/connections/notion/oauth/start", url.Values{
		"id": {"x"}, "display_name": {"X"},
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("start without OAuth creds: want 400, got %d", rr.Code)
	}
}

func TestNotion_ConfigureAndClearCreds(t *testing.T) {
	h, env, _ := notionTestServer(t, false)

	cfg := notionPost(t, h, env, "/connections/notion/oauth/configure", url.Values{
		"client_id": {"cid-123"}, "client_secret": {"client-secret-at-least-16"},
	})
	if cfg.Code != http.StatusSeeOther {
		t.Fatalf("configure: want 303, got %d (%s)", cfg.Code, cfg.Body.String())
	}
	creds, err := env.Connections.GetOAuthApp("notion")
	if err != nil || creds == nil || creds.ClientID != "cid-123" {
		t.Fatalf("creds not stored: %+v (err %v)", creds, err)
	}

	clr := notionPost(t, h, env, "/connections/notion/oauth/clear", url.Values{})
	if clr.Code != http.StatusSeeOther {
		t.Fatalf("clear: want 303, got %d", clr.Code)
	}
	if creds, _ := env.Connections.GetOAuthApp("notion"); creds != nil {
		t.Errorf("creds still present after clear: %+v", creds)
	}
}
