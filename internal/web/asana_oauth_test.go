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
	asanaconn "github.com/trilitech/Sieve/internal/connectors/asana"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

type asanaExchange struct {
	form string
}

func asanaTestServer(t *testing.T, withOAuthCreds bool) (http.Handler, *testenv.Env, *asanaExchange) {
	t.Helper()
	t.Setenv("ASANA_CLIENT_ID", "")
	t.Setenv("ASANA_CLIENT_SECRET", "")

	env := testenv.New(t).WithOperator("test-pass", "test-op")
	env.Registry.Register(asanaconn.Meta(), asanaconn.Factory())
	if withOAuthCreds {
		if err := env.Connections.PutOAuthApp("asana", connections.OAuthAppCredentials{
			ClientID:     "asana-client-id",
			ClientSecret: "asana-client-secret-16chars",
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

	rec := &asanaExchange{}
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/oauth_token":
			b, _ := io.ReadAll(r.Body)
			rec.form = string(b)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "asana-access-token", "refresh_token": "asana-refresh-token",
				"token_type": "bearer", "expires_in": 3600,
			})
		case "/api/1.0/users/me":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data":{"gid":"1"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(mock.Close)
	asanaOAuthEndpointOverride = mock.URL
	t.Cleanup(func() { asanaOAuthEndpointOverride = "" })

	return srv.Handler(), env, rec
}

func asanaPost(t *testing.T, h http.Handler, env *testenv.Env, path string, form url.Values) *httptest.ResponseRecorder {
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

func TestAsana_OAuthInstallStoresTokenBundle(t *testing.T) {
	h, env, rec := asanaTestServer(t, true)

	start := asanaPost(t, h, env, "/connections/asana/oauth/start", url.Values{
		"id": {"team-asana"}, "display_name": {"Team Asana"},
	})
	if start.Code != http.StatusFound {
		t.Fatalf("start: want 302, got %d (%s)", start.Code, start.Body.String())
	}
	loc, _ := url.Parse(start.Header().Get("Location"))
	q := loc.Query()
	if q.Get("client_id") != "asana-client-id" || q.Get("response_type") != "code" {
		t.Errorf("authorize query missing client_id/response_type: %v", q)
	}
	state := q.Get("state")
	if state == "" {
		t.Fatal("no state in authorize redirect")
	}

	cbReq := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=auth-code-xyz&state="+state, nil)
	if c := env.SessionCookie(); c != nil {
		cbReq.AddCookie(c)
	}
	cb := httptest.NewRecorder()
	h.ServeHTTP(cb, cbReq)
	if cb.Code != http.StatusSeeOther {
		t.Fatalf("callback: want 303, got %d (%s)", cb.Code, cb.Body.String())
	}

	if !strings.Contains(rec.form, "grant_type=authorization_code") || !strings.Contains(rec.form, "code=auth-code-xyz") {
		t.Errorf("token exchange form missing grant_type/code: %s", rec.form)
	}

	conn, err := env.Connections.GetWithConfig("team-asana")
	if err != nil {
		t.Fatalf("connection not created: %v", err)
	}
	tok, _ := conn.Config["oauth_token"].(map[string]any)
	if tok == nil || tok["access_token"] != "asana-access-token" {
		t.Errorf("oauth_token bundle missing/wrong: %v", conn.Config["oauth_token"])
	}
	if tok["refresh_token"] != "asana-refresh-token" {
		t.Errorf("refresh_token not stored: %v", tok)
	}
	if conn.Config["client_id"] != "asana-client-id" || conn.Config["client_secret"] != "asana-client-secret-16chars" {
		t.Errorf("client creds not stored for refresh: %v / %v", conn.Config["client_id"], conn.Config["client_secret"])
	}
}

func TestAsana_TokenPasteCreatesConnection(t *testing.T) {
	h, env, _ := asanaTestServer(t, false)
	rr := asanaPost(t, h, env, "/connections/asana/token", url.Values{
		"id": {"pat-asana"}, "display_name": {"PAT"}, "token": {"1/pasted-pat"},
	})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("token paste: want 303, got %d (%s)", rr.Code, rr.Body.String())
	}
	conn, err := env.Connections.GetWithConfig("pat-asana")
	if err != nil {
		t.Fatalf("connection not created: %v", err)
	}
	if conn.Config["api_key"] != "1/pasted-pat" {
		t.Errorf("api_key = %v, want the pasted token", conn.Config["api_key"])
	}
}

func TestAsana_OAuthStartRejectedWhenUnconfigured(t *testing.T) {
	h, env, _ := asanaTestServer(t, false)
	rr := asanaPost(t, h, env, "/connections/asana/oauth/start", url.Values{
		"id": {"x"}, "display_name": {"X"},
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("start without OAuth creds: want 400, got %d", rr.Code)
	}
}

func TestAsana_ConfigureAndClearCreds(t *testing.T) {
	h, env, _ := asanaTestServer(t, false)
	cfg := asanaPost(t, h, env, "/connections/asana/oauth/configure", url.Values{
		"client_id": {"cid"}, "client_secret": {"client-secret-at-least-16"},
	})
	if cfg.Code != http.StatusSeeOther {
		t.Fatalf("configure: want 303, got %d (%s)", cfg.Code, cfg.Body.String())
	}
	if creds, err := env.Connections.GetOAuthApp("asana"); err != nil || creds == nil || creds.ClientID != "cid" {
		t.Fatalf("creds not stored: %+v (err %v)", creds, err)
	}
	if clr := asanaPost(t, h, env, "/connections/asana/oauth/clear", url.Values{}); clr.Code != http.StatusSeeOther {
		t.Fatalf("clear: want 303, got %d", clr.Code)
	}
	if creds, _ := env.Connections.GetOAuthApp("asana"); creds != nil {
		t.Errorf("creds still present after clear: %+v", creds)
	}
}
