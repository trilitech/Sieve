package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	googleconn "github.com/trilitech/Sieve/internal/connectors/gmail"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// newGoogleReauthServer builds a server with one google connection pinned to a
// specific (stale) OAuth client, plus a known server-side client, so the tests
// can assert which client each reauth path re-authorizes against.
func newGoogleReauthServer(t *testing.T) (http.Handler, *testenv.Env) {
	t.Helper()
	t.Setenv("GOOGLE_OAUTH_CLIENT_ID", "server-client.apps.googleusercontent.com")
	t.Setenv("GOOGLE_OAUTH_CLIENT_SECRET", "server-secret")

	env := testenv.New(t).WithOperator("test-pass", "test-op")
	env.Registry.Register(googleconn.Meta, googleconn.Factory)
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := NewServer(
		env.Tokens, env.Connections, env.Roles,
		env.Registry, env.Approval, env.Audit,
		"", env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "127.0.0.1:0",
	)
	srv.SetAuth(env.Operator, env.Session)
	t.Cleanup(srv.Close)

	if err := env.Connections.Add("g1", "google", "Perso Gmail", map[string]any{
		"email":         "someone@example.com",
		"client_id":     "stale-project-client.apps.googleusercontent.com",
		"client_secret": "stale-secret",
		"oauth_token":   map[string]any{"access_token": "a", "refresh_token": "r"},
	}); err != nil {
		t.Fatalf("add google connection: %v", err)
	}
	return srv.Handler(), env
}

// redirectClientID posts to the reauth endpoint and returns the client_id
// carried in the Google consent URL we redirect to.
func redirectClientID(t *testing.T, handler http.Handler, env *testenv.Env, form url.Values) string {
	t.Helper()
	rec := formPost(handler, env, "/connections/g1/reauth", form)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", loc, err)
	}
	if !strings.Contains(u.Host, "google.com") {
		t.Fatalf("expected a Google consent redirect, got %q", loc)
	}
	return u.Query().Get("client_id")
}

// TestReauth_DefaultUsesStoredClient: the plain one-click "Re-authenticate"
// button sends no fields and must stay on the connection's own OAuth client —
// a connection from one Workspace org must not silently jump to another's.
func TestReauth_DefaultUsesStoredClient(t *testing.T) {
	handler, env := newGoogleReauthServer(t)
	got := redirectClientID(t, handler, env, url.Values{})
	if want := "stale-project-client.apps.googleusercontent.com"; got != want {
		t.Errorf("default reauth client_id = %q, want the connection's stored client %q", got, want)
	}
}

// TestReauth_ServerClientSourceNeedsNoCredentials is the UX fix: migrating a
// connection off a retired GCP project must not require the operator to track
// down and paste a client_id/secret. client_source=server alone is enough.
func TestReauth_ServerClientSourceNeedsNoCredentials(t *testing.T) {
	handler, env := newGoogleReauthServer(t)
	got := redirectClientID(t, handler, env, url.Values{"client_source": {"server"}})
	if want := "server-client.apps.googleusercontent.com"; got != want {
		t.Errorf("client_source=server client_id = %q, want the server's client %q "+
			"(migrating must need no pasted credentials)", got, want)
	}
}

// TestReauth_ExplicitClientWins: a pasted client still overrides both, for a
// client the server doesn't hold.
func TestReauth_ExplicitClientWins(t *testing.T) {
	handler, env := newGoogleReauthServer(t)
	got := redirectClientID(t, handler, env, url.Values{
		"client_source":        {"server"}, // explicit paste must beat this
		"google_client_id":     {"byo-client.apps.googleusercontent.com"},
		"google_client_secret": {"byo-secret"},
	})
	if want := "byo-client.apps.googleusercontent.com"; got != want {
		t.Errorf("explicit client_id = %q, want %q", got, want)
	}
}

// TestConnectionsPage_ReauthIsOneClick guards the reported UX bug: the
// connections row must offer a plain one-click Re-authenticate and must NOT
// embed OAuth client credential inputs (which overflowed the table and made
// the operator think they had to supply a client to re-auth at all).
func TestConnectionsPage_ReauthIsOneClick(t *testing.T) {
	handler, env := newGoogleReauthServer(t)
	rec := getRequest(handler, env, "/connections")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /connections = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `action="/connections/g1/reauth"`) {
		t.Error("connections row is missing a Re-authenticate form")
	}
	// The row's old inline migration form carried these placeholders. They are
	// unique to it — the "Add connection" form below uses different ones — so
	// their absence pins the fix without touching the legitimate add-time option.
	for _, gone := range []string{
		"new OAuth client_id (optional)",
		"new OAuth client_secret (optional)",
	} {
		if strings.Contains(body, gone) {
			t.Errorf("connections row still embeds %q; re-auth must be one click, "+
				"with client migration living on the edit page", gone)
		}
	}
	// And the row must link to the edit page, where migration now lives.
	if !strings.Contains(body, `href="/connections/g1/edit"`) {
		t.Error("google row is missing the Edit link that hosts OAuth client migration")
	}
}

// TestConnectionEditPage_ShowsOAuthClients: the edit page surfaces which client
// the connection is pinned to vs. the server's, which is what makes a
// stranded-on-a-retired-project connection diagnosable at a glance.
func TestConnectionEditPage_ShowsOAuthClients(t *testing.T) {
	handler, env := newGoogleReauthServer(t)
	rec := getRequest(handler, env, "/connections/g1/edit")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET edit page = %d (body: %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"stale-project-client.apps.googleusercontent.com", // this connection's client
		"server-client.apps.googleusercontent.com",        // the server's client
		`value="server"`,                                  // the no-credentials migrate action
	} {
		if !strings.Contains(body, want) {
			t.Errorf("edit page missing %q", want)
		}
	}
}
