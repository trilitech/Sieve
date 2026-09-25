package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	gmailconn "github.com/trilitech/Sieve/internal/connectors/gmail"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// newGoogleReauthTestServer wires an admin web server with the gmail ("google")
// connector registered so tests can seed and re-auth Google connections.
func newGoogleReauthTestServer(t *testing.T) (*httptest.Server, *testenv.Env) {
	t.Helper()
	env := testenv.New(t).WithOperator("test-pass", "test-op")
	env.Registry.Register(gmailconn.Meta, gmailconn.Factory)

	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := NewServer(
		env.Tokens, env.Connections, env.Roles,
		env.Registry, env.Approval, env.Audit,
		"", env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "127.0.0.1:0",
	)
	srv.SetAuth(env.Operator, env.Session)
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, env
}

func seedGoogleConn(t *testing.T, env *testenv.Env, id string) {
	t.Helper()
	if err := env.Connections.Add(id, "google", "Work Google", map[string]any{
		"email":         "user@example.com",
		"oauth_token":   map[string]any{"access_token": "ya29.stub", "refresh_token": "r"},
		"client_id":     "stored-cid.apps.googleusercontent.com",
		"client_secret": "stored-secret",
	}); err != nil {
		t.Fatalf("seed google connection: %v", err)
	}
}

// TestReauthPage_Renders proves the dedicated re-auth page renders for a Google
// connection and shows the bound account (so operators know what they're re-authing).
func TestReauthPage_Renders(t *testing.T) {
	ts, env := newGoogleReauthTestServer(t)
	seedGoogleConn(t, env, "g1")

	resp, err := env.AdminClient().Get(ts.URL + "/connections/g1/reauth")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reauth page: want 200, got %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)
	if !strings.Contains(body, "Re-authenticate") || !strings.Contains(body, "user@example.com") {
		t.Errorf("reauth page missing expected content (button / account email)")
	}
}

// TestReauth_DefaultUsesStoredClient proves re-auth with no client fields
// redirects to Google using the connection's STORED client (not a global one).
func TestReauth_DefaultUsesStoredClient(t *testing.T) {
	ts, env := newGoogleReauthTestServer(t)
	seedGoogleConn(t, env, "g1")

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/connections/g1/reauth", nil)
	req.Header.Set("Origin", ts.URL)
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("reauth: want 302 redirect to Google, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "client_id=stored-cid.apps.googleusercontent.com") {
		t.Errorf("reauth must use the STORED client; Location=%s", loc)
	}
}

// TestReauth_HalfSpecifiedClientRejected proves the both-or-neither guard: a
// client_id with no secret (which would build a non-refreshing config) is a 400.
func TestReauth_HalfSpecifiedClientRejected(t *testing.T) {
	ts, env := newGoogleReauthTestServer(t)
	seedGoogleConn(t, env, "g1")

	form := url.Values{"google_client_id": {"new-cid.apps.googleusercontent.com"}} // no secret
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/connections/g1/reauth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("half-specified client on reauth must be 400, got %d", resp.StatusCode)
	}
}

// TestAdd_HalfSpecifiedGoogleClientRejected proves the same guard on the add path.
func TestAdd_HalfSpecifiedGoogleClientRejected(t *testing.T) {
	ts, env := newGoogleReauthTestServer(t)

	form := url.Values{
		"connector_type":   {"google"},
		"id":               {"g2"},
		"display_name":     {"New Google"},
		"google_client_id": {"new-cid.apps.googleusercontent.com"}, // no secret
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/connections/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("half-specified Google client on add must be 400, got %d", resp.StatusCode)
	}
}
