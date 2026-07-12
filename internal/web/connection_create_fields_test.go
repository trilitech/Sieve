package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	linearconn "github.com/trilitech/Sieve/internal/connectors/linear"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

func newLinearCatalogServer(t *testing.T) (*httptest.Server, *testenv.Env) {
	t.Helper()
	env := testenv.New(t).WithOperator("test-pass", "test-op")
	env.Registry.Register(linearconn.Meta(), linearconn.Factory())
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

// TestConnectionsPage_RendersDataDrivenSetupFields is the regression for a
// generic catalog card that collected only alias + display_name: a
// data-driven connector (Linear) declares a required api_key SetupField, but
// the create form rendered no input for it, so submission failed validation
// ("Personal API Key is required") with no field to fill. The generic card
// must render the connector's create-mode SetupFields via the shared partial.
func TestConnectionsPage_RendersDataDrivenSetupFields(t *testing.T) {
	ts, env := newLinearCatalogServer(t)

	resp, err := env.AdminClient().Get(ts.URL + "/connections")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /connections: status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	// The Linear card's create form must carry its connector_type and an
	// input for the declared api_key field (plus base_url), so an operator
	// can actually supply the credential.
	for _, want := range []string{
		`name="connector_type" value="linear"`,
		`name="api_key"`,
		`name="base_url"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("connections page missing %q — Linear SetupField not rendered on the create card", want)
		}
	}
}

// TestConnectionsAdd_LinearPersistsAPIKey proves the full round trip: the
// api_key rendered by the create card is read by handleConnectionAdd and
// stored, so a Linear connection can actually be created from the UI.
func TestConnectionsAdd_LinearPersistsAPIKey(t *testing.T) {
	ts, env := newLinearCatalogServer(t)

	form := url.Values{
		"connector_type": {"linear"},
		"id":             {"my-linear"},
		"display_name":   {"My Linear"},
		"api_key":        {"lin_api_test-not-real"},
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/connections/add", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /connections/add: status %d, body: %s", resp.StatusCode, body)
	}

	conn, err := env.Connections.GetWithConfig("my-linear")
	if err != nil {
		t.Fatalf("Linear connection was not created: %v", err)
	}
	if conn.ConnectorType != "linear" {
		t.Errorf("connector_type = %q, want linear", conn.ConnectorType)
	}
	if got, _ := conn.Config["api_key"].(string); got != "lin_api_test-not-real" {
		t.Errorf("stored api_key = %q, want the submitted value", got)
	}
}
