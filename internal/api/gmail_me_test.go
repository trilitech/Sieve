package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/roles"
	mockconn "github.com/trilitech/Sieve/internal/testing/mockconnector"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/tokens"
)

// TestGmailMe_ResolvesToPermittedConnection proves that /gmail/v1/users/me/...
// resolves "me" to a Google account the token is actually PERMITTED to use.
// With two Google connections and a grant scoped to the SECOND, the request
// must succeed against that account — before the fix, "me" blindly took the
// first (ungranted) account, got denied (403), and never tried the granted one,
// making a valid IAM grant unusable via "me".
func TestGmailMe_ResolvesToPermittedConnection(t *testing.T) {
	env := testenv.New(t)

	// A Google-typed mock on the shared registry (used by both the connections
	// service and the router). Its default ops include the read-only list_emails.
	gmock := mockconn.New("google")
	gmock.SetResponse("list_emails", map[string]any{"messages": []any{}})
	env.Registry.Register(gmock.Meta(), gmock.Factory())

	// Two Google accounts; the token is granted read on the SECOND only.
	if err := env.Connections.Add("g1", "google", "First", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if err := env.Connections.Add("g2", "google", "Second", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	role, err := env.Roles.Create("g2reader", []roles.Binding{{ConnectionID: "g2"}})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := env.Tokens.Create(&tokens.CreateRequest{Name: "t", RoleID: role.ID})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: role.ID, Effect: "allow", ConnectorType: "google", OpScope: "read",
		ConnectionIDs: []string{"g2"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreatePolicy("g2-read", "", grant, true); err != nil {
		t.Fatal(err)
	}
	if err := env.Settings.Set("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	resp := doRequest(t, http.MethodGet, srv.URL+"/gmail/v1/users/me/messages", tok.PlaintextToken, "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me should resolve to the permitted account (g2); got %d: %s", resp.StatusCode, body)
	}
}
