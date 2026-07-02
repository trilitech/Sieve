package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/roles"
	mockconn "github.com/trilitech/Sieve/internal/testing/mockconnector"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/tokens"
)

// TestDiscoveryFilteredByIAM proves connection/account discovery does not leak
// connections the token has no grant for. With two Google accounts and a grant
// scoped to the SECOND only, GET /api/v1/connections and /gmail/v1/users must
// reveal only the permitted account — before the fix, both listed every
// connection (id/display/status/email) regardless of IAM, and default-deny only
// kicked in later at operation execution.
func TestDiscoveryFilteredByIAM(t *testing.T) {
	env := testenv.New(t)

	gmock := mockconn.New("google")
	gmock.SetResponse("list_emails", map[string]any{"messages": []any{}})
	env.Registry.Register(gmock.Meta(), gmock.Factory())

	if err := env.Connections.Add("g1", "google", "First", map[string]any{"email": "first@x.com"}); err != nil {
		t.Fatal(err)
	}
	if err := env.Connections.Add("g2", "google", "Second", map[string]any{"email": "second@x.com"}); err != nil {
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

	// GET /api/v1/connections — only g2 is discoverable.
	connsBody := readBody(t, doRequest(t, http.MethodGet, srv.URL+"/api/v1/connections", tok.PlaintextToken, ""))
	var conns []map[string]any
	if err := json.Unmarshal([]byte(connsBody), &conns); err != nil {
		t.Fatalf("decode connections: %v (%s)", err, connsBody)
	}
	ids := map[string]bool{}
	for _, c := range conns {
		ids[c["id"].(string)] = true
	}
	if ids["g1"] {
		t.Errorf("g1 (ungranted) must NOT appear in connection discovery: %s", connsBody)
	}
	if !ids["g2"] {
		t.Errorf("g2 (granted) must appear in connection discovery: %s", connsBody)
	}

	// GET /gmail/v1/users — only the permitted account's email leaks.
	usersBody := readBody(t, doRequest(t, http.MethodGet, srv.URL+"/gmail/v1/users", tok.PlaintextToken, ""))
	if strings.Contains(usersBody, "first@x.com") {
		t.Errorf("ungranted account email leaked via /gmail/v1/users: %s", usersBody)
	}
	if !strings.Contains(usersBody, "g2") {
		t.Errorf("granted account should be listed via /gmail/v1/users: %s", usersBody)
	}
}
