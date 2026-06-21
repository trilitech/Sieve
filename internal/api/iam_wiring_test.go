package api_test

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/roles"
	mockconnector "github.com/trilitech/Sieve/internal/testing/mockconnector"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/tokens"
)

// TestIAMWiring_AllowsPermittedOp proves the IAM engine permits a granted op
// through the live PEP. IAM is the sole authorization engine.
func TestIAMWiring_AllowsPermittedOp(t *testing.T) {
	env := setupIAMRouter(t)
	allowURL := env.url + "/api/v1/connections/mock-conn/ops/list_emails"
	if status, _ := apiPost(t, allowURL, env.tok, "{}"); status != 200 {
		t.Fatalf("expected 200 (IAM permit), got %d", status)
	}
}

// TestIAMWiring_ForbidDenies proves a Cedar forbid is enforced through the live
// PEP: a forbid on mock/send_email denies it while list_emails stays allowed.
func TestIAMWiring_ForbidDenies(t *testing.T) {
	env := setupIAMRouter(t)
	if err := env.settingsSet("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.iam.CreatePolicy("deny-send", "",
		fmt.Sprintf(`@deny_message("sends are blocked") forbid(principal in Sieve::Role::%q, action == Sieve::Action::"mock/send_email", resource);`, env.roleID), true); err != nil {
		t.Fatal(err)
	}

	if status, _ := apiPost(t, env.url+"/api/v1/connections/mock-conn/ops/list_emails", env.tok, "{}"); status != 200 {
		t.Fatalf("list_emails should still be allowed, got %d", status)
	}
	if status, _ := apiPost(t, env.url+"/api/v1/connections/mock-conn/ops/send_email", env.tok, `{"to":"x@y.com","subject":"s","body":"b"}`); status != 403 {
		t.Fatalf("send_email should be forbidden, got %d", status)
	}
}

// --- harness ---

type iamRouterEnv struct {
	url         string
	tok         string
	roleID      string
	iam         *iampolicies.Service
	settingsSet func(k, v string) error
	mock        *mockconnector.Mock
}

func setupIAMRouter(t *testing.T) iamRouterEnv {
	t.Helper()
	env := testenv.New(t)

	env.Mock.SetResponse("list_emails", map[string]any{"emails": []any{}})
	env.Mock.SetResponse("send_email", map[string]any{"id": "sent-1"})

	if err := env.Connections.Add("mock-conn", "mock", "Mock", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	// Binding lists the connection (connectionAllowed) but NO legacy policies.
	role, err := env.Roles.Create("iam-role", []roles.Binding{{ConnectionID: "mock-conn"}})
	if err != nil {
		t.Fatal(err)
	}
	tokRes, err := env.Tokens.Create(&tokens.CreateRequest{Name: "iam-tok", RoleID: role.ID})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := env.IAM.CreatePolicy("allow-mock", "",
		fmt.Sprintf(`permit(principal in Sieve::Role::%q, action, resource in Sieve::Connection::"mock-conn");`, role.ID), true); err != nil {
		t.Fatal(err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	return iamRouterEnv{
		url: srv.URL, tok: tokRes.PlaintextToken, roleID: role.ID, iam: env.IAM,
		settingsSet: env.Settings.Set, mock: env.Mock,
	}
}
