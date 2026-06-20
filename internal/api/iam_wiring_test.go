package api_test

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/tokens"
)

// TestIAMWiring_FlagSwitchesEngine proves PR-D end to end at the HTTP layer: the
// SAME request is decided by the IAM engine when iam_enabled="true" and by the
// legacy evaluator otherwise. Setup: the role's binding lists the connection
// (so connectionAllowed passes) but carries NO legacy policies (legacy =
// deny-all); the IAM store has an allow policy. So:
//   - iam ON  → 200 (IAM permit)
//   - iam OFF → 403 (legacy: no policies for the connection)
func TestIAMWiring_FlagSwitchesEngine(t *testing.T) {
	env := setupIAMRouter(t)

	allowURL := env.url + "/api/v1/connections/mock-conn/ops/list_emails"

	// IAM enabled → permit.
	if err := env.settingsSet("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if status, _ := apiPost(t, allowURL, env.tok, "{}"); status != 200 {
		t.Fatalf("iam ON: expected 200 (IAM permit), got %d", status)
	}

	// IAM disabled → legacy path → 403 (the role has no legacy policies).
	if err := env.settingsSet("iam_enabled", "false"); err != nil {
		t.Fatal(err)
	}
	if status, _ := apiPost(t, allowURL, env.tok, "{}"); status != 403 {
		t.Fatalf("iam OFF: expected 403 (legacy deny-all), got %d", status)
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

	iamSvc := iampolicies.NewService(env.DB)
	if _, err := iamSvc.CreatePolicy("allow-mock", "",
		fmt.Sprintf(`permit(principal in Sieve::Role::%q, action, resource in Sieve::Connection::"mock-conn");`, role.ID), true); err != nil {
		t.Fatal(err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	router.SetIAM(iamSvc, env.Registry, env.Settings)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	return iamRouterEnv{
		url: srv.URL, tok: tokRes.PlaintextToken, roleID: role.ID, iam: iamSvc,
		settingsSet: env.Settings.Set,
	}
}
