package iammigrate_test

import (
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/iammigrate"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// mockReq builds an IAM request for a mock-connector op (as the live PIP would).
func mockReq(roleID, connID, op string, readOnly bool) iam.Request {
	od := connector.OperationDef{Name: op, ReadOnly: readOnly}
	pUID, pEnts := iam.PrincipalEntities("t1", []string{roleID})
	aUID, aEnts := iam.ResolveAction("mock", od)
	rUID, rEnts := iam.ResolveResource("mock", connID, od, nil)
	ents := append(append(append([]iam.Entity{}, pEnts...), aEnts...), rEnts...)
	return iam.Request{Principal: pUID, Action: aUID, Resource: rUID, Entities: ents}
}

// TestMigrateAll_GovernsAgentPath proves the full bridge: a legacy rules policy
// bound to a role → MigrateAll → the IAM engine decides the SAME way the legacy
// rules intended. This is what "Sieve runs on the IAM engine" rests on.
func TestMigrateAll_GovernsAgentPath(t *testing.T) {
	env := testenv.New(t)

	// Legacy setup: allow list_emails/read_email, deny send_email, default deny.
	pol, err := env.Policies.Create("legacy-read", "rules", map[string]any{
		"rules": []any{
			map[string]any{"action": "allow", "match": map[string]any{"operations": []any{"list_emails", "read_email"}}},
			map[string]any{"action": "deny", "match": map[string]any{"operations": []any{"send_email"}}},
		},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Connections.Add("mc", "mock", "Mock", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	role, err := env.Roles.Create("legacy-role", []roles.Binding{{ConnectionID: "mc", PolicyIDs: []string{pol.ID}}})
	if err != nil {
		t.Fatal(err)
	}

	// Migrate everything into IAM.
	iamSvc := iampolicies.NewService(env.DB)
	rep, err := iammigrate.MigrateAll(env.Policies, env.Roles, env.Connections, iamSvc)
	if err != nil {
		t.Fatal(err)
	}
	if rep.PoliciesCreated != 1 {
		t.Fatalf("expected 1 migrated policy, got %d (manual: %+v)", rep.PoliciesCreated, rep.Manual)
	}

	eng, err := iamSvc.BuildEngine()
	if err != nil {
		t.Fatalf("migrated policy did not compile: %v", err)
	}

	cases := []struct {
		op       string
		readOnly bool
		allow    bool
	}{
		{"list_emails", true, true},  // permitted
		{"read_email", true, true},   // permitted
		{"send_email", false, false}, // forbidden
		{"archive", false, false},    // unmatched → default deny
	}
	for _, c := range cases {
		d, err := eng.Decide(mockReq(role.ID, "mc", c.op, c.readOnly))
		if err != nil {
			t.Fatalf("%s: %v", c.op, err)
		}
		if d.Allow != c.allow {
			t.Errorf("migrated decision for %q: allow=%v want %v (reason=%s)", c.op, d.Allow, c.allow, d.Reason)
		}
	}
}
