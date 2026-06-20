package iampolicies

import (
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/iam"
)

func testDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// listEmailsReq builds the entity store + request for a google list_emails call
// on connection c1 by role r1's token, via the taxonomy (as PR-D's PIP will).
func listEmailsReq(connID string) iam.Request {
	op := connector.OperationDef{Name: "list_emails", ReadOnly: true}
	pUID, pEnts := iam.PrincipalEntities("t1", "r1", nil)
	aUID, aEnts := iam.ResolveAction("google", op)
	rUID, rEnts := iam.ResolveResource("google", connID, op, nil)
	ents := append(append(append([]iam.Entity{}, pEnts...), aEnts...), rEnts...)
	return iam.Request{Principal: pUID, Action: aUID, Resource: rUID, Entities: ents}
}

// TestStorage_RoundTrip is the end-to-end PR-C proof: a Cedar policy stored in
// the DB, loaded by the service, compiled into the engine, decides a request.
func TestStorage_RoundTrip(t *testing.T) {
	svc := NewService(testDB(t))

	pol, err := svc.CreatePolicy("read-c1", "read on c1",
		`permit(principal in Sieve::Role::"r1", action in Sieve::Action::"read", resource in Sieve::Connection::"c1");`, true)
	if err != nil {
		t.Fatal(err)
	}

	eng, err := svc.BuildEngine()
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	if d, _ := eng.Decide(listEmailsReq("c1")); !d.Allow {
		t.Fatal("stored policy should allow list_emails on c1")
	}
	if d, _ := eng.Decide(listEmailsReq("other")); d.Allow {
		t.Fatal("policy scoped to c1 must not allow connection 'other'")
	}

	// Disable → rebuild → deny (default).
	if err := svc.SetPolicyEnabled(pol.ID, false); err != nil {
		t.Fatal(err)
	}
	eng2, _ := svc.BuildEngine()
	if d, _ := eng2.Decide(listEmailsReq("c1")); d.Allow {
		t.Fatal("disabled policy must not contribute → default deny")
	}
}

// TestStorage_FilterLibraryRoundTrip: a stored filter is loaded and resolved by
// the engine when a policy references it.
func TestStorage_FilterLibraryRoundTrip(t *testing.T) {
	svc := NewService(testDB(t))
	if _, err := svc.CreateFilter("scrub-ccn", "redact cards", iam.KindRedact, 10,
		map[string]any{"patterns": []string{`\b\d{16}\b`}}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy("read-scrub", "",
		`@filters("scrub-ccn") permit(principal in Sieve::Role::"r1", action in Sieve::Action::"read", resource in Sieve::Connection::"c1");`, true); err != nil {
		t.Fatal(err)
	}
	eng, err := svc.BuildEngine()
	if err != nil {
		t.Fatal(err)
	}
	d, _ := eng.Decide(listEmailsReq("c1"))
	if !d.Allow {
		t.Fatal("should allow")
	}
	if len(d.Obligations.Post) != 1 || d.Obligations.Post[0].Name != "scrub-ccn" {
		t.Fatalf("filter from library not resolved into obligations: %+v", d.Obligations.Post)
	}
}

// TestStorage_RoleGroups: a policy scoped to a role-group matches a role in it.
func TestStorage_RoleGroups(t *testing.T) {
	svc := NewService(testDB(t))
	gid, err := svc.CreateRoleGroup("readers")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.AddRoleToGroup(gid, "r1"); err != nil {
		t.Fatal(err)
	}
	groups, err := svc.GroupsForRole("r1")
	if err != nil || len(groups) != 1 || groups[0] != gid {
		t.Fatalf("GroupsForRole = %v, %v; want [%s]", groups, err, gid)
	}

	if _, err := svc.CreatePolicy("rg-read", "",
		`permit(principal in Sieve::RoleGroup::"`+gid+`", action in Sieve::Action::"read", resource in Sieve::Connection::"c1");`, true); err != nil {
		t.Fatal(err)
	}
	eng, _ := svc.BuildEngine()
	// build request with the role's group in the principal chain
	op := connector.OperationDef{Name: "list_emails", ReadOnly: true}
	pUID, pEnts := iam.PrincipalEntities("t1", "r1", groups)
	aUID, aEnts := iam.ResolveAction("google", op)
	rUID, rEnts := iam.ResolveResource("google", "c1", op, nil)
	ents := append(append(append([]iam.Entity{}, pEnts...), aEnts...), rEnts...)
	d, _ := eng.Decide(iam.Request{Principal: pUID, Action: aUID, Resource: rUID, Entities: ents})
	if !d.Allow {
		t.Fatal("role-group policy should allow a role in the group")
	}
}

// TestStorage_BrokenPolicySurfaces: BuildEngine surfaces an unparseable stored
// policy rather than silently dropping it.
func TestStorage_BrokenPolicySurfaces(t *testing.T) {
	svc := NewService(testDB(t))
	if _, err := svc.CreatePolicy("broken", "", `this is not cedar`, true); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.BuildEngine(); err == nil {
		t.Fatal("BuildEngine should surface a broken policy")
	}
}
