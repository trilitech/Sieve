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
	pUID, pEnts := iam.PrincipalEntities("t1", []string{"r1"})
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

// TestStorage_MultiRoleComposition: a token assigned multiple roles is `in` all
// of them, so a rule targeting ANY one of its roles applies (RBAC union, §5.1).
// This is the composition primitive that replaced role-groups.
func TestStorage_MultiRoleComposition(t *testing.T) {
	svc := NewService(testDB(t))
	if _, err := svc.CreatePolicy("email-read", "",
		`permit(principal in Sieve::Role::"email-access", action in Sieve::Action::"read", resource in Sieve::Connection::"c1");`, true); err != nil {
		t.Fatal(err)
	}
	eng, _ := svc.BuildEngine()
	op := connector.OperationDef{Name: "list_emails", ReadOnly: true}
	// Token assigned BOTH roles; the rule targets only "email-access". The token
	// is `in` email-access (among its set), so the rule applies.
	pUID, pEnts := iam.PrincipalEntities("t1", []string{"llm-access", "email-access"})
	aUID, aEnts := iam.ResolveAction("google", op)
	rUID, rEnts := iam.ResolveResource("google", "c1", op, nil)
	ents := append(append(append([]iam.Entity{}, pEnts...), aEnts...), rEnts...)
	d, _ := eng.Decide(iam.Request{Principal: pUID, Action: aUID, Resource: rUID, Entities: ents})
	if !d.Allow {
		t.Fatal("multi-role token should be allowed by a rule targeting one of its roles")
	}

	// A rule targeting a role the token does NOT have must not apply.
	pUID2, pEnts2 := iam.PrincipalEntities("t2", []string{"llm-access"})
	ents2 := append(append(append([]iam.Entity{}, pEnts2...), aEnts...), rEnts...)
	d2, _ := eng.Decide(iam.Request{Principal: pUID2, Action: aUID, Resource: rUID, Entities: ents2})
	if d2.Allow {
		t.Fatal("token without the targeted role must be denied (default-deny)")
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
