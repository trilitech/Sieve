package iampolicies

import (
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	githubconn "github.com/trilitech/Sieve/internal/connectors/github"
	"github.com/trilitech/Sieve/internal/iam"
)

// findOp locates an op's static OperationDef in a connector's taxonomy catalog.
func findOp(t *testing.T, m connector.ConnectorMeta, name string) connector.OperationDef {
	t.Helper()
	for _, op := range m.Operations {
		if op.Name == name {
			return op
		}
	}
	t.Fatalf("op %q not found in %s taxonomy", name, m.Type)
	return connector.OperationDef{}
}

// TestPEP_Integration exercises the COMPLETE PR-D decision flow the way the live
// PEP will, using the REAL github taxonomy + DB-backed storage:
//
//	store policy/filter → BuildEngine → GroupsForRole + iam.BuildRequest (PIP) →
//	Decide → obligations
//
// It proves the switchover logic end to end before the live router edit, and
// validates the P1 owner-scoping + approval obligation against real op defs.
func TestPEP_Integration(t *testing.T) {
	svc := NewService(testDB(t))
	gh := githubconn.Meta()
	getFile := findOp(t, gh, "github_get_file") // Repo resource, ReadOnly
	createPR := findOp(t, gh, "github_create_pr")

	// Owner-scoped read (P1) + approval-gated PR creation, both on connection "ghc".
	if _, err := svc.CreatePolicy("gh-read-acme", "",
		`permit(principal in Sieve::Role::"r1", action in Sieve::Action::"github/read", resource in Sieve::Github::Owner::"ghc/acme");`, true); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePolicy("gh-pr-approval", "",
		`@approval("required") permit(principal in Sieve::Role::"r1", action == Sieve::Action::"github/github_create_pr", resource in Sieve::Github::Owner::"ghc/acme");`, true); err != nil {
		t.Fatal(err)
	}
	eng, err := svc.BuildEngine()
	if err != nil {
		t.Fatal(err)
	}

	// The PEP helper: resolve groups + build the request from the taxonomy.
	decide := func(op connector.OperationDef, params map[string]any) iam.Decision {
		groups, err := svc.GroupsForRole("r1")
		if err != nil {
			t.Fatal(err)
		}
		req := iam.BuildRequest("t1", "r1", groups, "github", "ghc", "active", op, params)
		d, err := eng.Decide(req)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	// read on acme/widgets → allowed (Repo is under Owner ghc/acme).
	if d := decide(getFile, map[string]any{"owner": "acme", "repo": "widgets"}); !d.Allow {
		t.Errorf("read on acme/widgets should be allowed (P1 owner-scope): %s", d.Reason)
	}
	// read on a DIFFERENT owner → denied (owner-scoped).
	if d := decide(getFile, map[string]any{"owner": "evilcorp", "repo": "x"}); d.Allow {
		t.Error("read on evilcorp must be denied — policy is scoped to owner acme")
	}
	// create_pr on acme → allowed WITH approval obligation.
	if d := decide(createPR, map[string]any{"owner": "acme", "repo": "widgets"}); !d.Allow || !d.Obligations.Approval {
		t.Errorf("create_pr on acme should allow+require-approval; allow=%v approval=%v", d.Allow, d.Obligations.Approval)
	}
	// create_pr is not in the read group, so the read policy doesn't cover it on
	// a different owner → denied.
	if d := decide(createPR, map[string]any{"owner": "evilcorp", "repo": "x"}); d.Allow {
		t.Error("create_pr on evilcorp must be denied")
	}
}
