package iampolicies

import (
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iam"
)

var builderOps = []connector.OperationDef{
	{Name: "list_emails", ReadOnly: true},
	{Name: "read_email", ReadOnly: true},
	{Name: "send_email", ReadOnly: false},
}

// decideOp compiles a rule, builds a REAL Cedar engine from it, and decides a
// request for op on (connType, connID). Proves the generated Cedar is valid
// Cedar and behaves as intended — the answer to "is the builder Cedar-compatible".
func decideEngine(t *testing.T, cedar string) *iam.Engine {
	t.Helper()
	eng, err := iam.NewEngine([]iam.Policy{{ID: "p1", Cedar: cedar}}, iam.MapFilterLibrary{})
	if err != nil {
		t.Fatalf("generated Cedar did NOT compile:\n%s\nerr: %v", cedar, err)
	}
	return eng
}

func reqFor(roleID, connType, connID, op string, readOnly bool) iam.Request {
	return iam.BuildRequest("tok", roleID, nil, connType, connID, "active",
		connector.OperationDef{Name: op, ReadOnly: readOnly}, nil)
}

func TestBuildRuleCedar_ReadAllow(t *testing.T) {
	cedar, err := BuildRuleCedar(RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "google", OpScope: "read",
	}, builderOps)
	if err != nil {
		t.Fatal(err)
	}
	eng := decideEngine(t, cedar)

	if d, _ := eng.Decide(reqFor("R", "google", "work", "list_emails", true)); !d.Allow {
		t.Errorf("read op should be allowed by a read rule\ncedar:\n%s", cedar)
	}
	if d, _ := eng.Decide(reqFor("R", "google", "work", "send_email", false)); d.Allow {
		t.Errorf("write op must NOT be allowed by a read rule")
	}
	// Connector-gating: same role, different connector → not matched.
	if d, _ := eng.Decide(reqFor("R", "github", "gh", "list_emails", true)); d.Allow {
		t.Errorf("a google rule must not apply to a github resource (connector-gating)")
	}
	// Different role → not matched.
	if d, _ := eng.Decide(reqFor("OTHER", "google", "work", "list_emails", true)); d.Allow {
		t.Errorf("rule scoped to role R must not apply to role OTHER")
	}
}

func TestBuildRuleCedar_DenyForbidsOverPermit(t *testing.T) {
	// allow-all + deny-write → write denied, read allowed (forbid overrides).
	allow, _ := BuildRuleCedar(RuleSpec{RoleID: "R", Effect: "allow", ConnectorType: "google", OpScope: "all"}, builderOps)
	deny, _ := BuildRuleCedar(RuleSpec{RoleID: "R", Effect: "deny", ConnectorType: "google", OpScope: "write"}, builderOps)
	eng, err := iam.NewEngine([]iam.Policy{{ID: "a", Cedar: allow}, {ID: "d", Cedar: deny}}, iam.MapFilterLibrary{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if d, _ := eng.Decide(reqFor("R", "google", "work", "list_emails", true)); !d.Allow {
		t.Errorf("read should remain allowed under allow-all + deny-write")
	}
	if d, _ := eng.Decide(reqFor("R", "google", "work", "send_email", false)); d.Allow {
		t.Errorf("write must be denied (forbid overrides permit)")
	}
}

func TestBuildRuleCedar_SpecificOps(t *testing.T) {
	cedar, err := BuildRuleCedar(RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "google",
		OpScope: "specific", Operations: []string{"list_emails"},
	}, builderOps)
	if err != nil {
		t.Fatal(err)
	}
	eng := decideEngine(t, cedar)
	if d, _ := eng.Decide(reqFor("R", "google", "work", "list_emails", true)); !d.Allow {
		t.Errorf("explicitly listed op should be allowed")
	}
	if d, _ := eng.Decide(reqFor("R", "google", "work", "read_email", true)); d.Allow {
		t.Errorf("unlisted op must NOT be allowed by a specific-ops rule")
	}
}

func TestBuildRuleCedar_RequireApproval(t *testing.T) {
	cedar, err := BuildRuleCedar(RuleSpec{
		RoleID: "R", Effect: "require_approval", ConnectorType: "google", OpScope: "write",
	}, builderOps)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cedar, "@approval") {
		t.Fatalf("require_approval must emit an @approval annotation:\n%s", cedar)
	}
	eng := decideEngine(t, cedar)
	d, _ := eng.Decide(reqFor("R", "google", "work", "send_email", false))
	if !d.Allow {
		t.Errorf("require_approval is a permit (gated), should resolve Allow at the engine")
	}
	if !d.Obligations.Approval {
		t.Errorf("require_approval must surface an approval obligation")
	}
}

func TestBuildRuleCedar_SpecificConnections(t *testing.T) {
	cedar, err := BuildRuleCedar(RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "google", OpScope: "all",
		ConnectionIDs: []string{"work"},
	}, builderOps)
	if err != nil {
		t.Fatal(err)
	}
	eng := decideEngine(t, cedar)
	if d, _ := eng.Decide(reqFor("R", "google", "work", "list_emails", true)); !d.Allow {
		t.Errorf("listed connection should be allowed")
	}
	if d, _ := eng.Decide(reqFor("R", "google", "personal", "list_emails", true)); d.Allow {
		t.Errorf("unlisted connection must NOT be allowed (connection-scoped rule)")
	}
}

func TestBuildScopeID(t *testing.T) {
	got := BuildScopeID("{conn}/{owner}/{repo}", "gh", map[string]string{"owner": "trilitech", "repo": "sieve"})
	if got != "gh/trilitech/sieve" {
		t.Errorf("BuildScopeID = %q", got)
	}
}

// ownerReq builds a request whose resource is a GitHub owner (mirrors the
// connector's runtime ResourceMapper id format: "<conn>/<owner>").
func ownerReq(roleID, connID, owner string) iam.Request {
	od := connector.OperationDef{
		Name: "get_repos", ReadOnly: true, ResourceType: "Sieve::Github::Owner",
		Resource: func(cid string, p map[string]any) []connector.ResourceRef {
			return []connector.ResourceRef{{Type: "Sieve::Github::Owner", ID: cid + "/" + owner}}
		},
	}
	return iam.BuildRequest("tok", roleID, nil, "github", connID, "active", od, nil)
}

func TestBuildRuleCedar_ResourceScope(t *testing.T) {
	cedar, err := BuildRuleCedar(RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "github", OpScope: "read",
		Scopes: []ScopeRef{{EntityType: "Sieve::Github::Owner", ID: "gh/trilitech"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	eng := decideEngine(t, cedar)
	if d, _ := eng.Decide(ownerReq("R", "gh", "trilitech")); !d.Allow {
		t.Errorf("owner-scoped read should be allowed for the scoped owner\ncedar:\n%s", cedar)
	}
	if d, _ := eng.Decide(ownerReq("R", "gh", "someone-else")); d.Allow {
		t.Errorf("owner-scoped rule must NOT apply to a different owner")
	}
}

func TestBuildRuleCedar_NumberCondition(t *testing.T) {
	cedar, err := BuildRuleCedar(RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "anthropic", OpScope: "all",
		Conditions: []ConditionInput{{Kind: "number", CtxPath: "context.param.amount", Op: "lte", Value: "1000"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	eng := decideEngine(t, cedar)
	mk := func(amount int) iam.Request {
		return iam.BuildRequest("tok", "R", nil, "anthropic", "ap", "active",
			connector.OperationDef{Name: "complete"}, map[string]any{"amount": amount})
	}
	if d, _ := eng.Decide(mk(500)); !d.Allow {
		t.Errorf("amount 500 <= 1000 should be allowed\ncedar:\n%s", cedar)
	}
	if d, _ := eng.Decide(mk(5000)); d.Allow {
		t.Errorf("amount 5000 must NOT be allowed by a <=1000 rule")
	}
}

func TestBuildRuleCedar_DomainAllowlist(t *testing.T) {
	cedar, err := BuildRuleCedar(RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "google", OpScope: "write",
		Conditions: []ConditionInput{{Kind: "domain_allowlist", CtxPath: "context.recipient_domains", Value: "example.com, trilitech.com"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	eng := decideEngine(t, cedar)
	// Build a send request and inject recipient_domains into context (the PEP
	// enricher does this in the live path).
	mk := func(domains ...string) iam.Request {
		req := iam.BuildRequest("tok", "R", nil, "google", "work", "active",
			connector.OperationDef{Name: "send_email"}, nil)
		set := make([]any, len(domains))
		for i, d := range domains {
			set[i] = d
		}
		if req.Context == nil {
			req.Context = map[string]any{}
		}
		req.Context["recipient_domains"] = set
		return req
	}
	if d, _ := eng.Decide(mk("example.com")); !d.Allow {
		t.Errorf("send to allowed domain should be permitted\ncedar:\n%s", cedar)
	}
	if d, _ := eng.Decide(mk("evil.com")); d.Allow {
		t.Errorf("send to a non-allowlisted domain must be denied")
	}
}

func TestBuildRuleCedar_Filters(t *testing.T) {
	cedar, err := BuildRuleCedar(RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "google", OpScope: "read",
		Filters: []string{"redact-ssn"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cedar, `@filters("redact-ssn")`) {
		t.Fatalf("expected @filters annotation, got:\n%s", cedar)
	}
	lib := iam.MapFilterLibrary{"redact-ssn": iam.Filter{Name: "redact-ssn", Kind: iam.KindRedact}}
	eng, err := iam.NewEngine([]iam.Policy{{ID: "p1", Cedar: cedar}}, lib)
	if err != nil {
		t.Fatalf("compile with filter lib: %v", err)
	}
	d, _ := eng.Decide(reqFor("R", "google", "work", "list_emails", true))
	if !d.Allow {
		t.Fatalf("filtered read should be allowed")
	}
	found := false
	for _, f := range d.Obligations.Post {
		if f.Name == "redact-ssn" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected redact-ssn in post obligations, got %+v", d.Obligations.Post)
	}
}

func TestHumanSummary(t *testing.T) {
	got := HumanSummary(RuleSpec{Effect: "allow", ConnectorType: "google", OpScope: "read"}, "agent", nil)
	want := "Allow read-only operations on google (any connection) — role: agent"
	if got != want {
		t.Errorf("summary = %q want %q", got, want)
	}
}
