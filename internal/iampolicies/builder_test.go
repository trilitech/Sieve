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
	eng, err := iam.NewEngine([]iam.Policy{{ID: "p1", Cedar: cedar}}, nil, iam.MapFilterLibrary{})
	if err != nil {
		t.Fatalf("generated Cedar did NOT compile:\n%s\nerr: %v", cedar, err)
	}
	return eng
}

func reqFor(roleID, connType, connID, op string, readOnly bool) iam.Request {
	return iam.BuildRequest("tok", []string{roleID}, connType, connID, "active",
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
	eng, err := iam.NewEngine([]iam.Policy{{ID: "a", Cedar: allow}, {ID: "d", Cedar: deny}}, nil, iam.MapFilterLibrary{})
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
	spec := RuleSpec{RoleID: "R", Effect: "require_approval", ConnectorType: "google", OpScope: "write"}
	// The GRANT carries the obligation directly (grant-scoped). This is safe under
	// composition because the engine UNIONS obligations across all matching permits
	// — a sibling grant can only ADD, never strip (spec §7).
	grant, err := BuildRuleCedar(spec, builderOps)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(grant, "@approval") {
		t.Fatalf("require_approval grant must carry @approval:\n%s", grant)
	}
	// No guardrail needed — the grant alone surfaces the approval obligation.
	eng, err := iam.NewEngine([]iam.Policy{{ID: "g", Cedar: grant}}, nil, iam.MapFilterLibrary{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	d, _ := eng.Decide(reqFor("R", "google", "work", "send_email", false))
	if !d.Allow {
		t.Errorf("the grant should allow the send")
	}
	if !d.Obligations.Approval {
		t.Errorf("the grant must surface an approval obligation")
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
	return iam.BuildRequest("tok", []string{roleID}, "github", connID, "active", od, nil)
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
		return iam.BuildRequest("tok", []string{"R"}, "anthropic", "ap", "active",
			connector.OperationDef{Name: "complete"}, map[string]any{"amount": amount})
	}
	if d, _ := eng.Decide(mk(500)); !d.Allow {
		t.Errorf("amount 500 <= 1000 should be allowed\ncedar:\n%s", cedar)
	}
	if d, _ := eng.Decide(mk(5000)); d.Allow {
		t.Errorf("amount 5000 must NOT be allowed by a <=1000 rule")
	}
}

func TestBuildRuleCedar_OneOfCondition(t *testing.T) {
	cedar, err := BuildRuleCedar(RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "anthropic", OpScope: "all",
		Conditions: []ConditionInput{{Kind: "one_of", CtxPath: "context.param.model", Value: "claude-opus-4-8, claude-sonnet-4-6"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	eng := decideEngine(t, cedar)
	mk := func(model string) iam.Request {
		return iam.BuildRequest("tok", []string{"R"}, "anthropic", "ap", "active",
			connector.OperationDef{Name: "messages_create"}, map[string]any{"model": model})
	}
	if d, _ := eng.Decide(mk("claude-opus-4-8")); !d.Allow {
		t.Errorf("an allowlisted model should be permitted\ncedar:\n%s", cedar)
	}
	if d, _ := eng.Decide(mk("gpt-4")); d.Allow {
		t.Errorf("a model not in the allowlist must be denied")
	}
}

func TestBuildRuleCedar_BoolCondition(t *testing.T) {
	cedar, err := BuildRuleCedar(RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "github", OpScope: "all",
		Conditions: []ConditionInput{{Kind: "bool", CtxPath: "context.param.draft", Value: "true"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	eng := decideEngine(t, cedar)
	mk := func(draft bool) iam.Request {
		return iam.BuildRequest("tok", []string{"R"}, "github", "gh", "active",
			connector.OperationDef{Name: "github_create_pr"}, map[string]any{"draft": draft})
	}
	if d, _ := eng.Decide(mk(true)); !d.Allow {
		t.Errorf("draft=true should satisfy the condition\ncedar:\n%s", cedar)
	}
	if d, _ := eng.Decide(mk(false)); d.Allow {
		t.Errorf("draft=false must be denied (condition requires draft == true)")
	}
}

// TestBuildRuleCedar_OpScopedConditionGuard proves an op-scoped condition binds
// ONLY its ops: a recipient_count cap scoped to send_email, attached to an
// all-operations allow, must NOT fail-close a read op that carries no
// recipient_count — and must still enforce the cap on a send.
func TestBuildRuleCedar_OpScopedConditionGuard(t *testing.T) {
	cedar, err := BuildRuleCedar(RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "google", OpScope: "all",
		Conditions: []ConditionInput{{
			Kind: "number", CtxPath: "context.recipient_count", Op: "lte", Value: "2",
			Ops: []string{"send_email"},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	eng := decideEngine(t, cedar)
	// A read op carries no recipient_count — the op-guard must let it through.
	read := iam.BuildRequest("tok", []string{"R"}, "google", "g", "active",
		connector.OperationDef{Name: "list_emails", ReadOnly: true}, map[string]any{})
	if d, _ := eng.Decide(read); !d.Allow {
		t.Errorf("read op must be allowed (an op-scoped send condition must not fail-close it)\ncedar:\n%s", cedar)
	}
	send := func(n int) iam.Request {
		r := iam.BuildRequest("tok", []string{"R"}, "google", "g", "active",
			connector.OperationDef{Name: "send_email"}, map[string]any{})
		r.Context["recipient_count"] = n // simulate EnrichContext
		return r
	}
	if d, _ := eng.Decide(send(2)); !d.Allow {
		t.Errorf("send within the cap (2<=2) should be allowed")
	}
	if d, _ := eng.Decide(send(5)); d.Allow {
		t.Errorf("send over the cap (5>2) must be denied")
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
		req := iam.BuildRequest("tok", []string{"R"}, "google", "work", "active",
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
	spec := RuleSpec{
		RoleID: "R", Effect: "allow", ConnectorType: "google", OpScope: "read",
		Filters: []string{"redact-ssn"},
	}
	// The grant carries @filters directly (grant-scoped) — composition-safe via
	// the engine's obligation-union, so no companion guardrail is needed.
	grant, err := BuildRuleCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(grant, `@filters("redact-ssn")`) {
		t.Fatalf("grant must carry @filters:\n%s", grant)
	}
	lib := iam.MapFilterLibrary{"redact-ssn": iam.Filter{Name: "redact-ssn", Kind: iam.KindRedact}}
	eng, err := iam.NewEngine([]iam.Policy{{ID: "g", Cedar: grant}}, nil, lib)
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

// TestObligationUnionUnderComposition is the safety proof for grant-level
// obligations: an obligation on role A's grant (approval + redact) is NOT stripped
// by composing role B that grants the SAME action without it. The engine unions
// obligations across all matching permits, so composition can only ADD, never
// remove — the monotonicity invariant that makes filters/approval on a rule safe.
func TestObligationUnionUnderComposition(t *testing.T) {
	grantA, err := BuildRuleCedar(RuleSpec{
		RoleID: "A", Effect: "require_approval", ConnectorType: "google", OpScope: "read",
		Filters: []string{"redact-ssn"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	grantB, err := BuildRuleCedar(RuleSpec{
		RoleID: "B", Effect: "allow", ConnectorType: "google", OpScope: "read",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lib := iam.MapFilterLibrary{"redact-ssn": iam.Filter{Name: "redact-ssn", Kind: iam.KindRedact}}
	eng, err := iam.NewEngine([]iam.Policy{{ID: "a", Cedar: grantA}, {ID: "b", Cedar: grantB}}, nil, lib)
	if err != nil {
		t.Fatal(err)
	}
	// A token in BOTH roles reads — both permits match.
	req := iam.BuildRequest("tok", []string{"A", "B"}, "google", "work", "active",
		connector.OperationDef{Name: "list_emails", ReadOnly: true}, nil)
	d, _ := eng.Decide(req)
	if !d.Allow {
		t.Fatalf("read should be allowed")
	}
	if !d.Obligations.Approval {
		t.Errorf("approval from role A must survive composition with role B (no bypass)")
	}
	found := false
	for _, f := range d.Obligations.Post {
		if f.Name == "redact-ssn" {
			found = true
		}
	}
	if !found {
		t.Errorf("redact from role A must survive composition with role B: %+v", d.Obligations.Post)
	}
}

func TestHumanSummary(t *testing.T) {
	got := HumanSummary(RuleSpec{Effect: "allow", ConnectorType: "google", OpScope: "read"}, "agent", nil)
	want := "Allow read-only operations on google (any connection) — role: agent"
	if got != want {
		t.Errorf("summary = %q want %q", got, want)
	}
}

// TestBuildGuardrailCedar_ConditionalFailsSafe proves the guardrail POLARITY
// (spec §7.6): a conditional guardrail imposes its obligation UNLESS provably
// exempt, and a MISSING attribute keeps the obligation in force (fail-safe).
func TestBuildGuardrailCedar_ConditionalFailsSafe(t *testing.T) {
	// "require approval for sends UNLESS all recipients are internal"
	spec := RuleSpec{
		RoleID: "R", Effect: "require_approval", ConnectorType: "google", OpScope: "write",
		ExemptConditions: []ConditionInput{
			{Kind: "domain_allowlist", CtxPath: "context.recipient_domains", Value: "trilitech.com"},
		},
	}
	guard, err := BuildGuardrailCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(guard, "unless {") || !strings.Contains(guard, "context has recipient_domains") {
		t.Fatalf("guardrail must has-guard the exemption inside an unless clause:\n%s", guard)
	}

	grant, _ := BuildRuleCedar(RuleSpec{RoleID: "R", Effect: "allow", ConnectorType: "google", OpScope: "write"}, nil)
	eng, err := iam.NewEngine(
		[]iam.Policy{{ID: "g", Cedar: grant}},
		[]iam.Policy{{ID: "h", Cedar: guard}},
		iam.MapFilterLibrary{},
	)
	if err != nil {
		t.Fatalf("compile: %v\ngrant:\n%s\nguard:\n%s", err, grant, guard)
	}

	send := func(domains []string) iam.Decision {
		req := iam.BuildRequest("tok", []string{"R"}, "google", "work", "active",
			connector.OperationDef{Name: "send_email"}, nil)
		if req.Context == nil {
			req.Context = map[string]any{}
		}
		if domains != nil {
			req.Context["recipient_domains"] = domains
		}
		d, err := eng.Decide(req)
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
		if !d.Allow {
			t.Fatalf("send should be allowed by the grant; got deny %q", d.Reason)
		}
		return d
	}

	// Attribute ABSENT → not provably exempt → approval STILL imposed (fail-safe).
	if d := send(nil); !d.Obligations.Approval {
		t.Error("absent recipient_domains must still require approval (fail-safe)")
	}
	// All-internal → exempt → no approval.
	if d := send([]string{"trilitech.com"}); d.Obligations.Approval {
		t.Error("all-internal send should be exempt from approval")
	}
	// External present → not exempt → approval imposed.
	if d := send([]string{"evil.com"}); !d.Obligations.Approval {
		t.Error("external send must require approval")
	}
}

// TestBuildGuardrailCedar_DecimalCondition proves fractional thresholds compile
// to a Cedar decimal and compare correctly at runtime (spec §4.5/§5.4).
func TestBuildGuardrailCedar_DecimalCondition(t *testing.T) {
	// "require approval for llm calls UNLESS estimated cost <= 0.5"
	spec := RuleSpec{
		RoleID: "R", Effect: "require_approval", ConnectorType: "anthropic", OpScope: "all",
		ExemptConditions: []ConditionInput{
			{Kind: "number", CtxPath: "context.estimated_cost", Op: "lte", Value: "0.5"},
		},
	}
	guard, err := BuildGuardrailCedar(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(guard, `decimal("0.5")`) {
		t.Fatalf("a fractional threshold must compile to a decimal literal:\n%s", guard)
	}

	grant, _ := BuildRuleCedar(RuleSpec{RoleID: "R", Effect: "allow", ConnectorType: "anthropic", OpScope: "all"}, nil)
	eng, err := iam.NewEngine(
		[]iam.Policy{{ID: "g", Cedar: grant}},
		[]iam.Policy{{ID: "h", Cedar: guard}},
		iam.MapFilterLibrary{},
	)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, guard)
	}

	call := func(cost float64) iam.Decision {
		req := iam.BuildRequest("tok", []string{"R"}, "anthropic", "ap", "active",
			connector.OperationDef{Name: "complete"}, nil)
		if req.Context == nil {
			req.Context = map[string]any{}
		}
		req.Context["estimated_cost"] = cost
		d, err := eng.Decide(req)
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
		if !d.Allow {
			t.Fatalf("call should be allowed by the grant; got deny %q", d.Reason)
		}
		return d
	}

	if d := call(0.3); d.Obligations.Approval {
		t.Error("cheap call (cost 0.3 <= 0.5) should be exempt from approval")
	}
	if d := call(0.7); !d.Obligations.Approval {
		t.Error("expensive call (cost 0.7 > 0.5) must require approval")
	}
}
