package iam

import (
	"testing"
)

// --- taxonomy builder: assembles the entity store a request needs, the way the
// PIP (PR-D) eventually will. Tests declare a small slice of the real taxonomy. ---

type tb struct{ ents map[EntityUID]Entity }

func newTB() *tb { return &tb{ents: map[EntityUID]Entity{}} }

func (b *tb) add(typ, id string, parents ...EntityUID) EntityUID {
	u := EntityUID{Type: typ, ID: id}
	e := b.ents[u]
	e.UID = u
	e.Parents = append(e.Parents, parents...)
	b.ents[u] = e
	return u
}

func (b *tb) attr(u EntityUID, k string, v any) {
	e := b.ents[u]
	if e.Attrs == nil {
		e.Attrs = map[string]any{}
	}
	e.Attrs[k] = v
	b.ents[u] = e
}

func (b *tb) slice() []Entity {
	out := make([]Entity, 0, len(b.ents))
	for _, e := range b.ents {
		out = append(out, e)
	}
	return out
}

// fixture builds a representative google+github taxonomy and returns the builder
// plus the common UIDs tests reference.
func fixture() (*tb, fixtureUIDs) {
	b := newTB()
	// action groups
	read := b.add("Sieve::Action", "read")
	write := b.add("Sieve::Action", "write")
	gmailRead := b.add("Sieve::Action", "google/gmail.read", read)
	gmailWrite := b.add("Sieve::Action", "google/gmail.write", write)
	githubRead := b.add("Sieve::Action", "github/read", read)
	// leaf actions
	listEmails := b.add("Sieve::Action", "google/list_emails", gmailRead)
	sendEmail := b.add("Sieve::Action", "google/send_email", gmailWrite)
	listRepos := b.add("Sieve::Action", "github/github_list_repos", githubRead)
	// connectors + connections
	google := b.add("Sieve::Connector", "google")
	github := b.add("Sieve::Connector", "github")
	work := b.add("Sieve::Connection", "work-gmail", google)
	ops := b.add("Sieve::Connection", "ops-gmail", google)
	ghconn := b.add("Sieve::Connection", "ops-github", github)
	// objects
	workMsg := b.add("Sieve::Google::Message", "work-gmail/m1", work)
	opsMsg := b.add("Sieve::Google::Message", "ops-gmail/m2", ops)
	ghOwner := b.add("Sieve::Github::Owner", "ops-github/trilitech", ghconn)
	ghRepo := b.add("Sieve::Github::Repo", "ops-github/trilitech/sieve", ghOwner)
	// principals
	rg := b.add("Sieve::RoleGroup", "readers")
	role := b.add("Sieve::Role", "assistant", rg)
	tok := b.add("Sieve::Token", "t1", role)

	return b, fixtureUIDs{
		listEmails: listEmails, sendEmail: sendEmail, listRepos: listRepos,
		work: work, ops: ops, ghconn: ghconn, google: google, github: github,
		workMsg: workMsg, opsMsg: opsMsg, ghOwner: ghOwner, ghRepo: ghRepo,
		role: role, rg: rg, tok: tok,
	}
}

type fixtureUIDs struct {
	listEmails, sendEmail, listRepos  EntityUID
	work, ops, ghconn, google, github EntityUID
	workMsg, opsMsg, ghOwner, ghRepo  EntityUID
	role, rg, tok                     EntityUID
}

func mustEngine(t *testing.T, lib FilterLibrary, policies ...Policy) *Engine {
	t.Helper()
	e, err := NewEngine(policies, nil, lib)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// mustEngineG builds a two-pass engine: a plain `grant` (pass 1 allow/deny) plus
// an obligation-bearing `guardrail` (pass 2). This is how obligations are tested
// under the spec §7 model — never as annotations on a grant.
func mustEngineG(t *testing.T, lib FilterLibrary, grant, guardrail string) *Engine {
	t.Helper()
	e, err := NewEngine([]Policy{{ID: "grant", Cedar: grant}}, []Policy{{ID: "guard", Cedar: guardrail}}, lib)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// --- algebraic properties ---

func TestEngine_DefaultDeny(t *testing.T) {
	b, u := fixture()
	e := mustEngine(t, nil) // no policies
	d, err := e.Decide(Request{Principal: u.tok, Action: u.listEmails, Resource: u.workMsg, Entities: b.slice()})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allow {
		t.Fatal("empty policy set must default-deny")
	}
	if len(d.Determining) != 0 {
		t.Errorf("default deny has no determining policies, got %v", d.Determining)
	}
}

// TestEngine_PermitUnion_P0 is THE regression for tezos_ops P0. Two single-
// service read permits (gmail-only and a hypothetical drive-only) must UNION:
// a gmail request is allowed even though the drive policy is silent on it. The
// old AND-of-default-deny model produced an empty intersection here → deny.
func TestEngine_PermitUnion_P0(t *testing.T) {
	b, u := fixture()
	e := mustEngine(t, nil,
		Policy{ID: "gmail-read", Cedar: `permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"google/gmail.read", resource in Sieve::Connection::"work-gmail");`},
		Policy{ID: "github-read", Cedar: `permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"github/read", resource in Sieve::Connection::"ops-github");`},
	)
	// gmail request: allowed by gmail-read; github-read is silent (not a deny).
	d, _ := e.Decide(Request{Principal: u.tok, Action: u.listEmails, Resource: u.workMsg, Entities: b.slice()})
	if !d.Allow {
		t.Fatalf("P0 regression: adding the github policy must NOT deny the gmail request; got deny (%s)", d.Reason)
	}
}

func TestEngine_ForbidOverrides(t *testing.T) {
	b, u := fixture()
	e := mustEngine(t, nil,
		Policy{ID: "read-all", Cedar: `permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"read", resource in Sieve::Connector::"google");`},
		Policy{ID: "block-ops", Cedar: `@deny_message("ops mailbox is off-limits") forbid(principal in Sieve::Role::"assistant", action, resource in Sieve::Connection::"ops-gmail");`},
	)
	// work-gmail allowed
	if d, _ := e.Decide(Request{Principal: u.tok, Action: u.listEmails, Resource: u.workMsg, Entities: b.slice()}); !d.Allow {
		t.Fatal("work-gmail read should be allowed")
	}
	// ops-gmail denied by forbid, with its message
	d, _ := e.Decide(Request{Principal: u.tok, Action: u.listEmails, Resource: u.opsMsg, Entities: b.slice()})
	if d.Allow {
		t.Fatal("ops-gmail must be denied by forbid")
	}
	if d.Reason != "ops mailbox is off-limits" {
		t.Errorf("deny reason = %q, want the @deny_message", d.Reason)
	}
}

// TestEngine_SetScopeReuse pins §9.1: one policy applies to many connections via
// a when-clause set; a connection not in the set is denied.
func TestEngine_SetScopeReuse(t *testing.T) {
	b, u := fixture()
	e := mustEngine(t, nil, Policy{ID: "multi", Cedar: `
permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"google/gmail.read", resource)
when { resource in [ Sieve::Connection::"work-gmail", Sieve::Connection::"ops-gmail" ] };`})

	for _, r := range []EntityUID{u.workMsg, u.opsMsg} {
		if d, _ := e.Decide(Request{Principal: u.tok, Action: u.listEmails, Resource: r, Entities: b.slice()}); !d.Allow {
			t.Fatalf("connection in set must be allowed: %s", r.ID)
		}
	}
	// a third gmail connection not in the set
	work3 := b.add("Sieve::Connection", "third-gmail", u.google)
	m3 := b.add("Sieve::Google::Message", "third-gmail/m3", work3)
	if d, _ := e.Decide(Request{Principal: u.tok, Action: u.listEmails, Resource: m3, Entities: b.slice()}); d.Allow {
		t.Fatal("connection NOT in the set must be denied")
	}
}

// TestEngine_RoleGroup pins that a policy scoped to a role-group matches a token
// whose role is in that group (principal hierarchy from the store).
func TestEngine_RoleGroup(t *testing.T) {
	b, u := fixture()
	e := mustEngine(t, nil, Policy{ID: "rg", Cedar: `permit(principal in Sieve::RoleGroup::"readers", action in Sieve::Action::"read", resource in Sieve::Connector::"google");`})
	if d, _ := e.Decide(Request{Principal: u.tok, Action: u.listEmails, Resource: u.workMsg, Entities: b.slice()}); !d.Allow {
		t.Fatal("token's role is in RoleGroup readers → role-group policy should allow")
	}
}

// --- obligations via the engine ---

func TestEngine_Obligations_ApprovalAndFilters(t *testing.T) {
	b, u := fixture()
	lib := MapFilterLibrary{
		"scrub-pii":  {Name: "scrub-pii", Kind: KindScriptFilter, Order: 10},
		"biz-hours":  {Name: "biz-hours", Kind: KindScriptGuard},
		"redact-ccn": {Name: "redact-ccn", Kind: KindRedact, Order: 5},
	}
	grant := `permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"google/gmail.read", resource in Sieve::Connection::"work-gmail");`
	guard := `
@approval("required")
@filters("scrub-pii biz-hours redact-ccn")
@audit_label("sensitive_read")
permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"google/gmail.read", resource in Sieve::Connection::"work-gmail");`
	e := mustEngineG(t, lib, grant, guard)

	d, _ := e.Decide(Request{Principal: u.tok, Action: u.listEmails, Resource: u.workMsg, Entities: b.slice()})
	if !d.Allow {
		t.Fatal("should allow")
	}
	o := d.Obligations
	if !o.Approval {
		t.Error("approval obligation not collected")
	}
	if len(o.Guards) != 1 || o.Guards[0].Name != "biz-hours" {
		t.Errorf("guards = %+v, want [biz-hours]", o.Guards)
	}
	// post sorted by (order,name): redact-ccn(5) before scrub-pii(10)
	if len(o.Post) != 2 || o.Post[0].Name != "redact-ccn" || o.Post[1].Name != "scrub-pii" {
		t.Errorf("post order wrong: %+v", o.Post)
	}
	if o.AuditLabel != "sensitive_read" {
		t.Errorf("audit label = %q", o.AuditLabel)
	}
}

// TestEngine_Obligations_UnknownFilter_FailsClosed: an @filters reference that
// doesn't resolve must DENY, not allow un-filtered (spec §7.5).
func TestEngine_Obligations_UnknownFilter_FailsClosed(t *testing.T) {
	b, u := fixture()
	grant := `permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"google/gmail.read", resource in Sieve::Connection::"work-gmail");`
	guard := `
@filters("does-not-exist")
permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"google/gmail.read", resource in Sieve::Connection::"work-gmail");`
	e := mustEngineG(t, MapFilterLibrary{}, grant, guard)
	d, _ := e.Decide(Request{Principal: u.tok, Action: u.listEmails, Resource: u.workMsg, Entities: b.slice()})
	if d.Allow {
		t.Fatal("unknown filter reference must fail closed (deny)")
	}
}

// TestEngine_GuardrailFailsSafe: a guardrail whose condition ERRORS (here an
// unguarded access to an absent context attribute) must STILL impose its
// obligation. The engine collects errored guardrails (Reasons ∪ Errors) — the
// mirror of the grant fail-closed rule (spec §7.3/§7.6). Skipping it would
// silently drop the approval (fail-open), the bug this polarity prevents.
func TestEngine_GuardrailFailsSafe(t *testing.T) {
	b, u := fixture()
	grant := `permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"google/gmail.read", resource in Sieve::Connection::"work-gmail");`
	guard := `@approval("required") permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"google/gmail.read", resource in Sieve::Connection::"work-gmail") when { context.nope == "x" };`
	e := mustEngineG(t, nil, grant, guard)
	d, _ := e.Decide(Request{Principal: u.tok, Action: u.listEmails, Resource: u.workMsg, Entities: b.slice()})
	if !d.Allow {
		t.Fatal("grant should allow the read")
	}
	if !d.Obligations.Approval {
		t.Error("an errored guardrail must STILL impose its obligation (fail-safe: Reasons ∪ Errors)")
	}
}

// TestEngine_Monotonicity: obligations can never flip the Cedar decision. The
// same request against the same permit, with and without obligation annotations,
// yields the same Allow value (spec §7 invariant).
func TestEngine_Monotonicity(t *testing.T) {
	b, u := fixture()
	lib := MapFilterLibrary{"scrub": {Name: "scrub", Kind: KindScriptFilter}}
	grant := `permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"google/gmail.read", resource in Sieve::Connection::"work-gmail");`
	bare := mustEngine(t, lib, Policy{ID: "p", Cedar: grant})
	withObl := mustEngineG(t, lib, grant, `@approval("required") @filters("scrub") permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"google/gmail.read", resource in Sieve::Connection::"work-gmail");`)

	r := Request{Principal: u.tok, Action: u.listEmails, Resource: u.workMsg, Entities: b.slice()}
	d1, _ := bare.Decide(r)
	d2, _ := withObl.Decide(r)
	if d1.Allow != d2.Allow {
		t.Fatalf("obligations changed the decision: bare=%v withObl=%v", d1.Allow, d2.Allow)
	}
	if !d2.Obligations.Approval {
		t.Error("expected approval obligation on the annotated policy")
	}
}

// TestEngine_Determining maps a decision back to the source policy statement.
func TestEngine_Determining(t *testing.T) {
	b, u := fixture()
	e := mustEngine(t, nil, Policy{ID: "my-policy", Cedar: `permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"google/gmail.read", resource in Sieve::Connection::"work-gmail");`})
	d, _ := e.Decide(Request{Principal: u.tok, Action: u.listEmails, Resource: u.workMsg, Entities: b.slice()})
	if len(d.Determining) != 1 || d.Determining[0] != "pol:my-policy#0" {
		t.Fatalf("determining = %v, want [pol:my-policy#0]", d.Determining)
	}
}

// TestEngine_BrokenPolicyRejected: NewEngine surfaces a parse error rather than
// silently dropping a malformed policy.
func TestEngine_BrokenPolicyRejected(t *testing.T) {
	_, err := NewEngine([]Policy{{ID: "bad", Cedar: `this is not cedar`}}, nil, nil)
	if err == nil {
		t.Fatal("expected NewEngine to reject unparseable Cedar")
	}
}

// TestEngine_DuplicatePolicyID: two policies sharing an id would collide on the
// cedar PolicyID and silently overwrite; NewEngine must reject loudly.
func TestEngine_DuplicatePolicyID(t *testing.T) {
	p := `permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"read", resource in Sieve::Connector::"google");`
	_, err := NewEngine([]Policy{{ID: "dup", Cedar: p}, {ID: "dup", Cedar: p}}, nil, nil)
	if err == nil {
		t.Fatal("expected NewEngine to reject duplicate policy ids")
	}
}

// TestEngine_ContextConversion exercises the Go→Cedar value conversion through a
// real condition: the §13.2 internal-send pattern. Proves string, []string→Set,
// int→Long, and bool conversions, and the has-guarded fail-closed shape (§7.6).
func TestEngine_ContextConversion(t *testing.T) {
	b, u := fixture()
	// The internal-only restriction is a GRANT condition (it changes allow→deny);
	// the approval is the obligation → a guardrail (spec §7.2).
	grant := `
permit(principal in Sieve::Role::"assistant", action == Sieve::Action::"google/send_email", resource in Sieve::Connection::"work-gmail")
when {
  context has recipient_domains &&
  ["trilitech.com"].containsAll(context.recipient_domains) &&
  context.attempt == 1 &&
  context.urgent == false
};`
	guard := `@approval("required") permit(principal in Sieve::Role::"assistant", action == Sieve::Action::"google/send_email", resource in Sieve::Connection::"work-gmail");`
	e := mustEngineG(t, nil, grant, guard)

	base := func(ctx map[string]any) Request {
		return Request{Principal: u.tok, Action: u.sendEmail, Resource: u.work, Entities: b.slice(), Context: ctx}
	}

	// all internal + scalars match → allow (+ approval obligation)
	if d, err := e.Decide(base(map[string]any{
		"recipient_domains": []string{"trilitech.com"},
		"attempt":           1,
		"urgent":            false,
	})); err != nil || !d.Allow || !d.Obligations.Approval {
		t.Fatalf("internal send should allow with approval; allow=%v approval=%v err=%v", d.Allow, d.Obligations.Approval, err)
	}
	// external recipient → containsAll false → deny
	if d, _ := e.Decide(base(map[string]any{
		"recipient_domains": []string{"trilitech.com", "evil.com"},
		"attempt":           1, "urgent": false,
	})); d.Allow {
		t.Fatal("external recipient must be denied")
	}
	// missing recipient_domains → has-guard false → deny (fail-closed, no error)
	if d, err := e.Decide(base(map[string]any{"attempt": 1, "urgent": false})); err != nil || d.Allow {
		t.Fatalf("absent recipient_domains must deny without error; allow=%v err=%v", d.Allow, err)
	}
}

// TestEngine_BadContextValue: a context value with no Cedar representation
// (e.g. a struct) surfaces an error from Decide (fail-loud → PEP fail-closed),
// rather than silently coercing. A non-integral float is NOT such a value — it
// now projects to a Cedar decimal (spec §4.5/§5.4), verified separately.
func TestEngine_BadContextValue(t *testing.T) {
	b, u := fixture()
	e := mustEngine(t, nil, Policy{ID: "p", Cedar: `permit(principal in Sieve::Role::"assistant", action in Sieve::Action::"read", resource in Sieve::Connector::"google");`})

	// A non-integral float is representable (decimal) — Decide must NOT error.
	if _, err := e.Decide(Request{
		Principal: u.tok, Action: u.listEmails, Resource: u.workMsg, Entities: b.slice(),
		Context: map[string]any{"ratio": 3.14},
	}); err != nil {
		t.Fatalf("a fractional float should project to a decimal, not error: %v", err)
	}

	// An unsupported Go type still fails loud.
	if _, err := e.Decide(Request{
		Principal: u.tok, Action: u.listEmails, Resource: u.workMsg, Entities: b.slice(),
		Context: map[string]any{"weird": struct{ X int }{1}},
	}); err == nil {
		t.Fatal("expected Decide to error on an unsupported context value type")
	}
}
