package iam

// H4 spike — verifies the load-bearing cedar-go v1.8.0 mechanics the IAM design
// depends on, BEFORE building the engine on top of them. Run:
//
//	go test ./internal/iam/ -run Spike -v
//
// Each sub-test maps to a design claim in docs/architecture/iam/01-spec.md:
//   - TestSpike_PolicyIDRoundTrip   → §9.3 / review H4 (diag.Reasons → Get → Annotations)
//   - TestSpike_HierarchyFromStore  → §8 / review C3 (no runtime schema; store carries hierarchy)
//   - TestSpike_ForbidOverrides     → §6 (default-deny, forbid-overrides-permit)
//   - TestSpike_SetValuedScopes     → §9.1 (one policy, many connections)
//   - TestSpike_FailOpenGotcha      → §7.6 (optional-attr access errors; permit-cond fail-closed)
//
// This file is the spike; PR-A's real engine reuses the constructors proven here.

import (
	"strconv"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// --- small constructors mirroring what the real engine (entities.go) will build ---

func uid(typ, id string) types.EntityUID {
	return cedar.NewEntityUID(types.EntityType(typ), cedar.String(id))
}

func ent(u types.EntityUID, parents ...types.EntityUID) types.Entity {
	return types.Entity{UID: u, Parents: cedar.NewEntityUIDSet(parents...)}
}

// baseStore builds the static + per-request entities the PIP would assemble.
// CRITICAL (review C3): cedar.Authorize takes NO schema, so action-group
// membership and resource ancestry must live HERE or `in` matches nothing.
func baseStore() types.EntityMap {
	tRead := uid("Sieve::Action", "read")
	tListEmails := uid("Sieve::Action", "google/list_emails")
	tSend := uid("Sieve::Action", "google/send_email")
	connA := uid("Sieve::Connection", "conn-A")
	connB := uid("Sieve::Connection", "conn-B")
	google := uid("Sieve::Connector", "google")
	role := uid("Sieve::Role", "r1")
	tok := uid("Sieve::Token", "t1")
	msgA := uid("Sieve::Google::Message", "conn-A/msg1")

	return types.EntityMap{
		// action hierarchy: list_emails ∈ read ; send_email ∈ (write, omitted)
		tRead:       ent(tRead),
		tListEmails: ent(tListEmails, tRead),
		tSend:       ent(tSend), // deliberately NOT in read
		// resource hierarchy: message → connection → connector
		google: ent(google),
		connA:  ent(connA, google),
		connB:  ent(connB, google),
		msgA:   ent(msgA, connA),
		// principal hierarchy: token → role
		role: ent(role),
		tok:  ent(tok, role),
	}
}

func req(action string, resource types.EntityUID, ctx types.Record) cedar.Request {
	return cedar.Request{
		Principal: uid("Sieve::Token", "t1"),
		Action:    uid("Sieve::Action", action),
		Resource:  resource,
		Context:   ctx,
	}
}

// addPolicies parses a multi-statement document and adds each statement under a
// stable Sieve PolicyID `pol:<name>#<idx>` (mirrors §9.3 assembly).
func addPolicies(t *testing.T, ps *cedar.PolicySet, name, doc string) {
	t.Helper()
	list, err := cedar.NewPolicyListFromBytes(name, []byte(doc))
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	for i, p := range list {
		id := types.PolicyID("pol:" + name + "#" + strconv.Itoa(i))
		ps.Add(id, p)
	}
}

// TestSpike_PolicyIDRoundTrip is the H4 core: a multi-statement policy added
// with our own IDs must come back in diag.Reasons, and Get(id).Annotations()
// must read our @-annotations. The entire obligation + explain chain rides on
// this.
func TestSpike_PolicyIDRoundTrip(t *testing.T) {
	ps := cedar.NewPolicySet()
	addPolicies(t, ps, "p1", `
@id("human-readable")
@filters("scrub-pii redact-card")
permit(
  principal == Sieve::Token::"t1",
  action in Sieve::Action::"read",
  resource in Sieve::Connection::"conn-A"
);

@approval("required")
permit(
  principal == Sieve::Token::"t1",
  action == Sieve::Action::"google/send_email",
  resource in Sieve::Connection::"conn-A"
);
`)

	store := baseStore()
	dec, diag := ps.IsAuthorized(store, req("google/list_emails", uid("Sieve::Google::Message", "conn-A/msg1"), types.Record{}))

	if dec != cedar.Allow {
		t.Fatalf("expected Allow, got %v (errors=%v)", dec, diag.Errors)
	}
	if len(diag.Reasons) != 1 {
		t.Fatalf("expected exactly 1 determining policy, got %d: %+v", len(diag.Reasons), diag.Reasons)
	}
	gotID := diag.Reasons[0].PolicyID
	if gotID != types.PolicyID("pol:p1#0") {
		t.Fatalf("determining PolicyID = %q, want pol:p1#0 (our stable id, NOT cedar's @id)", gotID)
	}

	// Read annotations off the determining policy — the obligation source.
	p := ps.Get(gotID)
	if p == nil {
		t.Fatalf("Get(%q) returned nil", gotID)
	}
	anns := p.Annotations()
	if got := string(anns[types.Ident("filters")]); got != "scrub-pii redact-card" {
		t.Fatalf("@filters annotation = %q, want \"scrub-pii redact-card\"", got)
	}
	t.Logf("round-trip OK: diag.Reasons → %q → @filters=%q, @id=%q",
		gotID, anns[types.Ident("filters")], anns[types.Ident("id")])
}

// TestSpike_HierarchyFromStore proves review-C3: with NO schema passed to
// Authorize, `action in <group>` and `resource in <connector>` resolve purely
// from entity-store parents. If the store omitted the action's `read` parent,
// this would deny — the "mass deny" failure mode.
func TestSpike_HierarchyFromStore(t *testing.T) {
	ps := cedar.NewPolicySet()
	addPolicies(t, ps, "h", `
permit(
  principal in Sieve::Role::"r1",
  action in Sieve::Action::"read",
  resource in Sieve::Connector::"google"
);
`)
	store := baseStore()

	// list_emails is in `read` (via store), message is under google connector
	// (via store ancestry message→conn-A→google), principal token is in r1.
	dec, diag := ps.IsAuthorized(store, req("google/list_emails", uid("Sieve::Google::Message", "conn-A/msg1"), types.Record{}))
	if dec != cedar.Allow {
		t.Fatalf("hierarchy-from-store should ALLOW (action∈read, resource∈google, token∈r1); got %v errors=%v", dec, diag.Errors)
	}

	// send_email is NOT in `read` → same policy must not match → deny.
	dec2, _ := ps.IsAuthorized(store, req("google/send_email", uid("Sieve::Connection", "conn-A"), types.Record{}))
	if dec2 != cedar.Deny {
		t.Fatalf("send_email is not in read group → expected Deny, got %v", dec2)
	}
	t.Log("hierarchy-from-store OK: action-group + resource-ancestry matched with no runtime schema")
}

// TestSpike_ForbidOverrides pins §6: default-deny, and forbid beats permit.
func TestSpike_ForbidOverrides(t *testing.T) {
	store := baseStore()

	// default deny: empty set
	empty := cedar.NewPolicySet()
	if dec, _ := empty.IsAuthorized(store, req("google/list_emails", uid("Sieve::Google::Message", "conn-A/msg1"), types.Record{})); dec != cedar.Deny {
		t.Fatalf("empty policy set must default-deny, got %v", dec)
	}

	// permit + forbid on the same request → deny (forbid wins, order-independent)
	ps := cedar.NewPolicySet()
	addPolicies(t, ps, "f", `
permit(principal in Sieve::Role::"r1", action in Sieve::Action::"read", resource in Sieve::Connector::"google");
forbid(principal in Sieve::Role::"r1", action, resource in Sieve::Google::Message::"conn-A/msg1");
`)
	dec, diag := ps.IsAuthorized(store, req("google/list_emails", uid("Sieve::Google::Message", "conn-A/msg1"), types.Record{}))
	if dec != cedar.Deny {
		t.Fatalf("forbid must override permit, got %v", dec)
	}
	// On deny-by-forbid, the forbid is the determining policy.
	if len(diag.Reasons) != 1 || diag.Reasons[0].PolicyID != types.PolicyID("pol:f#1") {
		t.Fatalf("deny reason should be the forbid pol:f#1, got %+v", diag.Reasons)
	}
	t.Log("forbid-overrides + default-deny OK")
}

// TestSpike_SetValuedScopes pins §9.1 reuse: one policy applies to many
// connections. IMPORTANT FINDING: `resource in [A, B]` is NOT valid in the
// scope (only `action` accepts a set there) — the connection set must live in a
// `when` clause, where `resource in [A, B]` IS a valid membership expression.
func TestSpike_SetValuedScopes(t *testing.T) {
	// Confirm the scope-position set is indeed rejected (so the design knows it
	// must use the when-clause form).
	if _, err := cedar.NewPolicyListFromBytes("bad", []byte(
		`permit(principal, action, resource in [ Sieve::Connection::"a", Sieve::Connection::"b" ]);`,
	)); err == nil {
		t.Fatal("expected `resource in [set]` in SCOPE to be a parse error; cedar-go accepted it — design can use scope form after all")
	}

	// The valid form: connection set in a `when` clause.
	ps := cedar.NewPolicySet()
	addPolicies(t, ps, "s", `
permit(
  principal in Sieve::Role::"r1",
  action in Sieve::Action::"read",
  resource
) when { resource in [ Sieve::Connection::"conn-A", Sieve::Connection::"conn-B" ] };
`)
	store := baseStore()
	store[uid("Sieve::Google::Message", "conn-B/msg9")] = ent(uid("Sieve::Google::Message", "conn-B/msg9"), uid("Sieve::Connection", "conn-B"))

	for _, c := range []string{"conn-A/msg1", "conn-B/msg9"} {
		dec, diag := ps.IsAuthorized(store, req("google/list_emails", uid("Sieve::Google::Message", c), types.Record{}))
		if dec != cedar.Allow {
			t.Fatalf("when-clause connection set should allow %s, got %v errors=%v", c, dec, diag.Errors)
		}
	}
	// A connection NOT in the set is denied (proves the set actually constrains).
	store[uid("Sieve::Google::Message", "conn-C/msgX")] = ent(uid("Sieve::Google::Message", "conn-C/msgX"), uid("Sieve::Connection", "conn-C"))
	store[uid("Sieve::Connection", "conn-C")] = ent(uid("Sieve::Connection", "conn-C"), uid("Sieve::Connector", "google"))
	if dec, _ := ps.IsAuthorized(store, req("google/list_emails", uid("Sieve::Google::Message", "conn-C/msgX"), types.Record{})); dec != cedar.Deny {
		t.Fatalf("conn-C not in set → expected Deny, got %v", dec)
	}
	t.Log("reuse OK via when-clause connection set: allows conn-A & conn-B, denies conn-C")
}

// TestSpike_FailOpenGotcha pins §7.6: accessing an absent optional attribute is
// an evaluation ERROR (policy skipped), so a restriction must be a permit-
// condition (skip ⇒ deny, safe), never a forbid-unless (skip ⇒ allow, unsafe).
func TestSpike_FailOpenGotcha(t *testing.T) {
	store := baseStore()
	r := req("google/send_email", uid("Sieve::Connection", "conn-A"), types.Record{}) // no recipient_domains

	// SAFE: permit-condition. Absent attr (no `has`) → error → permit skipped → deny.
	safe := cedar.NewPolicySet()
	addPolicies(t, safe, "safe", `
permit(principal in Sieve::Role::"r1", action == Sieve::Action::"google/send_email", resource in Sieve::Connection::"conn-A")
when { context.recipient_domains.containsAll([ "trilitech.com" ]) };
`)
	dec, diag := safe.IsAuthorized(store, r)
	if dec != cedar.Deny {
		t.Fatalf("permit-condition with absent attr must DENY (fail-closed), got %v", dec)
	}
	if len(diag.Errors) == 0 {
		t.Fatalf("expected an evaluation error for the absent-attribute access (proves the error-skip mechanic)")
	}
	t.Logf("permit-condition fail-closed OK: absent attr → error (%d) → skip → deny", len(diag.Errors))

	// UNSAFE shape (demonstrates WHY §7.6 bans it): forbid-unless. Absent attr →
	// forbid errors → skipped → NOT denied. We assert it does NOT deny, proving
	// the trap is real.
	unsafe := cedar.NewPolicySet()
	addPolicies(t, unsafe, "unsafe", `
permit(principal in Sieve::Role::"r1", action == Sieve::Action::"google/send_email", resource in Sieve::Connection::"conn-A");
forbid(principal in Sieve::Role::"r1", action == Sieve::Action::"google/send_email", resource in Sieve::Connection::"conn-A")
unless { context.recipient_domains.containsAll([ "trilitech.com" ]) };
`)
	decU, _ := unsafe.IsAuthorized(store, r)
	if decU != cedar.Allow {
		t.Fatalf("EXPECTED the forbid-unless trap to fail OPEN (allow) on absent attr — got %v. "+
			"If this changed, revisit §7.6.", decU)
	}
	t.Log("forbid-unless trap confirmed: absent attr → forbid skipped → fail-OPEN. §7.6 ban justified.")

	// And the has-guarded permit-condition: absent attr → has=false → no error → deny.
	guarded := cedar.NewPolicySet()
	addPolicies(t, guarded, "g", `
permit(principal in Sieve::Role::"r1", action == Sieve::Action::"google/send_email", resource in Sieve::Connection::"conn-A")
when { context has recipient_domains && context.recipient_domains.containsAll([ "trilitech.com" ]) };
`)
	decG, diagG := guarded.IsAuthorized(store, r)
	if decG != cedar.Deny {
		t.Fatalf("has-guarded permit must deny on absent attr, got %v", decG)
	}
	if len(diagG.Errors) != 0 {
		t.Fatalf("has-guard should avoid the eval error, got %d errors", len(diagG.Errors))
	}
	t.Log("has-guarded permit-condition OK: clean deny, no eval error")
}
