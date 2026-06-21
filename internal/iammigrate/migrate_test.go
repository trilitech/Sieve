package iammigrate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/policy"
)

// --- helpers: build the same legacy config for both engines, and assemble the
// new engine's entity store from the taxonomy (as PR-D's PIP eventually will). ---

func rulesConfigMap(t *testing.T, cfg policy.RulesConfig) map[string]any {
	t.Helper()
	b, _ := json.Marshal(cfg)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// opDefs for the test connector (google). No Resource mappers → connection-level.
var testOps = map[string]connector.OperationDef{
	"list_emails":  {Name: "list_emails", ReadOnly: true},
	"read_email":   {Name: "read_email", ReadOnly: true},
	"send_email":   {Name: "send_email", ReadOnly: false},
	"delete_email": {Name: "delete_email", ReadOnly: false},
	"archive":      {Name: "archive", ReadOnly: false},
}

func newReq(connType, role, conn, token, op string, params map[string]any) iam.Request {
	od := testOps[op]
	pUID, pEnts := iam.PrincipalEntities(token, []string{role})
	aUID, aEnts := iam.ResolveAction(connType, od)
	rUID, rEnts := iam.ResolveResource(connType, conn, od, params)
	ents := append(append(append([]iam.Entity{}, pEnts...), aEnts...), rEnts...)
	return iam.Request{Principal: pUID, Action: aUID, Resource: rUID, Entities: ents, Context: params}
}

// oldDecide runs the legacy rules evaluator.
func oldDecide(t *testing.T, cfg map[string]any, connType, conn, op string, params map[string]any) string {
	t.Helper()
	ev, err := policy.CreateEvaluator("rules", cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ev.Evaluate(context.Background(), &policy.PolicyRequest{
		Operation: op, Connection: conn, Connector: connType, Params: params, Phase: "pre",
	})
	if err != nil {
		t.Fatal(err)
	}
	return d.Action // "allow" | "deny" | "approval_required"
}

// newDecide migrates the config and runs the IAM engine; returns the
// old-evaluator-equivalent action string for direct comparison.
func newDecide(t *testing.T, cfg map[string]any, connType, role, conn, token, op string, params map[string]any) string {
	t.Helper()
	res, err := MigrateRulesBinding(connType, role, conn, PolicyInput{ID: "p", Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	lib := iam.MapFilterLibrary{}
	for _, f := range res.Filters {
		lib[f.Name] = f
	}
	eng, err := iam.NewEngine([]iam.Policy{{ID: "p", Cedar: res.Cedar}}, lib)
	if err != nil {
		t.Fatalf("migrated Cedar did not compile: %v\n%s", err, res.Cedar)
	}
	d, err := eng.Decide(newReq(connType, role, conn, token, op, params))
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case d.Allow && d.Obligations.Approval:
		return "approval_required"
	case d.Allow:
		return "allow"
	default:
		return "deny"
	}
}

// TestDifferential_CommonCase is the spec's key migration safety claim: a
// legacy Operations-based rules policy migrates to Cedar that yields IDENTICAL
// decisions to the old evaluator across a request corpus.
func TestDifferential_CommonCase(t *testing.T) {
	cfg := rulesConfigMap(t, policy.RulesConfig{
		Rules: []policy.Rule{
			{Action: "allow", Match: &policy.RuleMatch{Operations: []string{"list_emails", "read_email"}}},
			{Action: "approval_required", Match: &policy.RuleMatch{Operations: []string{"send_email"}}},
			{Action: "deny", Match: &policy.RuleMatch{Operations: []string{"delete_email"}}},
		},
		DefaultAction: "deny",
	})

	for _, op := range []string{"list_emails", "read_email", "send_email", "delete_email", "archive"} {
		old := oldDecide(t, cfg, "google", "work-gmail", op, nil)
		nu := newDecide(t, cfg, "google", "r1", "work-gmail", "t1", op, nil)
		if old != nu {
			t.Errorf("differential mismatch for %q: old=%s new=%s", op, old, nu)
		}
	}
}

// TestDifferential_H1CatchAllDeny is the regression that proves the H1 fix: a
// trailing catch-all `deny` rule is legacy "default deny" and must NOT become a
// catch-all Cedar forbid (which would override the permits). The differential
// would CATCH a mis-translation: list_emails is allowed by the old evaluator, so
// if migration emitted a catch-all forbid, the new engine would deny it → fail.
func TestDifferential_H1CatchAllDeny(t *testing.T) {
	cfg := rulesConfigMap(t, policy.RulesConfig{
		Rules: []policy.Rule{
			{Action: "allow", Match: &policy.RuleMatch{Operations: []string{"list_emails"}}},
			{Action: "deny"}, // catch-all (nil/empty match) = "deny everything else"
		},
		DefaultAction: "deny",
	})

	cases := map[string]string{
		"list_emails": "allow", // allowed by rule 0; catch-all deny must NOT clobber it
		"send_email":  "deny",  // unmatched → catch-all deny (old) == default deny (new)
		"archive":     "deny",
	}
	for op, want := range cases {
		old := oldDecide(t, cfg, "google", "work-gmail", op, nil)
		nu := newDecide(t, cfg, "google", "r1", "work-gmail", "t1", op, nil)
		if old != want {
			t.Fatalf("test premise wrong: old(%s)=%s want %s", op, old, want)
		}
		if nu != old {
			t.Errorf("H1 differential mismatch for %q: old=%s new=%s (a catch-all forbid would do this)", op, old, nu)
		}
	}

	// And assert the migrator did NOT emit a forbid at all.
	res, _ := MigrateRulesBinding("google", "r1", "work-gmail", PolicyInput{ID: "p", Config: cfg})
	if strings.Contains(res.Cedar, "forbid") {
		t.Errorf("H1: catch-all deny must not produce a forbid; got:\n%s", res.Cedar)
	}
}

// TestMigrate_RichMatchToManual: a rule using a non-Operations match field is
// reported as manual-port, not mis-translated (fail-closed).
func TestMigrate_RichMatchToManual(t *testing.T) {
	cfg := rulesConfigMap(t, policy.RulesConfig{
		Rules: []policy.Rule{
			{Action: "allow", Match: &policy.RuleMatch{Operations: []string{"send_email"}, To: []string{"*@trilitech.com"}}},
		},
		DefaultAction: "deny",
	})
	res, err := MigrateRulesBinding("google", "r1", "work-gmail", PolicyInput{ID: "p", Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Manual) != 1 {
		t.Fatalf("rich-match rule should be a manual-port item, got %d: %+v", len(res.Manual), res.Manual)
	}
	if strings.Contains(res.Cedar, "send_email") {
		t.Error("rich-match rule must NOT be auto-translated (fail-closed)")
	}
}

// TestMigrate_ResponseFilterToLibrary: a rule's ResponseFilter becomes a
// filter-library entry referenced by @filters on the permit.
func TestMigrate_ResponseFilterToLibrary(t *testing.T) {
	cfg := rulesConfigMap(t, policy.RulesConfig{
		Rules: []policy.Rule{
			{Action: "allow", Match: &policy.RuleMatch{Operations: []string{"list_emails"}},
				ResponseFilter: &policy.ResponseFilter{RedactPatterns: []string{`\b\d{16}\b`}}},
		},
		DefaultAction: "deny",
	})
	res, err := MigrateRulesBinding("google", "r1", "work-gmail", PolicyInput{ID: "p", Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Filters) != 1 || res.Filters[0].Kind != iam.KindRedact {
		t.Fatalf("expected one redact filter, got %+v", res.Filters)
	}
	if !strings.Contains(res.Cedar, "@filters(") {
		t.Errorf("permit should reference the filter via @filters; got:\n%s", res.Cedar)
	}
	// The migrated policy must still compile + the engine must resolve the filter.
	lib := iam.MapFilterLibrary{res.Filters[0].Name: res.Filters[0]}
	if _, err := iam.NewEngine([]iam.Policy{{ID: "p", Cedar: res.Cedar}}, lib); err != nil {
		t.Fatalf("migrated policy with @filters did not compile: %v", err)
	}
}

// TestMigrate_DefaultAllow: DefaultAction "allow" appends a broad permit.
func TestMigrate_DefaultAllow(t *testing.T) {
	cfg := rulesConfigMap(t, policy.RulesConfig{
		Rules:         []policy.Rule{{Action: "deny", Match: &policy.RuleMatch{Operations: []string{"send_email"}}}},
		DefaultAction: "allow",
	})
	// old: send_email denied, everything else allowed.
	// new: forbid(send_email) + broad permit → same.
	for op, want := range map[string]string{"send_email": "deny", "list_emails": "allow", "archive": "allow"} {
		old := oldDecide(t, cfg, "google", "work-gmail", op, nil)
		nu := newDecide(t, cfg, "google", "r1", "work-gmail", "t1", op, nil)
		if old != want || nu != want {
			t.Errorf("default-allow %q: old=%s new=%s want %s", op, old, nu, want)
		}
	}
}
