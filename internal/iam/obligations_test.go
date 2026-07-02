package iam

import "testing"

func lib() MapFilterLibrary {
	return MapFilterLibrary{
		"redact-a": {Name: "redact-a", Kind: KindRedact, Order: 20},
		"redact-b": {Name: "redact-b", Kind: KindRedact, Order: 10},
		"scrub":    {Name: "scrub", Kind: KindScriptFilter, Order: 30},
		"guard":    {Name: "guard", Kind: KindScriptGuard},
		"rl":       {Name: "rl", Kind: KindRateLimit},
	}
}

func TestCollect_ApprovalOR(t *testing.T) {
	// approval on the SECOND permit only ⇒ still required (OR).
	obl, err := collectObligations([]map[string]string{
		{},
		{annApproval: "required"},
	}, lib())
	if err != nil {
		t.Fatal(err)
	}
	if !obl.Approval {
		t.Fatal("approval should be required if ANY determining permit requires it")
	}
}

func TestCollect_FilterDedupeAcrossPermits(t *testing.T) {
	// Two permits both naming "redact-a" ⇒ it applies ONCE.
	obl, err := collectObligations([]map[string]string{
		{annFilters: "redact-a scrub"},
		{annFilters: "redact-a guard"},
	}, lib())
	if err != nil {
		t.Fatal(err)
	}
	// post: redact-a + scrub (deduped); guard is pre.
	if len(obl.Post) != 2 {
		t.Fatalf("post = %+v, want 2 (redact-a once, scrub)", obl.Post)
	}
	if len(obl.Guards) != 1 || obl.Guards[0].Name != "guard" {
		t.Fatalf("guards = %+v, want [guard]", obl.Guards)
	}
}

func TestCollect_PostSortedByOrderThenName(t *testing.T) {
	obl, err := collectObligations([]map[string]string{
		{annFilters: "scrub redact-a redact-b"},
	}, lib())
	if err != nil {
		t.Fatal(err)
	}
	// orders: redact-b(10), redact-a(20), scrub(30)
	want := []string{"redact-b", "redact-a", "scrub"}
	if len(obl.Post) != 3 {
		t.Fatalf("post len = %d", len(obl.Post))
	}
	for i, n := range want {
		if obl.Post[i].Name != n {
			t.Errorf("post[%d] = %s, want %s", i, obl.Post[i].Name, n)
		}
	}
}

func TestCollect_GuardsSplit(t *testing.T) {
	obl, err := collectObligations([]map[string]string{
		{annFilters: "guard rl scrub"},
	}, lib())
	if err != nil {
		t.Fatal(err)
	}
	if len(obl.Guards) != 2 { // guard + rl are pre
		t.Fatalf("guards = %+v, want 2", obl.Guards)
	}
	if len(obl.Post) != 1 || obl.Post[0].Name != "scrub" {
		t.Fatalf("post = %+v, want [scrub]", obl.Post)
	}
}

func TestCollect_UnknownFilterFailsClosed(t *testing.T) {
	_, err := collectObligations([]map[string]string{
		{annFilters: "redact-a nope"},
	}, lib())
	if err == nil {
		t.Fatal("unknown filter must error (fail closed)")
	}
}

func TestCollect_AuditLabelJoin(t *testing.T) {
	obl, err := collectObligations([]map[string]string{
		{annAuditLabel: "a"},
		{annAuditLabel: "b"},
		{},
	}, lib())
	if err != nil {
		t.Fatal(err)
	}
	if obl.AuditLabel != "a,b" {
		t.Errorf("audit label = %q, want a,b", obl.AuditLabel)
	}
}

func TestCollect_Empty(t *testing.T) {
	obl, err := collectObligations(nil, lib())
	if err != nil {
		t.Fatal(err)
	}
	if obl.Approval || len(obl.Guards) != 0 || len(obl.Post) != 0 || obl.AuditLabel != "" {
		t.Fatalf("empty input should yield empty obligations, got %+v", obl)
	}
}

// TestCollect_AuditLabelDedup pins that the same @audit_label from two matching
// permits appears once (first-seen order preserved).
func TestCollect_AuditLabelDedup(t *testing.T) {
	perPermit := []map[string]string{
		{"audit_label": "pii"},
		{"audit_label": "money"},
		{"audit_label": "pii"},
	}
	obl, err := collectObligations(perPermit, MapFilterLibrary{})
	if err != nil {
		t.Fatal(err)
	}
	if obl.AuditLabel != "pii,money" {
		t.Errorf("audit labels should dedupe preserving order: got %q want %q", obl.AuditLabel, "pii,money")
	}
}

// TestToValue_HighPrecisionDecimalRounds pins the minor fix: an agent-supplied
// number with more than Cedar's 4-dp precision is ROUNDED, not hard-errored (a
// >4dp value would otherwise fail the whole Decide).
func TestToValue_HighPrecisionDecimalRounds(t *testing.T) {
	if _, err := toValue(3.14159); err != nil {
		t.Errorf(">4dp decimal should round, not error: %v", err)
	}
}
