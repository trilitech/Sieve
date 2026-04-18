package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/murbard/Sieve/internal/connector"
)

func makeRulesEvaluator(t *testing.T, config map[string]any) Evaluator {
	t.Helper()
	eval, err := CreateEvaluator("rules", config, nil)
	if err != nil {
		t.Fatalf("create rules evaluator: %v", err)
	}
	return eval
}

func TestRulesAllowDeny(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("allowed operation", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "list_emails"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("denied operation", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})
}

func TestRulesFirstMatchWins(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "sending blocked",
			},
			map[string]any{
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("send_email denied by first rule", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
		if dec.Reason != "sending blocked" {
			t.Fatalf("expected reason 'sending blocked', got %q", dec.Reason)
		}
	})

	t.Run("list_emails allowed by second rule", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "list_emails"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})
}

func TestRulesApprovalRequired(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "approval_required",
				"reason": "sending needs approval",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "approval_required" {
		t.Fatalf("expected approval_required, got %s", dec.Action)
	}
	if dec.Reason != "sending needs approval" {
		t.Fatalf("expected reason 'sending needs approval', got %q", dec.Reason)
	}
}

func TestRulesDefaultDeny(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules":          []any{},
		"default_action": "deny",
	})
	ctx := context.Background()

	dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "list_emails"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "deny" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}
}

func TestRulesDefaultAllow(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules":          []any{},
		"default_action": "allow",
	})
	ctx := context.Background()

	dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "anything"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "allow" {
		t.Fatalf("expected allow, got %s", dec.Action)
	}
}

func TestRulesResponseFilters(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"action": "allow",
				"response_filter": map[string]any{
					"exclude_containing": "secret",
				},
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "list_emails"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "allow" {
		t.Fatalf("expected allow, got %s", dec.Action)
	}
	if len(dec.Filters) == 0 {
		t.Fatal("expected at least one response filter")
	}
	if dec.Filters[0].ExcludeContaining != "secret" {
		t.Fatalf("expected filter exclude_containing=secret, got %q", dec.Filters[0].ExcludeContaining)
	}
}

func TestRulesGlobalFilters(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"action": "allow",
			},
		},
		"default_action": "deny",
		"response_filters": []any{
			map[string]any{
				"redact_patterns": []any{`\d{3}-\d{2}-\d{4}`},
			},
		},
	})
	ctx := context.Background()

	dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "read_email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "allow" {
		t.Fatalf("expected allow, got %s", dec.Action)
	}
	if len(dec.Filters) == 0 {
		t.Fatal("expected global response filter")
	}
	found := false
	for _, f := range dec.Filters {
		if len(f.RedactPatterns) > 0 && f.RedactPatterns[0] == `\d{3}-\d{2}-\d{4}` {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected global redact pattern in filters")
	}
}

func TestRulesScriptAction(t *testing.T) {
	// A rule with action=script but a missing script file. The evaluator should
	// not panic; it returns a deny decision because the script cannot run.
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "script",
				"script": map[string]any{
					"command": "python3",
					"path":    "/nonexistent/script.py",
					"timeout": "5s",
				},
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	// Should not panic. The script will fail but the evaluator handles it.
	dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The decision will be deny since the script cannot execute.
	if dec.Action != "deny" {
		t.Fatalf("expected deny for missing script, got %s", dec.Action)
	}
}

func TestRulesOperationMatch(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"read_email", "list_emails"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("read_email matches", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "read_email"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for read_email, got %s", dec.Action)
		}
	})

	t.Run("list_emails matches", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "list_emails"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for list_emails, got %s", dec.Action)
		}
	})

	t.Run("send_email does not match", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny for send_email, got %s", dec.Action)
		}
	})
}

func TestRulesEmptyMatch(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"action": "allow",
				"reason": "catch-all",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches any operation", func(t *testing.T) {
		for _, op := range []string{"list_emails", "send_email", "delete_all", "unknown_op"} {
			dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: op})
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", op, err)
			}
			if dec.Action != "allow" {
				t.Fatalf("expected allow for %s, got %s", op, dec.Action)
			}
			if dec.Reason != "catch-all" {
				t.Fatalf("expected reason 'catch-all' for %s, got %q", op, dec.Reason)
			}
		}
	})
}

func TestRulesInvalidEmptyOperationList(t *testing.T) {
	// A rule with an explicit but empty operations list should match all operations
	// (empty operations = match all, same as nil).
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{}},
				"action": "allow",
				"reason": "empty ops list",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	for _, op := range []string{"list_emails", "send_email", "anything"} {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: op})
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", op, err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for %s with empty operations list, got %s", op, dec.Action)
		}
		if dec.Reason != "empty ops list" {
			t.Fatalf("expected reason 'empty ops list' for %s, got %q", op, dec.Reason)
		}
	}
}

func TestRulesNilMatchMatchesEverything(t *testing.T) {
	// A rule with no match block (nil match) should match every operation.
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"action": "deny",
				"reason": "catch-all deny",
			},
		},
		"default_action": "allow",
	})
	ctx := context.Background()

	for _, op := range []string{"list_emails", "send_email", "delete_everything", ""} {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: op})
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", op, err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny for %q (nil match should match everything), got %s", op, dec.Action)
		}
		if dec.Reason != "catch-all deny" {
			t.Fatalf("expected reason 'catch-all deny' for %q, got %q", op, dec.Reason)
		}
	}
}

func TestRulesFirstDenyShortCircuits(t *testing.T) {
	// When multiple rules exist and the first matching rule denies, subsequent
	// allow rules must NOT override it. First-match-wins semantics.
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "send blocked by rule 1",
			},
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "allow",
				"reason": "this should never fire",
			},
			map[string]any{
				"action": "allow",
				"reason": "catch-all allow",
			},
		},
		"default_action": "allow",
	})
	ctx := context.Background()

	t.Run("send_email denied by first matching rule", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny (first-match-wins), got %s", dec.Action)
		}
		if dec.Reason != "send blocked by rule 1" {
			t.Fatalf("expected reason 'send blocked by rule 1', got %q", dec.Reason)
		}
	})

	t.Run("list_emails allowed by catch-all", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "list_emails"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for list_emails, got %s", dec.Action)
		}
		if dec.Reason != "catch-all allow" {
			t.Fatalf("expected reason 'catch-all allow', got %q", dec.Reason)
		}
	})
}

// --- User story tests ---

// Story 314: Empty operations list matches everything.
func TestStory314_EmptyOperationsListMatchesEverything(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{}},
				"action": "allow",
				"reason": "empty ops matches all",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	for _, op := range []string{"list_emails", "send_email", "delete_everything", "random_op"} {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: op})
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", op, err)
		}
		if dec.Action != "allow" {
			t.Fatalf("story 314: expected allow for %s with empty operations list, got %s", op, dec.Action)
		}
	}
}

// Story 315: Nil match criteria matches everything.
func TestStory315_NilMatchMatchesEverything(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"action": "deny",
				"reason": "nil match catches all",
			},
		},
		"default_action": "allow",
	})
	ctx := context.Background()

	for _, op := range []string{"list_emails", "send_email", "", "unknown"} {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: op})
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", op, err)
		}
		if dec.Action != "deny" {
			t.Fatalf("story 315: nil match should match %q, expected deny got %s", op, dec.Action)
		}
		if dec.Reason != "nil match catches all" {
			t.Fatalf("story 315: expected reason 'nil match catches all', got %q", dec.Reason)
		}
	}
}

// Story 316: Default action is last resort when no rules match.
func TestStory316_DefaultActionIsLastResort(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"read_email"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	// read_email matches the rule
	dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "read_email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "allow" {
		t.Fatalf("story 316: expected allow for read_email, got %s", dec.Action)
	}

	// send_email doesn't match any rule, so default kicks in
	dec, err = eval.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "deny" {
		t.Fatalf("story 316: expected deny (default) for send_email, got %s", dec.Action)
	}
	if dec.Reason != "default policy" {
		t.Fatalf("story 316: expected reason 'default policy', got %q", dec.Reason)
	}
}

// Story 317: First matching rule wins — allow then deny for same op means allow wins.
func TestStory317_FirstMatchWinsAllowThenDeny(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "allow",
				"reason": "allow wins first",
			},
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "deny should not fire",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "allow" {
		t.Fatalf("story 317: first-match-wins should yield allow, got %s", dec.Action)
	}
	if dec.Reason != "allow wins first" {
		t.Fatalf("story 317: expected reason 'allow wins first', got %q", dec.Reason)
	}
}

// Story 55: First-match-wins with deny first — deny then allow means deny wins.
func TestStory55_FirstMatchWinsDenyFirst(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "deny wins first",
			},
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "allow",
				"reason": "allow should not fire",
			},
		},
		"default_action": "allow",
	})
	ctx := context.Background()

	dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "deny" {
		t.Fatalf("story 55: first-match-wins should yield deny, got %s", dec.Action)
	}
	if dec.Reason != "deny wins first" {
		t.Fatalf("story 55: expected reason 'deny wins first', got %q", dec.Reason)
	}
}

// Story 96: Policy with zero rules, default deny → denies everything.
func TestStory96_ZeroRulesDefaultDeny(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules":          []any{},
		"default_action": "deny",
	})
	ctx := context.Background()

	for _, op := range []string{"list_emails", "send_email", "read_email"} {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: op})
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", op, err)
		}
		if dec.Action != "deny" {
			t.Fatalf("story 96: expected deny for %s with zero rules + default deny, got %s", op, dec.Action)
		}
	}
}

// Story 96b: Policy with zero rules, default allow → allows everything.
func TestStory96b_ZeroRulesDefaultAllow(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules":          []any{},
		"default_action": "allow",
	})
	ctx := context.Background()

	for _, op := range []string{"list_emails", "send_email", "delete_all"} {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: op})
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", op, err)
		}
		if dec.Action != "allow" {
			t.Fatalf("story 96b: expected allow for %s with zero rules + default allow, got %s", op, dec.Action)
		}
	}
}

// Story 229: Content filter on deny rule — filters are NOT collected for deny decisions.
func TestStory229_DenyRuleDoesNotCollectFilters(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "blocked",
				"response_filter": map[string]any{
					"exclude_containing": "secret",
				},
				"redact_patterns": []any{`\d{3}-\d{2}-\d{4}`},
			},
		},
		"default_action": "allow",
	})
	ctx := context.Background()

	dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "deny" {
		t.Fatalf("story 229: expected deny, got %s", dec.Action)
	}
	if len(dec.Filters) != 0 {
		t.Fatalf("story 229: deny decisions must not collect filters, got %d filters", len(dec.Filters))
	}
}

// --- Composite evaluator tests ---

// Story 230: Two policies, one allows one denies same op → deny wins.
func TestStory230_CompositeDenyWins(t *testing.T) {
	allowEval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{"action": "allow"},
		},
		"default_action": "deny",
	})
	denyEval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "send blocked by policy B",
			},
		},
		"default_action": "allow",
	})

	composite := &CompositeEvaluator{Evaluators: []Evaluator{allowEval, denyEval}}
	ctx := context.Background()

	dec, err := composite.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "deny" {
		t.Fatalf("story 230: expected deny when one policy denies, got %s", dec.Action)
	}
	if dec.Reason != "send blocked by policy B" {
		t.Fatalf("story 230: expected reason from deny policy, got %q", dec.Reason)
	}
}

// Story 233: Policy A requires approval + Policy B allows → approval_required wins.
func TestStory233_CompositeApprovalRequiredWins(t *testing.T) {
	approvalEval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "approval_required",
				"reason": "needs human approval",
			},
		},
		"default_action": "allow",
	})
	allowEval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{"action": "allow"},
		},
		"default_action": "deny",
	})

	composite := &CompositeEvaluator{Evaluators: []Evaluator{approvalEval, allowEval}}
	ctx := context.Background()

	dec, err := composite.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "approval_required" {
		t.Fatalf("story 233: expected approval_required, got %s", dec.Action)
	}
}

// Story 234: Policy A allows all + Policy B requires approval for send → approval for send, allow for others.
func TestStory234_CompositeSelectiveApproval(t *testing.T) {
	allowAllEval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{"action": "allow"},
		},
		"default_action": "deny",
	})
	sendApprovalEval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "approval_required",
				"reason": "send needs approval",
			},
		},
		"default_action": "allow",
	})

	composite := &CompositeEvaluator{Evaluators: []Evaluator{allowAllEval, sendApprovalEval}}
	ctx := context.Background()

	// send_email requires approval
	dec, err := composite.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "approval_required" {
		t.Fatalf("story 234: expected approval_required for send_email, got %s", dec.Action)
	}

	// list_emails is allowed by both
	dec, err = composite.Evaluate(ctx, &PolicyRequest{Operation: "list_emails"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "allow" {
		t.Fatalf("story 234: expected allow for list_emails, got %s", dec.Action)
	}
}

// Story 352: Two policies with different redaction patterns → both merged.
func TestStory352_CompositeMergedRedactions(t *testing.T) {
	eval1 := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"action": "allow",
				"response_filter": map[string]any{
					"redact_patterns": []any{`\d{3}-\d{2}-\d{4}`},
				},
			},
		},
		"default_action": "deny",
	})
	eval2 := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"action": "allow",
				"response_filter": map[string]any{
					"redact_patterns": []any{`[A-Z]{2}\d{6}`},
				},
			},
		},
		"default_action": "deny",
	})

	composite := &CompositeEvaluator{Evaluators: []Evaluator{eval1, eval2}}
	ctx := context.Background()

	dec, err := composite.Evaluate(ctx, &PolicyRequest{Operation: "read_email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "allow" {
		t.Fatalf("story 352: expected allow, got %s", dec.Action)
	}
	if len(dec.Filters) < 2 {
		t.Fatalf("story 352: expected at least 2 merged filters, got %d", len(dec.Filters))
	}

	// Verify both patterns are present
	patterns := make(map[string]bool)
	for _, f := range dec.Filters {
		for _, p := range f.RedactPatterns {
			patterns[p] = true
		}
	}
	if !patterns[`\d{3}-\d{2}-\d{4}`] {
		t.Fatalf("story 352: SSN pattern missing from merged filters")
	}
	if !patterns[`[A-Z]{2}\d{6}`] {
		t.Fatalf("story 352: ID pattern missing from merged filters")
	}
}

// Story 353: First deny short-circuits — second evaluator never runs.
func TestStory353_CompositeDenyShortCircuits(t *testing.T) {
	denyEval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"action": "deny",
				"reason": "blocked",
			},
		},
		"default_action": "deny",
	})

	callCount := 0
	trackingEval := &trackingEvaluator{
		action:    "allow",
		callCount: &callCount,
	}

	composite := &CompositeEvaluator{Evaluators: []Evaluator{denyEval, trackingEval}}
	ctx := context.Background()

	dec, err := composite.Evaluate(ctx, &PolicyRequest{Operation: "anything"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "deny" {
		t.Fatalf("story 353: expected deny, got %s", dec.Action)
	}
	if callCount != 0 {
		t.Fatalf("story 353: second evaluator should not have been called, but was called %d times", callCount)
	}
}

// trackingEvaluator records whether Evaluate was called.
type trackingEvaluator struct {
	action    string
	callCount *int
}

func (te *trackingEvaluator) Type() string { return "tracking" }

func (te *trackingEvaluator) Evaluate(_ context.Context, _ *PolicyRequest) (*PolicyDecision, error) {
	*te.callCount++
	return &PolicyDecision{Action: te.action}, nil
}

func TestRulesScriptActionMissingScriptConfig(t *testing.T) {
	// A rule with action=script but NO script config at all should deny
	// (fail-closed) rather than panic.
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "script",
				// no "script" key at all
			},
		},
		"default_action": "allow",
	})
	ctx := context.Background()

	dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != "deny" {
		t.Fatalf("expected deny for script action without config, got %s", dec.Action)
	}
	if dec.Reason == "" {
		t.Fatal("expected a non-empty reason for deny decision")
	}
}

func TestRulesFilterActionBehavesLikeAllow(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails"}},
				"action": "filter",
				"reason": "filtered allow",
				"response_filter": map[string]any{
					"exclude_containing": "secret",
				},
				"filter_exclude": "confidential",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("filter action returns allow with filters", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "list_emails"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for filter action, got %s", dec.Action)
		}
		if dec.Reason != "filtered allow" {
			t.Fatalf("expected reason 'filtered allow', got %q", dec.Reason)
		}
		if len(dec.Filters) == 0 {
			t.Fatal("expected filters to be collected for filter action")
		}
		// Should have both the response_filter and the legacy filter_exclude
		foundExclude := false
		foundLegacy := false
		for _, f := range dec.Filters {
			if f.ExcludeContaining == "secret" {
				foundExclude = true
			}
			if f.ExcludeContaining == "confidential" {
				foundLegacy = true
			}
		}
		if !foundExclude {
			t.Fatal("expected response_filter exclude_containing='secret'")
		}
		if !foundLegacy {
			t.Fatal("expected legacy filter_exclude='confidential'")
		}
	})

	t.Run("non-matching op still denied", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{Operation: "send_email"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny for non-matching op, got %s", dec.Action)
		}
	})
}

func TestRulesMatchTo(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"to": []any{"*@company.com"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches company email", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "send_email",
			Params:    map[string]any{"to": "alice@company.com"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for company email, got %s", dec.Action)
		}
	})

	t.Run("rejects external email", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "send_email",
			Params:    map[string]any{"to": "bob@external.com"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny for external email, got %s", dec.Action)
		}
	})
}

func TestRulesMatchModel(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"model": []any{"claude-*"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches claude-sonnet", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "chat",
			Params:    map[string]any{"model": "claude-sonnet"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for claude-sonnet, got %s", dec.Action)
		}
	})

	t.Run("rejects gpt-4", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "chat",
			Params:    map[string]any{"model": "gpt-4"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny for gpt-4, got %s", dec.Action)
		}
	})
}

func TestRulesMatchMaxTokens(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"max_tokens": 1000},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("allows request within limit", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "chat",
			Params:    map[string]any{"max_tokens": float64(500)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for 500 tokens, got %s", dec.Action)
		}
	})

	t.Run("denies request exceeding limit", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "chat",
			Params:    map[string]any{"max_tokens": float64(2000)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny for 2000 tokens exceeding 1000 limit, got %s", dec.Action)
		}
	})
}

func TestRulesMatchPath(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"path": "/v1/*"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches /v1/messages", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "proxy",
			Params:    map[string]any{"path": "/v1/messages"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for /v1/messages, got %s", dec.Action)
		}
	})

	t.Run("rejects /v2/chat", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "proxy",
			Params:    map[string]any{"path": "/v2/chat"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny for /v2/chat, got %s", dec.Action)
		}
	})
}

func TestRulesMatchBucket(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"bucket": "prod-*"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches prod-data", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "s3_get",
			Params:    map[string]any{"bucket": "prod-data"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for prod-data, got %s", dec.Action)
		}
	})

	t.Run("rejects dev-data", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "s3_get",
			Params:    map[string]any{"bucket": "dev-data"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny for dev-data, got %s", dec.Action)
		}
	})
}

// --- New field tests (stories 389-412) ---

func TestRulesMatchMimeType(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"mime_type": "application/pdf"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches exact mime type", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "drive_download",
			Params:    map[string]any{"mime_type": "application/pdf"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("rejects non-matching mime type", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "drive_download",
			Params:    map[string]any{"mime_type": "image/png"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})
}

func TestRulesMatchMimeTypeGlob(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"mime_type": "application/*"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("glob matches application/json", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "drive_download",
			Params:    map[string]any{"mime_type": "application/json"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("glob rejects image/png", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "drive_download",
			Params:    map[string]any{"mime_type": "image/png"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})
}

func TestRulesMatchOwner(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"owner": "*@company.com"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches company owner", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "drive_list",
			Params:    map[string]any{"owner": "alice@company.com"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("rejects external owner", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "drive_list",
			Params:    map[string]any{"owner": "bob@external.com"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})
}

func TestRulesMatchCalendarID(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"calendar_id": "primary"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches primary calendar", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "calendar_list_events",
			Params:    map[string]any{"calendar_id": "primary"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("rejects other calendar", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "calendar_list_events",
			Params:    map[string]any{"calendar_id": "work-shared"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})
}

func TestRulesMatchAttendee(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"attendee": "*@company.com"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches company attendee", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "calendar_create_event",
			Params:    map[string]any{"attendee": "alice@company.com"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("rejects external attendee", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "calendar_create_event",
			Params:    map[string]any{"attendee": "bob@external.com"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})
}

func TestRulesMatchSpreadsheetID(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"spreadsheet_id": "abc123"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches exact spreadsheet", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "sheets_read",
			Params:    map[string]any{"spreadsheet_id": "abc123"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("rejects different spreadsheet", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "sheets_read",
			Params:    map[string]any{"spreadsheet_id": "xyz789"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})
}

func TestRulesMatchDocumentID(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"document_id": "doc-001"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches exact document", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "docs_read",
			Params:    map[string]any{"document_id": "doc-001"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("rejects different document", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "docs_read",
			Params:    map[string]any{"document_id": "doc-999"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})
}

func TestRulesMatchTitleContains(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"title_contains": "budget"},
				"action": "deny",
				"reason": "budget docs restricted",
			},
		},
		"default_action": "allow",
	})
	ctx := context.Background()

	t.Run("matches title containing budget (case-insensitive)", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "docs_read",
			Params:    map[string]any{"title": "Q4 Budget Report"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})

	t.Run("allows title without budget", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "docs_read",
			Params:    map[string]any{"title": "Meeting Notes"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})
}

func TestRulesMatchMaxCount(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"max_count": 5},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("allows count within limit", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_run_instances",
			Params:    map[string]any{"max_count": float64(3)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("denies count exceeding limit", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_run_instances",
			Params:    map[string]any{"max_count": float64(10)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})

	t.Run("falls back to count param", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_run_instances",
			Params:    map[string]any{"count": float64(2)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for count=2, got %s", dec.Action)
		}
	})
}

func TestRulesMatchAMI(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"ami": "ami-approved-*"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches approved AMI", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_run_instances",
			Params:    map[string]any{"ami": "ami-approved-12345"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("rejects unapproved AMI", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_run_instances",
			Params:    map[string]any{"ami": "ami-random-99999"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})

	t.Run("falls back to image_id param", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_run_instances",
			Params:    map[string]any{"image_id": "ami-approved-67890"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for image_id fallback, got %s", dec.Action)
		}
	})
}

func TestRulesMatchVPC(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"vpc": "vpc-prod-001"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches vpc_id", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_run_instances",
			Params:    map[string]any{"vpc_id": "vpc-prod-001"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("rejects wrong vpc", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_run_instances",
			Params:    map[string]any{"vpc_id": "vpc-dev-002"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})

	t.Run("falls back to subnet_id", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_run_instances",
			Params:    map[string]any{"subnet_id": "vpc-prod-001"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for subnet_id fallback, got %s", dec.Action)
		}
	})
}

func TestRulesMatchPorts(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"ports": "80,443,8080"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("allows port in list", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_authorize_security_group",
			Params:    map[string]any{"port": "443"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for port 443, got %s", dec.Action)
		}
	})

	t.Run("denies port not in list", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_authorize_security_group",
			Params:    map[string]any{"port": "22"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny for port 22, got %s", dec.Action)
		}
	})

	t.Run("handles numeric port param", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_authorize_security_group",
			Params:    map[string]any{"port": float64(80)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for numeric port 80, got %s", dec.Action)
		}
	})
}

func TestRulesMatchCIDR(t *testing.T) {
	// Test negation pattern: deny 0.0.0.0/0
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"cidr": "!0.0.0.0/0"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("allows specific CIDR", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_authorize_security_group",
			Params:    map[string]any{"cidr": "10.0.0.0/16"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for 10.0.0.0/16, got %s", dec.Action)
		}
	})

	t.Run("denies 0.0.0.0/0", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_authorize_security_group",
			Params:    map[string]any{"cidr": "0.0.0.0/0"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny for 0.0.0.0/0, got %s", dec.Action)
		}
	})
}

func TestRulesMatchCIDRExact(t *testing.T) {
	// Test exact match pattern (non-negated)
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"cidr": "10.0.0.0/8"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches exact CIDR", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_authorize_security_group",
			Params:    map[string]any{"cidr": "10.0.0.0/8"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("rejects different CIDR", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ec2_authorize_security_group",
			Params:    map[string]any{"cidr": "172.16.0.0/12"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})
}

func TestRulesMatchFunctionName(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"function_name": "prod-*"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches prod function", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "lambda_invoke",
			Params:    map[string]any{"function_name": "prod-handler"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("rejects dev function", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "lambda_invoke",
			Params:    map[string]any{"function_name": "dev-handler"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})
}

func TestRulesMatchRecipient(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"recipient": "*@company.com"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches company recipient", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ses_send",
			Params:    map[string]any{"recipient": "alice@company.com"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("rejects external recipient", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ses_send",
			Params:    map[string]any{"recipient": "bob@external.com"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})

	t.Run("falls back to to param", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "ses_send",
			Params:    map[string]any{"to": "carol@company.com"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for to fallback, got %s", dec.Action)
		}
	})
}

func TestRulesMatchTableName(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"table_name": "users"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches exact table name", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "dynamodb_query",
			Params:    map[string]any{"table_name": "users"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("rejects different table", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "dynamodb_query",
			Params:    map[string]any{"table_name": "secrets"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})

	t.Run("falls back to table param", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "dynamodb_query",
			Params:    map[string]any{"table": "users"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow for table fallback, got %s", dec.Action)
		}
	})
}

func TestRulesMatchFlavor(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"flavor": "n1-standard-4"},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("matches exact flavor", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "hyperstack_create_vm",
			Params:    map[string]any{"flavor": "n1-standard-4"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("rejects different flavor", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "hyperstack_create_vm",
			Params:    map[string]any{"flavor": "n1-highcpu-16"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})
}

func TestRulesMatchMaxVMs(t *testing.T) {
	eval := makeRulesEvaluator(t, map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"max_vms": 3},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	ctx := context.Background()

	t.Run("allows count within limit", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "hyperstack_create_vm",
			Params:    map[string]any{"count": float64(2)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "allow" {
			t.Fatalf("expected allow, got %s", dec.Action)
		}
	})

	t.Run("denies count exceeding limit", func(t *testing.T) {
		dec, err := eval.Evaluate(ctx, &PolicyRequest{
			Operation: "hyperstack_create_vm",
			Params:    map[string]any{"count": float64(5)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Action != "deny" {
			t.Fatalf("expected deny, got %s", dec.Action)
		}
	})
}

// --- Security audit tests ---

// Audit issue 3: Agent sends "from" as array instead of string to bypass policy.
// Before fix: type assertion silently failed, rule didn't match, policy bypassed.
// After fix: getStringParamSafe extracts first element from arrays.
func TestAudit_TypeMismatchFromBypass(t *testing.T) {
	config := map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"read_email"}, "from": []any{"*@company.com"}},
				"action": "deny",
				"reason": "only company emails",
			},
		},
		"default_action": "allow",
	}
	eval, err := NewRulesEvaluator(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// String type — should be denied.
	dec, _ := eval.Evaluate(ctx, &PolicyRequest{
		Operation: "read_email",
		Params:    map[string]any{"from": "alice@company.com"},
	})
	if dec.Action != "deny" {
		t.Fatalf("expected deny for string from, got %s", dec.Action)
	}

	// Array type — should ALSO be denied (first element extracted).
	dec, _ = eval.Evaluate(ctx, &PolicyRequest{
		Operation: "read_email",
		Params:    map[string]any{"from": []any{"bob@company.com"}},
	})
	if dec.Action != "deny" {
		t.Fatalf("expected deny for array from (type mismatch should not bypass), got %s", dec.Action)
	}

	// []string type — should ALSO be denied.
	dec, _ = eval.Evaluate(ctx, &PolicyRequest{
		Operation: "read_email",
		Params:    map[string]any{"from": []string{"carol@company.com"}},
	})
	if dec.Action != "deny" {
		t.Fatalf("expected deny for []string from, got %s", dec.Action)
	}
}

// Audit issue 3b: Same bypass for "to" field.
func TestAudit_TypeMismatchToBypass(t *testing.T) {
	config := map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}, "to": []any{"*@company.com"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	}
	eval, err := NewRulesEvaluator(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Array to — should match.
	dec, _ := eval.Evaluate(ctx, &PolicyRequest{
		Operation: "send_email",
		Params:    map[string]any{"to": []any{"alice@company.com"}},
	})
	if dec.Action != "allow" {
		t.Fatalf("expected allow for array to matching pattern, got %s", dec.Action)
	}

	// External via array — should be denied.
	dec, _ = eval.Evaluate(ctx, &PolicyRequest{
		Operation: "send_email",
		Params:    map[string]any{"to": []any{"hacker@evil.com"}},
	})
	if dec.Action != "deny" {
		t.Fatalf("expected deny for external array to, got %s", dec.Action)
	}
}

// Audit issue 4: Integer overflow in max_tokens.
// Before fix: huge float64 wraps to negative int, passes the limit check.
// After fix: getIntParam clamps to MaxInt32.
func TestAudit_IntegerOverflowMaxTokens(t *testing.T) {
	config := map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"chat"}, "max_tokens": 1000},
				"action": "allow",
			},
		},
		"default_action": "deny",
	}
	eval, err := NewRulesEvaluator(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Normal value within limit — allowed.
	dec, _ := eval.Evaluate(ctx, &PolicyRequest{
		Operation: "chat",
		Params:    map[string]any{"max_tokens": float64(500)},
	})
	if dec.Action != "allow" {
		t.Fatalf("expected allow for 500 tokens, got %s", dec.Action)
	}

	// Huge float64 that would overflow int — should be denied (clamped to MaxInt32).
	dec, _ = eval.Evaluate(ctx, &PolicyRequest{
		Operation: "chat",
		Params:    map[string]any{"max_tokens": float64(9999999999999999)},
	})
	if dec.Action != "deny" {
		t.Fatalf("expected deny for overflow max_tokens, got %s", dec.Action)
	}

	// Negative value — should be treated as 0 (within limit), allowed.
	dec, _ = eval.Evaluate(ctx, &PolicyRequest{
		Operation: "chat",
		Params:    map[string]any{"max_tokens": float64(-100)},
	})
	if dec.Action != "allow" {
		t.Fatalf("expected allow for negative max_tokens (clamped to 0), got %s", dec.Action)
	}
}

// Audit issue 4b: Negative max_cost bypass.
func TestAudit_NegativeMaxCost(t *testing.T) {
	config := map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"chat"}, "max_cost": 0.10},
				"action": "allow",
			},
		},
		"default_action": "deny",
	}
	eval, err := NewRulesEvaluator(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Normal cost — allowed.
	dec, _ := eval.Evaluate(ctx, &PolicyRequest{
		Operation: "chat",
		Params:    map[string]any{"max_cost": float64(0.05)},
	})
	if dec.Action != "allow" {
		t.Fatalf("expected allow for $0.05, got %s", dec.Action)
	}

	// Negative cost — should be clamped to 0 (within limit).
	dec, _ = eval.Evaluate(ctx, &PolicyRequest{
		Operation: "chat",
		Params:    map[string]any{"max_cost": float64(-1000)},
	})
	if dec.Action != "allow" {
		t.Fatalf("expected allow for negative cost (clamped to 0), got %s", dec.Action)
	}
}

// --- Policy validation tests ---

func TestValidatePolicy_ValidGmailRule(t *testing.T) {
	ops := []connector.OperationDef{
		{Name: "send_email", Params: map[string]connector.ParamDef{"to": {Type: "[]string"}, "subject": {Type: "string"}, "body": {Type: "string"}}},
		{Name: "list_emails", Params: map[string]connector.ParamDef{"query": {Type: "string"}, "max_results": {Type: "int"}}},
	}

	config := map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}, "to": []any{"*@company.com"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	}

	errs := ValidatePolicy(config, ops)
	if len(errs) != 0 {
		t.Fatalf("expected valid policy, got errors: %v", errs)
	}
}

func TestValidatePolicy_InvalidFilterForOperation(t *testing.T) {
	ops := []connector.OperationDef{
		{Name: "send_email", Params: map[string]connector.ParamDef{"to": {Type: "[]string"}, "subject": {Type: "string"}}},
		{Name: "list_emails", Params: map[string]connector.ParamDef{"query": {Type: "string"}}},
	}

	config := map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails"}, "to": []any{"*@company.com"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	}

	errs := ValidatePolicy(config, ops)
	if len(errs) == 0 {
		t.Fatal("expected validation error for 'to' filter on list_emails")
	}
	if !strings.Contains(errs[0], "to") || !strings.Contains(errs[0], "list_emails") {
		t.Fatalf("expected error about 'to' not applying to list_emails, got: %s", errs[0])
	}
	// Should suggest valid operations.
	if !strings.Contains(errs[0], "send_email") {
		t.Fatalf("expected error to suggest send_email as valid, got: %s", errs[0])
	}
}

func TestValidatePolicy_MixedOperationsPartiallyValid(t *testing.T) {
	ops := []connector.OperationDef{
		{Name: "send_email", Params: map[string]connector.ParamDef{"to": {Type: "[]string"}}},
		{Name: "list_emails", Params: map[string]connector.ParamDef{"query": {Type: "string"}}},
	}

	// to filter with both send_email and list_emails — valid because send_email has "to".
	config := map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email", "list_emails"}, "to": []any{"*@company.com"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	}

	errs := ValidatePolicy(config, ops)
	if len(errs) != 0 {
		t.Fatalf("expected valid (at least one op has 'to'), got errors: %v", errs)
	}
}

func TestValidatePolicy_UnknownOperation(t *testing.T) {
	ops := []connector.OperationDef{
		{Name: "list_emails", Params: map[string]connector.ParamDef{}},
	}

	config := map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"bogus_operation"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	}

	errs := ValidatePolicy(config, ops)
	if len(errs) == 0 {
		t.Fatal("expected error for unknown operation")
	}
	if !strings.Contains(errs[0], "bogus_operation") {
		t.Fatalf("expected error mentioning bogus_operation, got: %s", errs[0])
	}
}

func TestValidatePolicy_CatchAllRuleAlwaysValid(t *testing.T) {
	ops := []connector.OperationDef{
		{Name: "list_emails", Params: map[string]connector.ParamDef{}},
	}

	// No match block = catch-all, always valid.
	config := map[string]any{
		"rules": []any{
			map[string]any{"action": "deny", "reason": "block everything"},
		},
		"default_action": "deny",
	}

	errs := ValidatePolicy(config, ops)
	if len(errs) != 0 {
		t.Fatalf("catch-all rule should be valid, got errors: %v", errs)
	}
}

func TestValidatePolicy_ResponseFieldsAlwaysValid(t *testing.T) {
	ops := []connector.OperationDef{
		{Name: "list_emails", Params: map[string]connector.ParamDef{"query": {Type: "string"}}},
	}

	// "from" and "labels" are response-based fields, should be valid on any operation.
	config := map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails"}, "from": []any{"*@company.com"}, "labels": []any{"INBOX"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	}

	errs := ValidatePolicy(config, ops)
	if len(errs) != 0 {
		t.Fatalf("response-based fields (from, labels) should be valid on any op, got errors: %v", errs)
	}
}
