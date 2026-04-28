package policies_test

import (
	"context"
	"testing"

	"github.com/trilitech/Sieve/internal/policy"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

func TestCreateAndGet(t *testing.T) {
	env := testenv.New(t)

	config := map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	}

	pol, err := env.Policies.Create("test-policy", "rules", config)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if pol.Name != "test-policy" {
		t.Fatalf("expected name 'test-policy', got %q", pol.Name)
	}
	if pol.PolicyType != "rules" {
		t.Fatalf("expected type 'rules', got %q", pol.PolicyType)
	}

	got, err := env.Policies.Get(pol.ID)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if got.Name != "test-policy" {
		t.Fatalf("expected name 'test-policy', got %q", got.Name)
	}
	if got.PolicyType != "rules" {
		t.Fatalf("expected type 'rules', got %q", got.PolicyType)
	}
}

func TestGetByName(t *testing.T) {
	env := testenv.New(t)

	_, err := env.Policies.Create("find-me-policy", "rules", map[string]any{
		"rules":          []any{},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	got, err := env.Policies.GetByName("find-me-policy")
	if err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if got.Name != "find-me-policy" {
		t.Fatalf("expected name 'find-me-policy', got %q", got.Name)
	}
}

func TestSeedPresets(t *testing.T) {
	env := testenv.New(t)

	// Presets are seeded by testenv.New, so they should exist.
	presetNames := policy.RulesPresetNames()
	if len(presetNames) == 0 {
		t.Fatal("no preset names defined")
	}

	for _, name := range presetNames {
		pol, err := env.Policies.GetByName(name)
		if err != nil {
			t.Fatalf("preset %q not found: %v", name, err)
		}
		if pol.PolicyType != "rules" {
			t.Fatalf("expected preset %q type 'rules', got %q", name, pol.PolicyType)
		}
	}
}

func TestBuildEvaluator(t *testing.T) {
	env := testenv.New(t)

	pol, err := env.Policies.Create("eval-test", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	eval, err := env.Policies.BuildEvaluator([]string{pol.ID})
	if err != nil {
		t.Fatalf("build evaluator: %v", err)
	}

	ctx := context.Background()

	dec, err := eval.Evaluate(ctx, &policy.PolicyRequest{Operation: "list_emails"})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if dec.Action != "allow" {
		t.Fatalf("expected allow, got %s", dec.Action)
	}

	dec, err = eval.Evaluate(ctx, &policy.PolicyRequest{Operation: "send_email"})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if dec.Action != "deny" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}
}

func TestBuildCompositeEvaluator(t *testing.T) {
	env := testenv.New(t)

	// First policy: allow list_emails and send_email.
	pol1, err := env.Policies.Create("allow-both", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails", "send_email"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy 1: %v", err)
	}

	// Second policy: deny send_email, allow everything else.
	pol2, err := env.Policies.Create("deny-send", "rules", map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email"}},
				"action": "deny",
				"reason": "send blocked by second policy",
			},
		},
		"default_action": "allow",
	})
	if err != nil {
		t.Fatalf("create policy 2: %v", err)
	}

	eval, err := env.Policies.BuildEvaluator([]string{pol1.ID, pol2.ID})
	if err != nil {
		t.Fatalf("build composite evaluator: %v", err)
	}

	ctx := context.Background()

	// list_emails: allowed by both.
	dec, err := eval.Evaluate(ctx, &policy.PolicyRequest{Operation: "list_emails"})
	if err != nil {
		t.Fatalf("evaluate list_emails: %v", err)
	}
	if dec.Action != "allow" {
		t.Fatalf("expected allow for list_emails, got %s", dec.Action)
	}

	// send_email: allowed by first, denied by second. Composite should deny.
	dec, err = eval.Evaluate(ctx, &policy.PolicyRequest{Operation: "send_email"})
	if err != nil {
		t.Fatalf("evaluate send_email: %v", err)
	}
	if dec.Action != "deny" {
		t.Fatalf("expected deny for send_email, got %s", dec.Action)
	}
}

func TestUpdate(t *testing.T) {
	env := testenv.New(t)

	pol, err := env.Policies.Create("update-me", "rules", map[string]any{
		"rules":          []any{},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	newConfig := map[string]any{
		"rules":          []any{},
		"default_action": "allow",
	}

	if err := env.Policies.Update(pol.ID, "updated-policy", "rules", newConfig); err != nil {
		t.Fatalf("update policy: %v", err)
	}

	got, err := env.Policies.Get(pol.ID)
	if err != nil {
		t.Fatalf("get updated policy: %v", err)
	}
	if got.Name != "updated-policy" {
		t.Fatalf("expected name 'updated-policy', got %q", got.Name)
	}

	defaultAction, ok := got.PolicyConfig["default_action"].(string)
	if !ok || defaultAction != "allow" {
		t.Fatalf("expected default_action 'allow', got %v", got.PolicyConfig["default_action"])
	}
}

func TestDeletePolicy(t *testing.T) {
	env := testenv.New(t)

	pol, err := env.Policies.Create("delete-me", "rules", map[string]any{
		"rules":          []any{},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	if err := env.Policies.Delete(pol.ID); err != nil {
		t.Fatalf("delete policy: %v", err)
	}

	_, err = env.Policies.Get(pol.ID)
	if err == nil {
		t.Fatal("expected error getting deleted policy")
	}
}

func TestBuildEvaluatorNonexistentPolicyID(t *testing.T) {
	env := testenv.New(t)

	_, err := env.Policies.BuildEvaluator([]string{"nonexistent-policy-id"})
	if err == nil {
		t.Fatal("expected error building evaluator with nonexistent policy ID")
	}
}

func TestCreatePolicyEmptyName(t *testing.T) {
	env := testenv.New(t)

	pol, err := env.Policies.Create("", "rules", map[string]any{
		"rules":          []any{},
		"default_action": "deny",
	})
	if err != nil {
		t.Fatalf("create policy with empty name: %v", err)
	}
	if pol.Name != "" {
		t.Fatalf("expected empty name, got %q", pol.Name)
	}
	if pol.ID == "" {
		t.Fatal("expected non-empty ID even with empty name")
	}

	// Should be retrievable.
	got, err := env.Policies.Get(pol.ID)
	if err != nil {
		t.Fatalf("get policy with empty name: %v", err)
	}
	if got.Name != "" {
		t.Fatalf("expected empty name on retrieved policy, got %q", got.Name)
	}
}

func TestGetByNameNonexistent(t *testing.T) {
	env := testenv.New(t)

	_, err := env.Policies.GetByName("this-policy-does-not-exist")
	if err == nil {
		t.Fatal("expected error getting policy by nonexistent name")
	}
}
