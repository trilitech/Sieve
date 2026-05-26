package policy_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/policy"
)

// Spec 001-fix-security-vulns US4 / FR-018a (hard-break migration):
// stored policies whose `command` is outside the configured allowlist
// MUST fail at the next evaluation with the documented error.
//
// The evaluator is built fresh per request via CreateEvaluator →
// NewScriptEvaluator, so the construction-time check IS the
// evaluation-time safety net. This test exercises CreateEvaluator
// directly to confirm the path.

func TestCreateEvaluator_ScriptType_RejectsDisallowedCommand(t *testing.T) {
	policy.SetCommandAllowlist(nil) // default → bundled Python only
	t.Cleanup(func() { policy.SetCommandAllowlist(nil) })

	_, err := policy.CreateEvaluator("script", map[string]any{
		"command": "bash",
		"script":  "/dev/stdin",
	}, nil)
	if err == nil {
		t.Fatal("expected CreateEvaluator to reject command=bash")
	}
	if !errors.Is(err, policy.ErrCommandNotAllowed) {
		t.Errorf("got %v, want ErrCommandNotAllowed", err)
	}
}

func TestCreateEvaluator_ScriptType_AllowsOperatorExtendedAllowlist(t *testing.T) {
	policy.SetCommandAllowlist([]string{"/opt/sieve-py/bin/python3", "/usr/bin/node"})
	t.Cleanup(func() { policy.SetCommandAllowlist(nil) })

	// /usr/bin/node may not exist on this test container; literal-string
	// match wins before the os.Stat on script kicks in. The os.Stat on
	// /dev/null is reliable.
	_, err := policy.CreateEvaluator("script", map[string]any{
		"command": "/usr/bin/node",
		"script":  "/dev/null",
	}, nil)
	if err != nil && strings.Contains(err.Error(), "not in allowlist") {
		t.Errorf("operator-extended /usr/bin/node should pass allowlist; got %v", err)
	}
}

func TestCreateEvaluator_NewAllowlistTightensExistingPolicy(t *testing.T) {
	// Simulate the migration scenario: an existing policy stores
	// command=/usr/bin/perl, then the operator tightens the allowlist to
	// the bundled-Python-only default. The next CreateEvaluator call MUST
	// fail with ErrCommandNotAllowed — no grace period, no auto-rewrite
	// (Q5 clarification).
	policy.SetCommandAllowlist([]string{"/usr/bin/perl"}) // pre-tightening
	if _, err := policy.CreateEvaluator("script", map[string]any{
		"command": "/usr/bin/perl",
		"script":  "/dev/null",
	}, nil); err != nil && strings.Contains(err.Error(), "not in allowlist") {
		t.Fatalf("setup phase rejected /usr/bin/perl: %v", err)
	}

	// Operator tightens.
	policy.SetCommandAllowlist(nil)
	t.Cleanup(func() { policy.SetCommandAllowlist(nil) })

	_, err := policy.CreateEvaluator("script", map[string]any{
		"command": "/usr/bin/perl",
		"script":  "/dev/null",
	}, nil)
	if err == nil {
		t.Fatal("expected the next evaluation of the stored policy to fail post-tightening")
	}
	if !errors.Is(err, policy.ErrCommandNotAllowed) {
		t.Errorf("got %v, want ErrCommandNotAllowed", err)
	}
}
