package iam

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cedarBin locates the authoritative Rust `cedar` CLI (the validator CI uses).
// Returns "" if absent, in which case the CLI-backed tests skip.
func cedarBin() string {
	if p, err := exec.LookPath("cedar"); err == nil {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil {
		cand := filepath.Join(home, ".cargo", "bin", "cedar")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return ""
}

// TestSchema_CLIValidation is the empirical settlement of review N2, N4, and the
// connector-gating invariant — validated by the authoritative Rust cedar CLI
// against the generated schema. Skips when the CLI is not installed.
func TestSchema_CLIValidation(t *testing.T) {
	bin := cedarBin()
	if bin == "" {
		t.Skip("cedar CLI not installed (cargo install cedar-policy-cli); CI provides it")
	}
	dir := t.TempDir()
	schema, err := GenerateSchema(testMetas())
	if err != nil {
		t.Fatal(err)
	}
	schemaPath := filepath.Join(dir, "schema.cedar")
	if err := os.WriteFile(schemaPath, []byte(schema), 0o644); err != nil {
		t.Fatal(err)
	}

	validate := func(policy string) (bool, string) {
		pp := filepath.Join(dir, "p.cedar")
		if err := os.WriteFile(pp, []byte(policy), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "validate", "--schema", schemaPath, "--policies", pp).CombinedOutput()
		return err == nil, string(out)
	}

	good := map[string]string{
		"N4 action-group + connection resource": `permit(principal in Sieve::Role::"r", action in Sieve::Action::"read", resource in Sieve::Connection::"c");`,
		"cross-service read across connections": `permit(principal in Sieve::Role::"r", action in Sieve::Action::"read", resource) when { resource in [Sieve::Connection::"a", Sieve::Connection::"b"] };`,
		"N2 per-action typed param context":     `permit(principal in Sieve::Role::"r", action == Sieve::Action::"google/list_emails", resource) when { context has param && context.param has query && context.param.query == "x" };`,
		"github owner-scoped (P1)":              `permit(principal in Sieve::Role::"r", action in Sieve::Action::"github/read", resource in Sieve::Github::Owner::"c/org");`,
		"escape-hatch http_method (P2)":         `permit(principal in Sieve::Role::"r", action == Sieve::Action::"github/github_request", resource in Sieve::Connection::"c") when { context has http_method && context.http_method == "GET" };`,
	}
	for name, src := range good {
		ok, out := validate(src)
		if !ok {
			t.Errorf("GOOD policy %q should validate but the CLI rejected it:\n%s", name, strings.TrimSpace(out))
		}
	}

	bad := map[string]string{
		"connector-gating: google action on github resource": `permit(principal in Sieve::Role::"r", action == Sieve::Action::"google/list_emails", resource in Sieve::Github::Repo::"c/o/r");`,
		"N2: undeclared context.param key":                   `permit(principal in Sieve::Role::"r", action == Sieve::Action::"google/list_emails", resource) when { context.param.nonexistent == "x" };`,
		"unknown action":                                     `permit(principal in Sieve::Role::"r", action == Sieve::Action::"google/nonexistent_op", resource);`,
	}
	for name, src := range bad {
		ok, out := validate(src)
		if ok {
			t.Errorf("BAD policy %q should FAIL validation but the CLI accepted it", name)
		} else {
			t.Logf("correctly rejected %q:\n%s", name, strings.TrimSpace(firstLines(out, 3)))
		}
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
