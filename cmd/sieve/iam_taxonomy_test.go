package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iam"
)

// schemaPath is the checked-in canonical Cedar schema, generated from the full
// connector registry. The staleness test keeps it in sync; regenerate with
// SIEVE_REGEN_SCHEMA=1 go test ./cmd/sieve/ -run TestIAMSchema_Staleness
var schemaPath = filepath.Join("..", "..", "internal", "iam", "schema.cedar")

// TestIAMTaxonomy_Coherence enforces review M1 across every production op: a
// declared ResourceType must be a type the connector declares, and the op's
// Resource mapper must actually produce that type. This is the drift guard that
// makes "an op's resource type silently disagrees with the schema" impossible.
func TestIAMTaxonomy_Coherence(t *testing.T) {
	reg := buildConnectorRegistry()
	for _, m := range reg.AllMetas() {
		declared := map[string]bool{}
		for _, rt := range m.ResourceTypes {
			declared[rt.Name] = true
		}
		if len(m.Operations) == 0 {
			t.Errorf("connector %q declares no Operations (needed for IAM taxonomy)", m.Type)
		}
		for _, op := range m.Operations {
			// (a) ResourceType, if set, must be declared.
			if op.ResourceType != "" && !declared[op.ResourceType] {
				t.Errorf("%s/%s: ResourceType %q not in connector ResourceTypes %v",
					m.Type, op.Name, op.ResourceType, keys(declared))
			}
			// (b) Resource mapper must produce the declared type (M1: one type).
			if op.Resource != nil {
				refs := op.Resource("test-conn", map[string]any{})
				if len(refs) == 0 {
					t.Errorf("%s/%s: Resource mapper returned no refs", m.Type, op.Name)
					continue
				}
				if refs[0].Type != op.ResourceType {
					t.Errorf("%s/%s: mapper leaf type %q != ResourceType %q",
						m.Type, op.Name, refs[0].Type, op.ResourceType)
				}
			}
			// (c) An op with a non-connection ResourceType should have a mapper
			// (otherwise the runtime resource would default to the connection,
			// contradicting the declared type).
			if op.ResourceType != "" && op.Resource == nil {
				t.Errorf("%s/%s: declares ResourceType %q but has no Resource mapper",
					m.Type, op.Name, op.ResourceType)
			}
		}
	}
}

// TestIAMSchema_Staleness regenerates the schema from the registry and compares
// it to the checked-in copy (CI guard against drift). Regenerate by setting
// SIEVE_REGEN_SCHEMA=1.
func TestIAMSchema_Staleness(t *testing.T) {
	reg := buildConnectorRegistry()
	got, err := iam.GenerateSchema(reg.AllMetas())
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("SIEVE_REGEN_SCHEMA") == "1" {
		if err := os.WriteFile(schemaPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("regenerated %s", schemaPath)
		return
	}
	want, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read %s (run with SIEVE_REGEN_SCHEMA=1 to create): %v", schemaPath, err)
	}
	if string(want) != got {
		t.Errorf("%s is stale; run: SIEVE_REGEN_SCHEMA=1 go test ./cmd/sieve/ -run TestIAMSchema_Staleness", schemaPath)
	}
}

// TestIAMSchema_CedarValidates validates the full generated schema with the
// authoritative Rust cedar CLI (skips if absent). Asserts the schema is
// well-formed and a representative real-connector policy validates.
func TestIAMSchema_CedarValidates(t *testing.T) {
	bin := cedarBin()
	if bin == "" {
		t.Skip("cedar CLI not installed")
	}
	reg := buildConnectorRegistry()
	schema, err := iam.GenerateSchema(reg.AllMetas())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sp := filepath.Join(dir, "schema.cedar")
	if err := os.WriteFile(sp, []byte(schema), 0o644); err != nil {
		t.Fatal(err)
	}
	// A policy referencing real derived actions/resources across connectors.
	policy := `permit(principal in Sieve::Role::"r", action in Sieve::Action::"read", resource);
permit(principal in Sieve::Role::"r", action == Sieve::Action::"github/github_get_file", resource in Sieve::Github::Owner::"c/org");
permit(principal in Sieve::Role::"r", action == Sieve::Action::"google/list_emails", resource) when { context has param && context.param has query };`
	pp := filepath.Join(dir, "p.cedar")
	if err := os.WriteFile(pp, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "validate", "--schema", sp, "--policies", pp).CombinedOutput()
	if err != nil {
		t.Fatalf("full schema failed cedar validation:\n%s", out)
	}
}

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

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

var _ = connector.OperationDef{} // keep connector import for clarity of intent
