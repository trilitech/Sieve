package iam

import (
	"strings"
	"testing"

	xschema "github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/trilitech/Sieve/internal/connector"
)

// testMetas is a representative slice of the real taxonomy (google + github),
// enough to exercise the generator + validator end-to-end.
func testMetas() []connector.ConnectorMeta {
	return []connector.ConnectorMeta{
		{
			Type: "google",
			Operations: []connector.OperationDef{
				{Name: "list_emails", ReadOnly: true, ResourceType: "Sieve::Google::Message",
					Params: map[string]connector.ParamDef{"query": {Type: "string"}, "max_results": {Type: "int"}}},
				{Name: "send_email", ReadOnly: false}, // resource = connection
				{Name: "drive.list_files", ReadOnly: true, ResourceType: "Sieve::Google::DriveFile"},
			},
			ResourceTypes: []connector.ResourceType{
				{Name: "Sieve::Google::Message"},
				{Name: "Sieve::Google::DriveFile"},
			},
		},
		{
			Type: "github",
			Operations: []connector.OperationDef{
				{Name: "github_list_repos", ReadOnly: true, ResourceType: "Sieve::Github::Owner"},
				{Name: "github_get_file", ReadOnly: true, ResourceType: "Sieve::Github::Repo"},
				{Name: "github_request", ReadOnly: false, ResourceType: "Sieve::Github::RawRequest",
					Params: map[string]connector.ParamDef{"method": {Type: "string"}, "path": {Type: "string"}}},
			},
			ResourceTypes: []connector.ResourceType{
				{Name: "Sieve::Github::Owner"},
				{Name: "Sieve::Github::Repo", Parent: "Sieve::Github::Owner"},
				{Name: "Sieve::Github::RawRequest"},
			},
		},
	}
}

// TestSchema_GeneratesAndParses: the generated schema must parse and resolve
// under cedar-go's x/exp schema package (well-formedness, Go-side).
func TestSchema_GeneratesAndParses(t *testing.T) {
	text, err := GenerateSchema(testMetas())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("generated schema:\n%s", text)
	s := &xschema.Schema{}
	if err := s.UnmarshalCedar([]byte(text)); err != nil {
		t.Fatalf("schema does not parse:\n%s\nerror: %v", text, err)
	}
	if _, err := s.Resolve(); err != nil {
		t.Fatalf("schema does not resolve: %v", err)
	}
}

// TestSchema_Deterministic: generation is stable (required for the staleness
// guard — same input, byte-identical output).
func TestSchema_Deterministic(t *testing.T) {
	a, _ := GenerateSchema(testMetas())
	b, _ := GenerateSchema(testMetas())
	if a != b {
		t.Fatal("schema generation is not deterministic")
	}
	if !strings.Contains(a, "namespace Sieve {") {
		t.Error("expected a Sieve namespace block")
	}
}
