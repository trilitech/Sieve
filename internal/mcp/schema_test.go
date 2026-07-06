package mcp

import (
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
)

// TestBuildInputSchema_TypeMapping pins the connector.ParamDef.Type ->
// JSON Schema type translation. Drift here would cause MCP clients to
// validate against the wrong types and reject valid agent payloads.
//
// The vocabulary is intentionally small. Most of the values listed
// below are in active use by some registered connector — anthropic
// uses object / []object / float / int / string, http_proxy uses
// string, gmail uses string / int / []string, etc. "number" is
// included as a documented alias of "float" that no connector
// currently emits but buildInputSchema accepts so a future connector
// can use the more JSON-Schema-native name without an additional
// switch case. The "unknown_future_type" row pins the safety net:
// anything outside the known set falls back to "string" so an
// outdated connector still produces a workable schema.
func TestBuildInputSchema_TypeMapping(t *testing.T) {
	cases := []struct {
		paramType string
		wantType  string
		wantItems string // "" = no items key expected
	}{
		{"string", "string", ""},
		{"int", "integer", ""},
		{"float", "number", ""},
		{"number", "number", ""},
		{"bool", "boolean", ""},
		{"[]string", "array", "string"},
		{"object", "object", ""},
		{"[]object", "array", "object"},
		// Unrecognized types fall back to "string" so old connectors
		// keep working when new types are added to the vocabulary.
		{"unknown_future_type", "string", ""},
	}
	for _, tc := range cases {
		op := connector.OperationDef{
			Name: "test_op",
			Params: map[string]connector.ParamDef{
				"p": {Type: tc.paramType, Description: "x"},
			},
		}
		schema := buildInputSchema(op, false)
		props, ok := schema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s: properties missing", tc.paramType)
		}
		prop, ok := props["p"].(map[string]any)
		if !ok {
			t.Fatalf("%s: param p missing from properties", tc.paramType)
		}
		if prop["type"] != tc.wantType {
			t.Errorf("type %q: schema type = %v, want %v", tc.paramType, prop["type"], tc.wantType)
		}
		if tc.wantItems == "" {
			if _, has := prop["items"]; has {
				t.Errorf("type %q: unexpected items entry %v", tc.paramType, prop["items"])
			}
		} else {
			items, ok := prop["items"].(map[string]any)
			if !ok {
				t.Errorf("type %q: items missing", tc.paramType)
				continue
			}
			if items["type"] != tc.wantItems {
				t.Errorf("type %q: items.type = %v, want %v", tc.paramType, items["type"], tc.wantItems)
			}
		}
	}
}

// TestBuildInputSchema_ObjectTypeIsSchemaless documents the intentional
// limit on the `object` type: we don't try to model the upstream API's
// nested shape — the schema just says "object" and lets MCP clients
// pass the value through verbatim. The actual structure is the
// connector's responsibility to forward and the upstream's to validate.
func TestBuildInputSchema_ObjectTypeIsSchemaless(t *testing.T) {
	op := connector.OperationDef{
		Params: map[string]connector.ParamDef{
			"metadata": {Type: "object", Description: "Anthropic metadata"},
		},
	}
	schema := buildInputSchema(op, false)
	props := schema["properties"].(map[string]any)
	meta := props["metadata"].(map[string]any)

	// No "properties" / "required" / "additionalProperties" — kept
	// open by design.
	for _, key := range []string{"properties", "required", "additionalProperties"} {
		if _, has := meta[key]; has {
			t.Errorf("object type should not carry %q nested schema; got %v", key, meta)
		}
	}
}
