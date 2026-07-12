package connector

import (
	"encoding/json"
	"testing"
)

// TestConfigWithoutReservedKeys pins the invariant relied on by every
// connector factory that re-marshals its config map: reserved "_"-prefixed
// runtime keys (which may hold non-serializable func values injected by
// connections.Service) are dropped, non-reserved keys survive, the input is
// not mutated, and the result is JSON-marshalable.
func TestConfigWithoutReservedKeys(t *testing.T) {
	raw := map[string]any{
		"token":                     "glpat-x",
		"base_url":                  "https://gitlab.com",
		"_on_token_refresh":         func() {},
		"_on_token_refresh_failure": func(string) {},
	}
	got := ConfigWithoutReservedKeys(raw)

	if _, ok := got["_on_token_refresh"]; ok {
		t.Error("_on_token_refresh must be stripped")
	}
	if _, ok := got["_on_token_refresh_failure"]; ok {
		t.Error("_on_token_refresh_failure must be stripped")
	}
	if got["token"] != "glpat-x" || got["base_url"] != "https://gitlab.com" {
		t.Errorf("non-reserved keys must survive, got %v", got)
	}
	if _, ok := raw["_on_token_refresh"]; !ok {
		t.Error("input map must not be mutated")
	}
	if _, err := json.Marshal(got); err != nil {
		t.Fatalf("stripped config must be marshalable: %v", err)
	}
	if ConfigWithoutReservedKeys(nil) != nil {
		t.Error("nil in must yield nil out")
	}
}
