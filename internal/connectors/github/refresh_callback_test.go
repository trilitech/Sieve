package github

import "testing"

// TestFactoryIgnoresInjectedRefreshCallbacks — see the gitlab test of the same
// name. github's parseConfig re-marshals the config map too, so it must drop
// the injected _on_token_refresh(_failure) func values rather than fail on them.
func TestFactoryIgnoresInjectedRefreshCallbacks(t *testing.T) {
	_, err := Factory()(map[string]any{
		"credentials": []any{
			map[string]any{"kind": "fpat", "scope": map[string]any{"type": "user", "name": "murbard"}, "token": "ghp_user"},
		},
		"default_credential_index":  0,
		"_on_token_refresh":         func() {},
		"_on_token_refresh_failure": func() {},
	})
	if err != nil {
		t.Fatalf("Factory must ignore injected refresh callbacks; got: %v", err)
	}
}
