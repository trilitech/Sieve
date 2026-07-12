package gitlab

import "testing"

// TestFactoryIgnoresInjectedRefreshCallbacks reproduces the connector-
// construction bug: connections.Service injects _on_token_refresh /
// _on_token_refresh_failure func values into the config map before calling
// the factory, and parseConfig re-marshals that map to coerce types. A func
// value is not JSON-encodable, so before the fix construction aborted with
// "json: unsupported type: func(...)". The factory must drop those reserved
// keys and construct normally.
func TestFactoryIgnoresInjectedRefreshCallbacks(t *testing.T) {
	_, err := Factory()(map[string]any{
		"token":                     "glpat-test",
		"_on_token_refresh":         func() {},
		"_on_token_refresh_failure": func() {},
	})
	if err != nil {
		t.Fatalf("Factory must ignore injected refresh callbacks; got: %v", err)
	}
}
