package linear

import "testing"

// TestFactoryIgnoresInjectedRefreshCallbacks — see the gitlab test of the same
// name. linear's parseConfig re-marshals the config map too, so it must drop
// the injected _on_token_refresh(_failure) func values rather than fail on them.
func TestFactoryIgnoresInjectedRefreshCallbacks(t *testing.T) {
	_, err := Factory()(map[string]any{
		"api_key":                   "lin_api_test-not-real",
		"_on_token_refresh":         func() {},
		"_on_token_refresh_failure": func() {},
	})
	if err != nil {
		t.Fatalf("Factory must ignore injected refresh callbacks; got: %v", err)
	}
}
