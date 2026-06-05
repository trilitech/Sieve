package connections_test

// Tests for the OAuth-app credential helpers: round-trip, keyring-locked
// path, validation rules, list, and delete.

import (
	"testing"

	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/secrets"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// TestOAuthApp_RoundTrip verifies that Put then Get returns equal
// credentials and that nothing leaks to the plaintext settings table.
func TestOAuthApp_RoundTrip(t *testing.T) {
	env := testenv.New(t)

	want := connections.OAuthAppCredentials{
		ClientID:     "1234567890.0987654321",
		ClientSecret: "0123456789abcdef0123456789abcdef",
	}
	if err := env.Connections.PutOAuthApp("slack", want); err != nil {
		t.Fatalf("PutOAuthApp: %v", err)
	}
	got, err := env.Connections.GetOAuthApp("slack")
	if err != nil {
		t.Fatalf("GetOAuthApp: %v", err)
	}
	if got == nil {
		t.Fatal("GetOAuthApp returned nil after Put")
	}
	if *got != want {
		t.Fatalf("round-trip: got %+v, want %+v", *got, want)
	}

	// Secret must not survive in the plaintext settings table.
	if v, _ := env.Settings.Get("slack_client_secret"); v != "" {
		t.Errorf("secret leaked into settings: %q", v)
	}
}

// TestOAuthApp_GetMissing returns (nil, nil) when no row exists.
func TestOAuthApp_GetMissing(t *testing.T) {
	env := testenv.New(t)
	got, err := env.Connections.GetOAuthApp("slack")
	if err != nil {
		t.Fatalf("GetOAuthApp on missing: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for missing, got %+v", got)
	}
}

// TestOAuthApp_KeyringLocked verifies Get and Put return
// secrets.ErrKeyringNotLoaded when the keyring is unloaded.
func TestOAuthApp_KeyringLocked(t *testing.T) {
	env := testenv.New(t)
	// Seed a row with the keyring loaded, then drop the KEK.
	if err := env.Connections.PutOAuthApp("slack", connections.OAuthAppCredentials{
		ClientID:     "1.2",
		ClientSecret: "0123456789abcdef",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	env.Keyring.Lock()

	if _, err := env.Connections.GetOAuthApp("slack"); err != secrets.ErrKeyringNotLoaded {
		t.Errorf("GetOAuthApp on locked keyring: got %v, want ErrKeyringNotLoaded", err)
	}
	if err := env.Connections.PutOAuthApp("slack", connections.OAuthAppCredentials{
		ClientID: "1.2", ClientSecret: "abcdefghij1234567",
	}); err != secrets.ErrKeyringNotLoaded {
		t.Errorf("PutOAuthApp on locked keyring: got %v, want ErrKeyringNotLoaded", err)
	}
}

// TestOAuthApp_Validation rejects malformed providers and short secrets.
func TestOAuthApp_Validation(t *testing.T) {
	env := testenv.New(t)
	good := connections.OAuthAppCredentials{ClientID: "1.2", ClientSecret: "0123456789abcdef"}

	cases := []struct {
		name     string
		provider string
		creds    connections.OAuthAppCredentials
	}{
		{"empty provider", "", good},
		{"uppercase provider", "Slack", good},
		{"non-ascii provider", "slackö", good},
		{"empty client_id", "slack", connections.OAuthAppCredentials{ClientSecret: "0123456789abcdef"}},
		{"short client_secret", "slack", connections.OAuthAppCredentials{ClientID: "1.2", ClientSecret: "short"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := env.Connections.PutOAuthApp(tc.provider, tc.creds); err == nil {
				t.Fatalf("expected PutOAuthApp to reject %q / %+v", tc.provider, tc.creds)
			}
		})
	}
}

// TestOAuthApp_Delete is idempotent.
func TestOAuthApp_Delete(t *testing.T) {
	env := testenv.New(t)
	if err := env.Connections.DeleteOAuthApp("slack"); err != nil {
		t.Fatalf("delete on absent: %v", err)
	}
	if err := env.Connections.PutOAuthApp("slack", connections.OAuthAppCredentials{
		ClientID: "1.2", ClientSecret: "0123456789abcdef",
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := env.Connections.DeleteOAuthApp("slack"); err != nil {
		t.Fatalf("delete on present: %v", err)
	}
	got, _ := env.Connections.GetOAuthApp("slack")
	if got != nil {
		t.Fatalf("expected nil after delete, got %+v", got)
	}
}

// TestOAuthApp_ListShowsMetaWithoutSecret verifies ListOAuthApps returns
// the public client_id and a HasSecret flag but never the secret itself.
func TestOAuthApp_ListShowsMetaWithoutSecret(t *testing.T) {
	env := testenv.New(t)
	if err := env.Connections.PutOAuthApp("slack", connections.OAuthAppCredentials{
		ClientID: "1234567890.public", ClientSecret: "0123456789abcdef",
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	metas, err := env.Connections.ListOAuthApps()
	if err != nil {
		t.Fatalf("ListOAuthApps: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("expected 1 meta, got %d", len(metas))
	}
	m := metas[0]
	if m.Provider != "slack" {
		t.Errorf("provider: got %q, want slack", m.Provider)
	}
	if m.ClientID != "1234567890.public" {
		t.Errorf("client_id: got %q, want 1234567890.public", m.ClientID)
	}
	if !m.HasSecret {
		t.Errorf("HasSecret: got false, want true")
	}
}
