package connections_test

// Tests for the OAuth-app credential helpers introduced by spec 002 US3.
// Covers: round-trip, keyring-locked path, validation rules, list, delete,
// and the legacy-settings migration (including idempotency + locked-keyring
// deferral).

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

	// FR-013: secret must not survive in the plaintext settings table.
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

// TestMigrateLegacySlackOAuth_FromSettings simulates a pre-fix
// deployment with plaintext settings rows and asserts the migration
// converts them to an encrypted _oauth_app:slack row + deletes the
// plaintext source rows.
func TestMigrateLegacySlackOAuth_FromSettings(t *testing.T) {
	env := testenv.New(t)
	if err := env.Settings.Set("slack_client_id", "1234567890.0987654321"); err != nil {
		t.Fatalf("seed cid: %v", err)
	}
	if err := env.Settings.Set("slack_client_secret", "0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatalf("seed sec: %v", err)
	}

	if err := env.Connections.MigrateLegacySlackOAuth(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	got, err := env.Connections.GetOAuthApp("slack")
	if err != nil {
		t.Fatalf("get after migrate: %v", err)
	}
	if got == nil {
		t.Fatal("expected oauth_app:slack row after migration")
	}
	if got.ClientID != "1234567890.0987654321" {
		t.Errorf("client_id: got %q, want 1234567890.0987654321", got.ClientID)
	}
	if got.ClientSecret != "0123456789abcdef0123456789abcdef" {
		t.Errorf("client_secret: got %q (truncated for safety)", got.ClientSecret[:4]+"...")
	}

	// Settings rows wiped.
	if v, _ := env.Settings.Get("slack_client_id"); v != "" {
		t.Errorf("settings client_id not deleted: %q", v)
	}
	if v, _ := env.Settings.Get("slack_client_secret"); v != "" {
		t.Errorf("settings client_secret not deleted: %q", v)
	}
}

// TestMigrateLegacySlackOAuth_NoLegacyIsNoOp verifies a fresh install
// (no settings rows) sees an immediate no-op return.
func TestMigrateLegacySlackOAuth_NoLegacyIsNoOp(t *testing.T) {
	env := testenv.New(t)
	if err := env.Connections.MigrateLegacySlackOAuth(); err != nil {
		t.Fatalf("migrate on fresh: %v", err)
	}
	got, _ := env.Connections.GetOAuthApp("slack")
	if got != nil {
		t.Fatalf("no-op migration created a row: %+v", got)
	}
}

// TestMigrateLegacySlackOAuth_IdempotentAcrossRuns verifies a second
// call after a successful conversion is a clean no-op.
func TestMigrateLegacySlackOAuth_IdempotentAcrossRuns(t *testing.T) {
	env := testenv.New(t)
	_ = env.Settings.Set("slack_client_id", "1.2")
	_ = env.Settings.Set("slack_client_secret", "0123456789abcdef")

	if err := env.Connections.MigrateLegacySlackOAuth(); err != nil {
		t.Fatalf("migrate 1: %v", err)
	}
	if err := env.Connections.MigrateLegacySlackOAuth(); err != nil {
		t.Fatalf("migrate 2: %v", err)
	}
	got, _ := env.Connections.GetOAuthApp("slack")
	if got == nil || got.ClientID != "1.2" {
		t.Fatalf("expected stable row across runs, got %+v", got)
	}
}

// TestMigrateLegacySlackOAuth_KeyringLockedDefers verifies that a locked
// keyring returns ErrKeyringNotLoaded without destroying the legacy rows.
func TestMigrateLegacySlackOAuth_KeyringLockedDefers(t *testing.T) {
	env := testenv.New(t)
	_ = env.Settings.Set("slack_client_id", "1.2")
	_ = env.Settings.Set("slack_client_secret", "0123456789abcdef")
	env.Keyring.Lock()

	err := env.Connections.MigrateLegacySlackOAuth()
	if err != secrets.ErrKeyringNotLoaded {
		t.Fatalf("expected ErrKeyringNotLoaded, got %v", err)
	}
	// Legacy rows must NOT be deleted.
	if v, _ := env.Settings.Get("slack_client_id"); v != "1.2" {
		t.Errorf("client_id destroyed on locked-keyring defer: %q", v)
	}
	if v, _ := env.Settings.Get("slack_client_secret"); v == "" {
		t.Errorf("client_secret destroyed on locked-keyring defer")
	}
}
