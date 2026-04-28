package connections_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/secrets"
	mockconn "github.com/trilitech/Sieve/internal/testing/mockconnector"
)

// TestEncryptedRoundTrip confirms that a stored config decrypts back to the
// exact value that was written.
func TestEncryptedRoundTrip(t *testing.T) {
	svc, _ := setup(t)

	original := map[string]any{
		"refresh_token": "1//abcdefRefresh",
		"client_secret": "GOCSPX-deadbeef",
		"nested": map[string]any{
			"api_key": "sk-test-12345",
		},
	}

	if err := svc.Add("enc-conn", "mock", "Encrypted", original); err != nil {
		t.Fatalf("add: %v", err)
	}

	got, err := svc.GetWithConfig("enc-conn")
	if err != nil {
		t.Fatalf("get with config: %v", err)
	}

	if got.Config["refresh_token"] != "1//abcdefRefresh" {
		t.Fatalf("refresh_token: %v", got.Config["refresh_token"])
	}
	if got.Config["client_secret"] != "GOCSPX-deadbeef" {
		t.Fatalf("client_secret: %v", got.Config["client_secret"])
	}
	nested, ok := got.Config["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested missing or wrong type: %T", got.Config["nested"])
	}
	if nested["api_key"] != "sk-test-12345" {
		t.Fatalf("nested.api_key: %v", nested["api_key"])
	}
}

// TestNoPlaintextOnDisk is the explicit guarantee operators need: the SQLite
// file must never contain the cleartext credential. We write a config with
// distinctive marker strings, then scan the entire DB file for any of them.
func TestNoPlaintextOnDisk(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := database.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	registry := connector.NewRegistry()
	mock := mockconn.New("mock")
	registry.Register(mock.Meta(), mock.Factory())

	keyring := testKeyring(t, db)
	svc := connections.NewService(db, registry, keyring)

	markers := []string{
		"REFRESH-TOKEN-MARKER-1234",
		"CLIENT-SECRET-MARKER-5678",
		"PROXY-API-KEY-MARKER-90AB",
	}
	cfg := map[string]any{
		"refresh_token": markers[0],
		"client_secret": markers[1],
		"auth_value":    "Bearer " + markers[2],
	}
	if err := svc.Add("plain-check", "mock", "Plaintext Check", cfg); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Force any WAL pages to flush to the main DB file before reading.
	if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}

	contents, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read db file: %v", err)
	}
	for _, marker := range markers {
		if strings.Contains(string(contents), marker) {
			t.Fatalf("plaintext marker %q found in on-disk DB — encryption broken", marker)
		}
	}
}

// TestKeyringNotLoadedSurfaces verifies that operations needing decryption
// return the typed sentinel when the keyring is locked, so callers can
// detect it with errors.Is and respond with a 503.
func TestKeyringNotLoadedSurfaces(t *testing.T) {
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	registry := connector.NewRegistry()
	mock := mockconn.New("mock")
	registry.Register(mock.Meta(), mock.Factory())

	// Build the service with an unloaded keyring.
	svc := connections.NewService(db, registry, &secrets.Keyring{})

	if err := svc.Add("x", "mock", "X", map[string]any{}); !errors.Is(err, secrets.ErrKeyringNotLoaded) {
		t.Fatalf("Add: want ErrKeyringNotLoaded, got %v", err)
	}
	if _, err := svc.GetWithConfig("x"); !errors.Is(err, secrets.ErrKeyringNotLoaded) {
		t.Fatalf("GetWithConfig: want ErrKeyringNotLoaded, got %v", err)
	}
	if err := svc.UpdateConfig("x", map[string]any{}); !errors.Is(err, secrets.ErrKeyringNotLoaded) {
		t.Fatalf("UpdateConfig: want ErrKeyringNotLoaded, got %v", err)
	}
	if err := svc.InitAll(); !errors.Is(err, secrets.ErrKeyringNotLoaded) {
		t.Fatalf("InitAll: want ErrKeyringNotLoaded, got %v", err)
	}
}

// TestTamperedCiphertextFailsClosed corrupts the ciphertext column on disk
// and confirms decryption returns an error rather than malformed data.
func TestTamperedCiphertextFailsClosed(t *testing.T) {
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	registry := connector.NewRegistry()
	mock := mockconn.New("mock")
	registry.Register(mock.Meta(), mock.Factory())

	keyring := testKeyring(t, db)
	svc := connections.NewService(db, registry, keyring)

	if err := svc.Add("tamper", "mock", "T", map[string]any{"k": "v"}); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Flip a bit in config_ciphertext directly through the database handle.
	var ct []byte
	if err := db.QueryRow(`SELECT config_ciphertext FROM connections WHERE id = ?`, "tamper").Scan(&ct); err != nil {
		t.Fatalf("read ct: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("ciphertext empty")
	}
	ct[0] ^= 0x01
	if _, err := db.Exec(`UPDATE connections SET config_ciphertext = ? WHERE id = ?`, ct, "tamper"); err != nil {
		t.Fatalf("update ct: %v", err)
	}

	if _, err := svc.GetWithConfig("tamper"); err == nil {
		t.Fatal("expected GetWithConfig to fail on tampered ciphertext")
	}
}
