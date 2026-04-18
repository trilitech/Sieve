package secrets

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// fastParams is a low-cost argon2 setting for tests — production uses
// DefaultArgon2Params, but a real KEK derivation per test would slow the
// suite to a crawl.
var fastParams = Argon2Params{Time: 1, Memory: 8, Threads: 1, KeyLen: 32}

func newDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`
		CREATE TABLE crypto_meta (
			id            INTEGER PRIMARY KEY CHECK (id = 1),
			argon2_salt   BLOB NOT NULL,
			argon2_params TEXT NOT NULL,
			kek_check     BLOB NOT NULL
		);
		CREATE TABLE connections (
			id           TEXT PRIMARY KEY,
			dek_wrapped  BLOB NOT NULL,
			dek_nonce    BLOB NOT NULL
		);
	`)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	return db
}

// setupFast performs the same work as Keyring.Setup but with cheap argon2
// params so tests stay fast. Production code paths still use the slow
// defaults.
func setupFast(t *testing.T, db *sql.DB, k *Keyring, passphrase []byte) {
	t.Helper()
	saved := DefaultArgon2Params
	DefaultArgon2Params = fastParams
	t.Cleanup(func() { DefaultArgon2Params = saved })
	if err := k.Setup(db, passphrase); err != nil {
		t.Fatalf("setup: %v", err)
	}
}

func TestSetupAndLoad(t *testing.T) {
	db := newDB(t)
	k := &Keyring{}
	setupFast(t, db, k, []byte("correct horse battery staple"))

	if !k.IsLoaded() {
		t.Fatal("expected keyring loaded after setup")
	}

	// Fresh keyring loads from same db with same passphrase.
	k2 := &Keyring{}
	if err := k2.Load(db, []byte("correct horse battery staple")); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !k2.IsLoaded() {
		t.Fatal("expected keyring loaded")
	}
}

func TestLoadWrongPassphrase(t *testing.T) {
	db := newDB(t)
	k := &Keyring{}
	setupFast(t, db, k, []byte("right"))

	k2 := &Keyring{}
	err := k2.Load(db, []byte("wrong"))
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase, got %v", err)
	}
	if k2.IsLoaded() {
		t.Fatal("keyring should not be loaded after wrong passphrase")
	}
}

func TestLoadMissingMeta(t *testing.T) {
	db := newDB(t)
	k := &Keyring{}
	err := k.Load(db, []byte("x"))
	if !errors.Is(err, ErrCryptoMetaMissing) {
		t.Fatalf("expected ErrCryptoMetaMissing, got %v", err)
	}
}

func TestSetupRefusesIfAlreadyInitialized(t *testing.T) {
	db := newDB(t)
	k := &Keyring{}
	setupFast(t, db, k, []byte("first"))

	k2 := &Keyring{}
	err := k2.Setup(db, []byte("second"))
	if !errors.Is(err, ErrCryptoMetaPresent) {
		t.Fatalf("expected ErrCryptoMetaPresent, got %v", err)
	}
}

func TestKeyringLockZeroes(t *testing.T) {
	db := newDB(t)
	k := &Keyring{}
	setupFast(t, db, k, []byte("pp"))

	if !k.IsLoaded() {
		t.Fatal("loaded")
	}
	k.Lock()
	if k.IsLoaded() {
		t.Fatal("expected unloaded after lock")
	}
}

func TestRotate(t *testing.T) {
	db := newDB(t)
	k := &Keyring{}
	setupFast(t, db, k, []byte("old"))

	// Insert a fake connection row with a wrapped DEK.
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}
	wrapped, nonce, err := gcmSeal(k.KEK(), dek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO connections (id, dek_wrapped, dek_nonce) VALUES (?, ?, ?)`,
		"conn-1", wrapped, nonce,
	); err != nil {
		t.Fatal(err)
	}

	if err := k.Rotate(db, []byte("old"), []byte("new")); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// After rotate the in-memory KEK is the new one — we can unwrap the
	// row's now-rewrapped DEK and recover the original 32 bytes.
	var newWrapped, newNonce []byte
	if err := db.QueryRow(
		`SELECT dek_wrapped, dek_nonce FROM connections WHERE id = ?`, "conn-1",
	).Scan(&newWrapped, &newNonce); err != nil {
		t.Fatal(err)
	}
	got, err := gcmOpen(k.KEK(), newWrapped, newNonce)
	if err != nil {
		t.Fatalf("unwrap with new kek: %v", err)
	}
	for i, b := range got {
		if b != byte(i) {
			t.Fatalf("dek[%d] = %d, want %d", i, b, i)
		}
	}

	// And the new passphrase loads cleanly on a fresh keyring.
	k2 := &Keyring{}
	if err := k2.Load(db, []byte("new")); err != nil {
		t.Fatalf("load with new pp: %v", err)
	}

	// Old passphrase no longer works.
	k3 := &Keyring{}
	if err := k3.Load(db, []byte("old")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase with old passphrase, got %v", err)
	}
}

func TestRotateRejectsWrongOldPassphrase(t *testing.T) {
	db := newDB(t)
	k := &Keyring{}
	setupFast(t, db, k, []byte("right"))

	err := k.Rotate(db, []byte("wrong"), []byte("new"))
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase, got %v", err)
	}
}
