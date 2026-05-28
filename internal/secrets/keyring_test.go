package secrets

import (
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

	count, err := k.Rotate(db, []byte("old"), []byte("new"), nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if count != 1 {
		t.Fatalf("rewrap count: got %d, want 1", count)
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

	_, err := k.Rotate(db, []byte("wrong"), []byte("new"), nil)
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase, got %v", err)
	}
}

// TestRotateConcurrentRead asserts the load-bearing concurrency
// invariant: while Rotate is running, concurrent WithKEK callers MUST
// fail-fast with ErrKeyringRotating rather than block, hang, or observe
// a torn key. After rotation completes, fresh WithKEK calls MUST
// succeed against the new key material.
func TestRotateConcurrentRead(t *testing.T) {
	db := newDB(t)
	k := &Keyring{}
	setupFast(t, db, k, []byte("old"))

	// Insert a connection row so Rotate has DEKs to rewrap.
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

	// Reader goroutine: loop calling WithKEK and tally outcomes.
	var (
		stop          atomic.Bool
		successes     atomic.Int64
		rotatingErrs  atomic.Int64
		notLoadedErrs atomic.Int64
		otherErrs     atomic.Int64
	)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			err := k.WithKEK(func(kek []byte) error {
				if len(kek) != 32 {
					return errors.New("torn KEK")
				}
				return nil
			})
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrKeyringRotating):
				rotatingErrs.Add(1)
			case errors.Is(err, ErrKeyringNotLoaded):
				notLoadedErrs.Add(1)
			default:
				otherErrs.Add(1)
			}
		}
	}()

	// Give the reader goroutine a head start so we observe pre-rotation
	// successes before flipping the rotating flag.
	time.Sleep(5 * time.Millisecond)

	count, err := k.Rotate(db, []byte("old"), []byte("new"), nil)
	if err != nil {
		stop.Store(true)
		wg.Wait()
		t.Fatalf("rotate: %v", err)
	}
	if count != 1 {
		t.Fatalf("rewrap count: got %d, want 1", count)
	}

	// Let the reader goroutine run for a bit after rotation completes so
	// we can observe post-rotation successes.
	time.Sleep(5 * time.Millisecond)
	stop.Store(true)
	wg.Wait()

	if otherErrs.Load() != 0 {
		t.Fatalf("got unexpected non-typed errors during concurrent read: %d", otherErrs.Load())
	}
	if notLoadedErrs.Load() != 0 {
		t.Fatalf("got unexpected ErrKeyringNotLoaded during concurrent read: %d", notLoadedErrs.Load())
	}
	if successes.Load() == 0 {
		t.Fatal("no WithKEK successes — reader never ran or rotating flag never cleared")
	}
	// We can't deterministically assert rotatingErrs > 0 because the
	// reader goroutine and Rotate are racing; on very fast hardware a
	// tight scheduler could let every WithKEK call slot in either before
	// or after the rotating flag was held. The contract this test enforces
	// is the "no torn KEK / no inconsistent error" invariant; the
	// fail-fast latency claim is verified by inspection of the WithKEK
	// implementation. Log the counts so a CI failure on a future change
	// is easier to diagnose.
	t.Logf("concurrent-read tallies: success=%d rotating=%d notLoaded=%d other=%d",
		successes.Load(), rotatingErrs.Load(), notLoadedErrs.Load(), otherErrs.Load())
}

// TestRotateConcurrentRotate verifies the two-tabs edge case: when two
// goroutines call Rotate simultaneously, exactly one returns
// ErrAlreadyRotating and the other completes the rotation. The on-disk
// state after both return MUST be the result of the successful rotation.
func TestRotateConcurrentRotate(t *testing.T) {
	db := newDB(t)
	k := &Keyring{}
	setupFast(t, db, k, []byte("old"))

	// Add a row so each rotation has a DEK to rewrap.
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

	type rotateResult struct {
		count int
		err   error
		newPP []byte
	}
	results := make(chan rotateResult, 2)

	go func() {
		count, err := k.Rotate(db, []byte("old"), []byte("new-A"), nil)
		results <- rotateResult{count, err, []byte("new-A")}
	}()
	go func() {
		count, err := k.Rotate(db, []byte("old"), []byte("new-B"), nil)
		results <- rotateResult{count, err, []byte("new-B")}
	}()

	r1 := <-results
	r2 := <-results

	// Exactly one MUST be ErrAlreadyRotating; the other MUST be nil.
	switch {
	case errors.Is(r1.err, ErrAlreadyRotating) && r2.err == nil:
		// r2 won the race; verify it claims the rewrap count and the
		// resulting on-disk state loads with new-B.
		if r2.count != 1 {
			t.Fatalf("winner count: got %d, want 1", r2.count)
		}
		k2 := &Keyring{}
		if err := k2.Load(db, r2.newPP); err != nil {
			t.Fatalf("load winner passphrase %q: %v", r2.newPP, err)
		}
	case errors.Is(r2.err, ErrAlreadyRotating) && r1.err == nil:
		if r1.count != 1 {
			t.Fatalf("winner count: got %d, want 1", r1.count)
		}
		k2 := &Keyring{}
		if err := k2.Load(db, r1.newPP); err != nil {
			t.Fatalf("load winner passphrase %q: %v", r1.newPP, err)
		}
	default:
		t.Fatalf("expected exactly one ErrAlreadyRotating and one nil; got r1=%v, r2=%v", r1.err, r2.err)
	}
}

// TestRotateRollbackPreservesState verifies that when the rotation
// transaction fails mid-flight, the on-disk state and the in-memory KEK
// MUST remain on the pre-rotation values. We induce a mid-rotation
// failure by inserting a connection row whose dek_wrapped
// is corrupted — the unwrap step inside Rotate's loop will fail, the
// transaction rolls back, and the next Load with the OLD passphrase
// MUST succeed.
func TestRotateRollbackPreservesState(t *testing.T) {
	db := newDB(t)
	k := &Keyring{}
	setupFast(t, db, k, []byte("old"))

	// Insert a row whose wrapped DEK is gibberish — Rotate will fail on
	// gcmOpen for this row, rolling back the transaction.
	garbage := make([]byte, 48)
	garbageNonce := make([]byte, 12)
	if _, err := db.Exec(
		`INSERT INTO connections (id, dek_wrapped, dek_nonce) VALUES (?, ?, ?)`,
		"corrupt", garbage, garbageNonce,
	); err != nil {
		t.Fatal(err)
	}

	originalKEK := append([]byte(nil), k.KEK()...)

	_, err := k.Rotate(db, []byte("old"), []byte("new"), nil)
	if err == nil {
		t.Fatal("expected rotate to fail on corrupt row, got nil")
	}

	// In-memory KEK MUST be unchanged.
	if !equalBytes(originalKEK, k.KEK()) {
		t.Fatal("in-memory KEK changed after failed rotation")
	}

	// On-disk crypto_meta MUST still verify against the OLD passphrase.
	k2 := &Keyring{}
	if err := k2.Load(db, []byte("old")); err != nil {
		t.Fatalf("load with old passphrase after failed rotate: %v", err)
	}

	// And the new passphrase MUST still fail to load.
	k3 := &Keyring{}
	if err := k3.Load(db, []byte("new")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase loading with new pp after failed rotate, got %v", err)
	}

	// rotating flag MUST be cleared after the failed rotation (defer).
	if k.rotating.Load() {
		t.Fatal("rotating flag still set after failed rotation")
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
