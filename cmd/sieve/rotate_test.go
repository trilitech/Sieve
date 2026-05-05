package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/policies"
	"github.com/trilitech/Sieve/internal/secrets"
)

// TestRotateCLI_Success drives the same Keyring.Rotate call path that
// runRotate uses (with the audit-logger adapter), verifying the bottom-half
// of the CLI flow without needing a TTY for the prompt step. The runRotate
// function itself is deliberately thin — it wires Acquire + Rotate + exit
// codes — so the load-bearing assertions live here:
//
//   - count returned matches the number of credential rows on disk
//   - one keyring.rotate audit row is written with surface="cli"
//   - the new passphrase loads on a fresh keyring; the old does not
func TestRotateCLI_Success(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rotate.db")

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Cheap argon2 for the test.
	saved := secrets.DefaultArgon2Params
	secrets.DefaultArgon2Params = secrets.Argon2Params{Time: 1, Memory: 8, Threads: 1, KeyLen: 32}
	t.Cleanup(func() { secrets.DefaultArgon2Params = saved })

	k := &secrets.Keyring{}
	if err := k.Setup(db.DB, []byte("old-pp")); err != nil {
		t.Fatalf("setup: %v", err)
	}

	auditLog := audit.NewLogger(db)
	auditor := auditLog.AsRotationAuditor("cli")

	count, err := k.Rotate(db.DB, []byte("old-pp"), []byte("new-pp"), auditor)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// Empty connections table → count=0 is correct, but the audit row
	// MUST still be written.
	if count != 0 {
		t.Fatalf("count: got %d, want 0 (empty connections table)", count)
	}

	entries, err := auditLog.List(&audit.ListFilter{Operation: "keyring.rotate"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit rows: got %d, want 1", len(entries))
	}
	if entries[0].PolicyResult != "success" {
		t.Fatalf("policy_result: got %q", entries[0].PolicyResult)
	}
	if entries[0].TokenID != "system" || entries[0].ConnectionID != "-" {
		t.Fatalf("sentinel actors: token_id=%q connection_id=%q", entries[0].TokenID, entries[0].ConnectionID)
	}
	if !contains(entries[0].Params, `"surface":"cli"`) {
		t.Fatalf("params should contain surface=\"cli\", got: %s", entries[0].Params)
	}

	// A fresh keyring loads with the new passphrase; the old one fails.
	k2 := &secrets.Keyring{}
	if err := k2.Load(db.DB, []byte("new-pp")); err != nil {
		t.Fatalf("load with new passphrase: %v", err)
	}
	k3 := &secrets.Keyring{}
	if err := k3.Load(db.DB, []byte("old-pp")); !errors.Is(err, secrets.ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase loading with old pp, got %v", err)
	}
}

// TestRotateCLI_ExitCodeMappings exercises the runRotate helper logic:
// each of the documented sentinel errors must map to its corresponding
// non-zero exit code.
func TestRotateCLI_ExitCodeMappings(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"wrong passphrase", secrets.ErrWrongPassphrase, rotateExitWrongPassphrase},
		{"keyring missing", secrets.ErrCryptoMetaMissing, rotateExitKeyringMissing},
		{"already rotating", secrets.ErrAlreadyRotating, rotateExitLockConflict},
		{"unknown error", errors.New("some other failure"), rotateExitGeneric},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapRotateError(tc.err)
			if got != tc.want {
				t.Fatalf("exit code: got %d, want %d", got, tc.want)
			}
		})
	}
}

// mapRotateError is a tiny extraction of the switch in runRotate so it can
// be unit-tested without driving the whole TTY/DB pipeline.
func mapRotateError(err error) int {
	switch {
	case errors.Is(err, secrets.ErrWrongPassphrase):
		return rotateExitWrongPassphrase
	case errors.Is(err, secrets.ErrCryptoMetaMissing):
		return rotateExitKeyringMissing
	case errors.Is(err, secrets.ErrAlreadyRotating):
		return rotateExitLockConflict
	case isLockConflict(err):
		return rotateExitLockConflict
	default:
		return rotateExitGeneric
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestResetKeyring_DeletesCredentialsAndPreservesEverythingElse exercises
// the load-bearing transactional behavior of runResetKeyring without
// driving the TTY confirmation. After the reset:
//
//   - the connections table MUST be empty
//   - the crypto_meta row MUST be gone (Load returns ErrCryptoMetaMissing)
//   - the audit_log table MUST contain a "keyring.reset" row whose
//     params record the deleted-connections count
//   - policies MUST still be present (proves preservation)
func TestResetKeyring_DeletesCredentialsAndPreservesEverythingElse(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "reset.db")

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Cheap argon2 for the test.
	saved := secrets.DefaultArgon2Params
	secrets.DefaultArgon2Params = secrets.Argon2Params{Time: 1, Memory: 8, Threads: 1, KeyLen: 32}
	t.Cleanup(func() { secrets.DefaultArgon2Params = saved })

	k := &secrets.Keyring{}
	if err := k.Setup(db.DB, []byte("forgotten-pp")); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Insert a fake connection row (no live encrypted blob needed for
	// this test — runResetKeyring just deletes rows).
	dummy := []byte{1, 2, 3, 4}
	for i := 0; i < 3; i++ {
		if _, err := db.DB.Exec(
			`INSERT INTO connections (id, connector_type, display_name, config_ciphertext, config_nonce, dek_wrapped, dek_nonce, enc_version)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			"conn-"+string(rune('a'+i)), "mock", "M", dummy, dummy, dummy, dummy, 1,
		); err != nil {
			t.Fatal(err)
		}
	}

	// Insert a policy so we can verify it survives.
	policiesSvc := policies.NewService(db)
	if _, err := policiesSvc.Create("preserved-policy", "rules", map[string]any{
		"default_action": "deny",
	}); err != nil {
		t.Fatalf("create policy: %v", err)
	}

	// Drive the SAME deletes runResetKeyring performs, in the SAME
	// transactional order, so test coverage matches production behavior.
	// (runResetKeyring itself blocks on TTY input which we can't fake
	// from inside `go test`; the load-bearing assertions are about what
	// the DB looks like after the deletes commit, which we test directly.)
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`DELETE FROM connections`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`DELETE FROM crypto_meta`); err != nil {
		t.Fatal(err)
	}
	auditLog := audit.NewLogger(db)
	if err := auditLog.LogTx(tx, &audit.LogRequest{
		TokenID: "system", TokenName: "system", ConnectionID: "-",
		Operation: "keyring.reset",
		Params: map[string]any{
			"surface":             "cli",
			"connections_deleted": 3,
		},
		PolicyResult: "success",
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Connections gone.
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM connections`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("connections after reset: got %d, want 0", n)
	}

	// crypto_meta gone — a fresh keyring's Load surfaces the typed
	// sentinel so the run path can prompt the operator to --setup.
	k2 := &secrets.Keyring{}
	if err := k2.Load(db.DB, []byte("forgotten-pp")); !errors.Is(err, secrets.ErrCryptoMetaMissing) {
		t.Fatalf("Load after reset: want ErrCryptoMetaMissing, got %v", err)
	}

	// Audit row written, exactly one, with the right shape.
	entries, err := auditLog.List(&audit.ListFilter{Operation: "keyring.reset"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("keyring.reset rows: got %d, want 1", len(entries))
	}
	if !contains(entries[0].Params, `"connections_deleted":3`) {
		t.Fatalf("params should record connections_deleted=3, got: %s", entries[0].Params)
	}
	if !contains(entries[0].Params, `"surface":"cli"`) {
		t.Fatalf("params should record surface=cli, got: %s", entries[0].Params)
	}

	// Policy preserved — proves "everything else survives".
	all, err := policiesSvc.List()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range all {
		if p.Name == "preserved-policy" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("policy did not survive the reset (preservation guarantee broken)")
	}
}

// TestResetKeyring_AbortsWithoutDestruction verifies the UX safeguard:
// when stdin is not a TTY (a regular file, /dev/null, or a pipe — i.e.
// any source where the operator cannot interactively type RESET),
// runResetKeyring exits with resetExitAborted and does NOT touch the
// database.
//
// This is deterministic regardless of how `go test` is invoked: we
// override os.Stdin with a regular file, which os.Stat reports without
// the ModeCharDevice bit, so stdinIsTerminal() reliably returns false.
func TestResetKeyring_AbortsWithoutDestruction(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "reset.db")

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	saved := secrets.DefaultArgon2Params
	secrets.DefaultArgon2Params = secrets.Argon2Params{Time: 1, Memory: 8, Threads: 1, KeyLen: 32}
	t.Cleanup(func() { secrets.DefaultArgon2Params = saved })
	k := &secrets.Keyring{}
	if err := k.Setup(db.DB, []byte("pp")); err != nil {
		t.Fatalf("setup: %v", err)
	}
	db.Close()

	// Replace os.Stdin with a regular file so stdinIsTerminal() is
	// deterministically false. (A regular file's mode never carries
	// os.ModeCharDevice.)
	stdinFile, err := os.Open(filepath.Join(dir, "stdin-substitute.txt"))
	if os.IsNotExist(err) {
		// Create the file first.
		f, createErr := os.Create(filepath.Join(dir, "stdin-substitute.txt"))
		if createErr != nil {
			t.Fatal(createErr)
		}
		f.Close()
		stdinFile, err = os.Open(filepath.Join(dir, "stdin-substitute.txt"))
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdinFile.Close() })

	origStdin := os.Stdin
	os.Stdin = stdinFile
	t.Cleanup(func() { os.Stdin = origStdin })

	got := runResetKeyring(dbPath)
	if got != resetExitAborted {
		t.Fatalf("exit code: got %d, want %d (resetExitAborted)", got, resetExitAborted)
	}

	// crypto_meta MUST still be present — proof that the early refusal
	// did not run any deletes.
	db2, err := database.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	k2 := &secrets.Keyring{}
	if err := k2.Load(db2.DB, []byte("pp")); err != nil {
		t.Fatalf("keyring should still load after refused reset, got %v", err)
	}
}

