package secrets_test

// Source-selection contract for Acquire. The intake priority (file →
// FD 3 → TTY → error) changed in this PR; these tests pin which source
// wins under each combination so a future regression can't silently
// flip the order. The TTY branch itself is not exercised here (go test
// runs under a pipe/file stdin and term.IsTerminal returns false in
// that environment); the production wiring for the TTY path is
// covered by the cmd/sieve rotate flow.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/trilitech/Sieve/internal/secrets"
)

// TestAcquire_FileSource_WinsOverFD3 verifies that when both
// SIEVE_PASSPHRASE_FILE is set and FD 3 is open, the file wins. This is
// the documented order — operators set the file env var deliberately;
// FD 3 is the systemd LoadCredential= convention.
func TestAcquire_FileSource_WinsOverFD3(t *testing.T) {
	dir := t.TempDir()
	filePP := []byte("from-file-source")
	path := filepath.Join(dir, "pp")
	if err := os.WriteFile(path, filePP, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(secrets.PassphraseFileEnv, path)

	// Also open FD 3 so both sources are available.
	fd3 := openFD3Pipe(t, "from-fd3-source\n")
	defer fd3.Close()

	got, err := secrets.Acquire(secrets.PromptOptions{})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if string(got) != "from-file-source" {
		t.Errorf("expected file source to win, got %q", got)
	}
}

// TestAcquire_FD3_UsedWhenFileEnvUnset verifies FD 3 is the second
// fallback when SIEVE_PASSPHRASE_FILE is not set.
func TestAcquire_FD3_UsedWhenFileEnvUnset(t *testing.T) {
	// Make sure the env var is unset for this test.
	t.Setenv(secrets.PassphraseFileEnv, "")
	os.Unsetenv(secrets.PassphraseFileEnv)

	fd3 := openFD3Pipe(t, "from-fd3\n")
	defer fd3.Close()

	got, err := secrets.Acquire(secrets.PromptOptions{})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if string(got) != "from-fd3" {
		t.Errorf("expected FD 3 source, got %q", got)
	}
}

// TestAcquire_NoSource_NoTTY verifies the clear-error path: no file,
// no FD 3, stdin not a TTY → error mentioning all three.
func TestAcquire_NoSource_NoTTY(t *testing.T) {
	t.Setenv(secrets.PassphraseFileEnv, "")
	os.Unsetenv(secrets.PassphraseFileEnv)
	closeFD3IfOpen(t)

	_, err := secrets.Acquire(secrets.PromptOptions{})
	if err == nil {
		t.Fatal("expected error when no source available")
	}
	for _, want := range []string{secrets.PassphraseFileEnv, "FD 3", "TTY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

// TestAcquire_RequireTTY_RejectsFileSource verifies the rotation-safety
// gate: when RequireTTY is set, SIEVE_PASSPHRASE_FILE is ignored even
// though it's configured, and Acquire fails closed (since the test
// stdin is not a TTY). This pins the property that
// --rotate-passphrase's "new passphrase" prompt cannot be silently
// satisfied by re-reading the existing file source.
func TestAcquire_RequireTTY_RejectsFileSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pp")
	if err := os.WriteFile(path, []byte("should-be-ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(secrets.PassphraseFileEnv, path)

	_, err := secrets.Acquire(secrets.PromptOptions{RequireTTY: true})
	if err == nil {
		t.Fatal("expected error: RequireTTY must refuse the file source")
	}
	if !strings.Contains(err.Error(), "TTY") {
		t.Errorf("error should mention TTY, got: %v", err)
	}
}

// TestAcquire_Confirm_ImpliesRequireTTY verifies Confirm=true also
// gates on a TTY — confirming a value read from a static file is
// meaningless, so the same TTY-required behavior applies.
func TestAcquire_Confirm_ImpliesRequireTTY(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pp")
	if err := os.WriteFile(path, []byte("file-source"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(secrets.PassphraseFileEnv, path)

	_, err := secrets.Acquire(secrets.PromptOptions{Confirm: true})
	if err == nil {
		t.Fatal("expected error: Confirm=true must imply RequireTTY")
	}
	if !strings.Contains(err.Error(), "TTY") {
		t.Errorf("error should mention TTY, got: %v", err)
	}
}

// TestAcquire_FilePathEmpty_FailsLoudly verifies the file path's empty-
// file guard. Operator dropping an empty mount as the credential source
// must NOT be silently treated as "no passphrase" and silently fall
// through to FD 3 / TTY.
func TestAcquire_FilePathEmpty_FailsLoudly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty-pp")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(secrets.PassphraseFileEnv, path)

	_, err := secrets.Acquire(secrets.PromptOptions{})
	if err == nil {
		t.Fatal("expected error for empty passphrase file")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention 'empty', got: %v", err)
	}
}

// --- test helpers ---

// openFD3Pipe creates a pipe, dups its read end onto file descriptor 3
// (the slot Acquire probes), writes `content` into the write end, and
// returns the read end so the test can close it via t.Cleanup. The
// caller does not need to close it explicitly.
func openFD3Pipe(t *testing.T, content string) *os.File {
	t.Helper()
	rEnd, wEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := wEnd.WriteString(content); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = wEnd.Close()
	// Dup the read end onto FD 3, preserving any existing FD 3 so we
	// can restore it after the test. syscall.Dup2 replaces the
	// destination FD atomically.
	prevFD3, err := dupFD(3)
	if err != nil {
		// FD 3 wasn't open; nothing to restore.
		prevFD3 = -1
	}
	if err := syscall.Dup2(int(rEnd.Fd()), 3); err != nil {
		t.Fatalf("dup2 onto FD 3: %v", err)
	}
	t.Cleanup(func() {
		if prevFD3 >= 0 {
			_ = syscall.Dup2(prevFD3, 3)
			_ = syscall.Close(prevFD3)
		} else {
			_ = syscall.Close(3)
		}
		_ = rEnd.Close()
	})
	return rEnd
}

// closeFD3IfOpen makes sure FD 3 is closed before a test that expects
// the "no source" path. Tests share a process, so a previous test's
// FD 3 might still be open even after its t.Cleanup ran if the test
// runner reuses things; the explicit close here keeps the
// no-source-available branch deterministic.
func closeFD3IfOpen(t *testing.T) {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Fstat(3, &st); err == nil {
		_ = syscall.Close(3)
	}
}

// dupFD duplicates a file descriptor onto a fresh slot, returning the
// new FD. Used to snapshot FD 3 before a test redirects it so we can
// restore the original afterwards.
func dupFD(fd int) (int, error) {
	newFD, err := syscall.Dup(fd)
	if err != nil {
		return -1, err
	}
	if newFD < 0 {
		return -1, errors.New("dup returned negative fd")
	}
	return newFD, nil
}
