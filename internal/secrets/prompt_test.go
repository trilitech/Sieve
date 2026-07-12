//go:build !windows

// Build-tagged off Windows because the FD 3 manipulation below uses
// syscall.Dup / syscall.Dup2, which aren't available on the Windows
// syscall package. The same pattern is used by other POSIX-only test
// files in this repo (cmd/sieve/rotate_test.go's reset-keyring TTY
// guard, internal/policy/script_path_test.go's mkfifo test).

package secrets_test

// Source-selection contract for Acquire. The intake priority (file →
// SIEVE_PASSPHRASE_FD (opt-in) → TTY → error); these tests pin which
// source wins under each combination so a future regression can't silently
// flip the order — and, crucially, that an open-but-unnamed fd 3 is IGNORED
// (the footgun the opt-in fixes). The TTY branch itself is not exercised here (go test
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

// TestAcquire_FileSource_WinsOverFD verifies that when SIEVE_PASSPHRASE_FILE
// is set and SIEVE_PASSPHRASE_FD names an open fd, the file wins. Operators
// set both deliberately; the documented order puts the file first.
func TestAcquire_FileSource_WinsOverFD(t *testing.T) {
	dir := t.TempDir()
	filePP := []byte("from-file-source")
	path := filepath.Join(dir, "pp")
	if err := os.WriteFile(path, filePP, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(secrets.PassphraseFileEnv, path)

	// Also make an fd source available (fd 3, explicitly named). openFD3Pipe
	// registers its own t.Cleanup; no explicit Close needed.
	openFD3Pipe(t, "from-fd-source\n")
	t.Setenv(secrets.PassphraseFDEnv, "3")

	got, err := secrets.Acquire(secrets.PromptOptions{})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if string(got) != "from-file-source" {
		t.Errorf("expected file source to win, got %q", got)
	}
}

// TestAcquire_FD_UsedWhenNamed verifies the fd source is used when
// SIEVE_PASSPHRASE_FD names it and the file env is unset.
func TestAcquire_FD_UsedWhenNamed(t *testing.T) {
	t.Setenv(secrets.PassphraseFileEnv, "")
	os.Unsetenv(secrets.PassphraseFileEnv)

	openFD3Pipe(t, "from-fd\n")
	t.Setenv(secrets.PassphraseFDEnv, "3")

	got, err := secrets.Acquire(secrets.PromptOptions{})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if string(got) != "from-fd" {
		t.Errorf("expected fd source, got %q", got)
	}
}

// TestAcquire_UnnamedOpenFD3_Ignored is the regression for the footgun: an
// open fd 3 that the operator did NOT designate via SIEVE_PASSPHRASE_FD must
// be ignored — a stray descriptor leaked by a terminal/IDE/CI launcher must
// never hijack intake. With no file and no named fd (stdin not a TTY under
// `go test`), Acquire must reach the loud "no source" error rather than read
// the leaked fd's contents.
func TestAcquire_UnnamedOpenFD3_Ignored(t *testing.T) {
	t.Setenv(secrets.PassphraseFileEnv, "")
	os.Unsetenv(secrets.PassphraseFileEnv)
	t.Setenv(secrets.PassphraseFDEnv, "")
	os.Unsetenv(secrets.PassphraseFDEnv)

	// fd 3 is open with a would-be passphrase, but never named.
	openFD3Pipe(t, "leaked-secret-must-not-be-used\n")

	_, err := secrets.Acquire(secrets.PromptOptions{})
	if err == nil {
		t.Fatal("expected error: an unnamed open fd 3 must not be used as a passphrase source")
	}
	if strings.Contains(err.Error(), "leaked-secret") {
		t.Fatalf("Acquire read the leaked fd 3 contents; footgun not closed: %v", err)
	}
	if !strings.Contains(err.Error(), "no passphrase source") {
		t.Errorf("expected the no-source error, got: %v", err)
	}
}

// TestAcquire_NoSource_NoTTY verifies the clear-error path: no file, no
// named fd, stdin not a TTY → error mentioning both env vars and the TTY.
func TestAcquire_NoSource_NoTTY(t *testing.T) {
	t.Setenv(secrets.PassphraseFileEnv, "")
	os.Unsetenv(secrets.PassphraseFileEnv)
	t.Setenv(secrets.PassphraseFDEnv, "")
	os.Unsetenv(secrets.PassphraseFDEnv)
	closeFD3IfOpen(t)

	_, err := secrets.Acquire(secrets.PromptOptions{})
	if err == nil {
		t.Fatal("expected error when no source available")
	}
	for _, want := range []string{secrets.PassphraseFileEnv, secrets.PassphraseFDEnv, "TTY"} {
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
// (the slot Acquire probes), and writes `content` into the write end.
// All cleanup (closing the read end, restoring any previous FD 3) is
// registered via t.Cleanup, so the caller does not need to close
// anything.
func openFD3Pipe(t *testing.T, content string) {
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
