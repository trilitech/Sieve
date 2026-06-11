package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// command field on script-type policies (and on rules-type nested
// `script.command`) must be validated against an operator-configurable
// allowlist at every CRUD site and at evaluation time.

func TestValidateCommand_EmptyAllowlistUsesDefault(t *testing.T) {
	if err := ValidateCommand(DefaultCommand, nil); err != nil {
		t.Errorf("default %q with empty allowlist should pass, got %v", DefaultCommand, err)
	}
	for _, bad := range []string{"bash", "/bin/sh", "/bin/bash", "/usr/bin/perl"} {
		if err := ValidateCommand(bad, nil); err == nil {
			t.Errorf("expected denial for %q with empty allowlist", bad)
		}
	}
}

func TestValidateCommand_EmptyCommandRejected(t *testing.T) {
	if err := ValidateCommand("", nil); err == nil {
		t.Fatal("empty command must be rejected")
	}
}

func TestValidateCommand_ExactLiteralMatchWins(t *testing.T) {
	// Even when the configured allowlist entry doesn't exist on disk
	// (e.g., the bundled Python venv isn't installed in the test
	// container), a literal-string match still passes. This keeps the
	// default workflow functional under `go test` without the docker
	// image's `/opt/sieve-py` tree mounted.
	allow := []string{"/opt/sieve-py/bin/python3"}
	if err := ValidateCommand("/opt/sieve-py/bin/python3", allow); err != nil {
		t.Errorf("literal match should pass: %v", err)
	}
}

func TestValidateCommand_DisallowedBinaryRejected(t *testing.T) {
	allow := []string{"/opt/sieve-py/bin/python3"}
	for _, bad := range []string{"bash", "/bin/bash", "/bin/sh", "/usr/bin/perl",
		"/usr/bin/env", "/opt/sieve-py/bin/python", "../python3"} {
		err := ValidateCommand(bad, allow)
		if err == nil {
			t.Errorf("expected denial for %q", bad)
			continue
		}
		if !errors.Is(err, ErrCommandNotAllowed) {
			t.Errorf("for %q: got %v, want ErrCommandNotAllowed", bad, err)
		}
	}
}

func TestValidateCommand_OperatorOverride(t *testing.T) {
	allow := []string{"/opt/sieve-py/bin/python3", "/usr/bin/node"}
	if err := ValidateCommand("/usr/bin/node", allow); err != nil {
		t.Errorf("operator-allowlisted /usr/bin/node should pass, got %v", err)
	}
	if err := ValidateCommand("/usr/bin/ruby", allow); err == nil {
		t.Error("non-allowlisted /usr/bin/ruby should be rejected")
	}
}

func TestValidateCommand_SymlinkResolution(t *testing.T) {
	// Create a real interpreter target in the temp dir and a symlink
	// pointing at it. Allowlist contains ONLY the symlink target.
	// Passing the symlink path should succeed because it resolves to
	// the allowed target. Passing a different path to the same target
	// (a sibling symlink in the same dir) should also succeed —
	// resolution is what matters, not the literal string.
	dir := t.TempDir()
	target := filepath.Join(dir, "python3-real")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "python3-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	// Allowlist holds the target. The symlink should be accepted.
	if err := ValidateCommand(link, []string{target}); err != nil {
		t.Errorf("symlink %q -> %q should pass, got %v", link, target, err)
	}
}

func TestValidateCommand_SymlinkEscapeAttempt(t *testing.T) {
	// Operator allowlists only the canonical Python interpreter; an
	// attacker symlinks /tmp/fake-python -> /bin/sh and tries to use
	// the symlink path. Resolution still routes to /bin/sh, which is
	// not allowlisted, so the check fails.
	dir := t.TempDir()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	link := filepath.Join(dir, "fake-python")
	if err := os.Symlink("/bin/sh", link); err != nil {
		t.Fatal(err)
	}
	allow := []string{"/opt/sieve-py/bin/python3"}
	if err := ValidateCommand(link, allow); err == nil {
		t.Error("symlink escape to /bin/sh should be rejected")
	}
}
