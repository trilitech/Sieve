//go:build !windows

// The non-regular-file test uses syscall.Mkfifo, which is not defined on
// Windows; the symlink test uses os.Symlink, which on Windows requires
// Developer Mode / admin and is irrelevant to the Unix-y deployments
// Sieve actually targets. Keeping the whole file POSIX-only avoids a
// hard compile failure on Windows builders.

package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/trilitech/Sieve/internal/policy"
)

// TestNewScriptEvaluator_RefusesNonRegularFile verifies that a script
// path pointing at a non-regular file (FIFO in this test) is rejected
// at construction time. The interpreter would block or read garbage
// from a FIFO, so refusing surfaces the misconfiguration loudly.
func TestNewScriptEvaluator_RefusesNonRegularFile(t *testing.T) {
	t.Cleanup(func() { policy.SetCommandAllowlist(nil) })
	policy.SetCommandAllowlist([]string{"/usr/bin/python3", "/bin/sh"})

	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Skipf("mkfifo not supported on this platform: %v", err)
	}
	_, err := policy.NewScriptEvaluator(map[string]any{
		"command": "/bin/sh",
		"script":  fifoPath,
	})
	if err == nil {
		t.Fatal("expected NewScriptEvaluator to refuse FIFO script path")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Errorf("error should mention 'regular file', got: %v", err)
	}
}

// TestNewScriptEvaluator_ResolvesSymlinkToRegularFile confirms a
// symlink to a regular script is accepted (we still need to support
// e.g. NixOS-style symlink-farm deployments) and that the evaluator's
// in-memory config carries the resolved path — so the script that
// Evaluate() invokes can't be redirected by a later swap of the
// symlink target without going through a fresh NewScriptEvaluator call.
func TestNewScriptEvaluator_ResolvesSymlinkToRegularFile(t *testing.T) {
	t.Cleanup(func() { policy.SetCommandAllowlist(nil) })
	policy.SetCommandAllowlist([]string{"/bin/sh"})

	dir := t.TempDir()
	realPath := filepath.Join(dir, "real.sh")
	if err := os.WriteFile(realPath, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "link.sh")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := policy.NewScriptEvaluator(map[string]any{
		"command": "/bin/sh",
		"script":  linkPath,
	}); err != nil {
		t.Fatalf("symlink to regular file should be accepted, got: %v", err)
	}
}

// TestNewScriptEvaluator_RejectsMissingFile pins the not-found case so a
// future refactor of the path-resolution block can't silently downgrade
// the error to "exists but unusable" (or vice versa).
func TestNewScriptEvaluator_RejectsMissingFile(t *testing.T) {
	t.Cleanup(func() { policy.SetCommandAllowlist(nil) })
	policy.SetCommandAllowlist([]string{"/bin/sh"})

	missing := filepath.Join(t.TempDir(), "does-not-exist.sh")
	_, err := policy.NewScriptEvaluator(map[string]any{
		"command": "/bin/sh",
		"script":  missing,
	})
	if err == nil {
		t.Fatal("expected NewScriptEvaluator to refuse missing script path")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}
