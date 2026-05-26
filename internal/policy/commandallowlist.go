package policy

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
)

// Package-level command allowlist. The web server's startup wires the
// operator-configured value via SetCommandAllowlist after reading
// settings.CommandAllowlist(); the rules engine and script evaluator
// pick it up implicitly through CurrentCommandAllowlist.
//
// Using a package var avoids cascading signature changes through
// CreateEvaluator/NewScriptEvaluator/NewRulesEvaluator (each of which
// has multiple call sites in production code and tests). The trade-off
// is that tests must reset the var on entry to avoid cross-test leak —
// see TestMain in this package for the reset hook.
var (
	cmdAllowlistMu sync.RWMutex
	cmdAllowlist   []string // nil = caller has not configured; ValidateCommand uses DefaultCommand
)

// SetCommandAllowlist replaces the package-level command allowlist.
// Pass nil or an empty slice to revert to the bundled-Python default.
func SetCommandAllowlist(list []string) {
	cmdAllowlistMu.Lock()
	defer cmdAllowlistMu.Unlock()
	if len(list) == 0 {
		cmdAllowlist = nil
		return
	}
	cmdAllowlist = append([]string(nil), list...)
}

// CurrentCommandAllowlist returns a copy of the active allowlist. Empty
// when no operator override is in force — callers should treat that as
// "default to DefaultCommand" via ValidateCommand's empty-list semantics.
func CurrentCommandAllowlist() []string {
	cmdAllowlistMu.RLock()
	defer cmdAllowlistMu.RUnlock()
	if len(cmdAllowlist) == 0 {
		return nil
	}
	return append([]string(nil), cmdAllowlist...)
}

// ErrCommandNotAllowed is returned when a script-policy's command field
// (top-level or nested inside a rules-engine script action) names an
// interpreter that the operator-configured allowlist does not permit.
//
// Shannon INJ-VULN-01/02/03 traced an RCE chain through this field: the
// raw value was passed to exec.CommandContext with no validation, so a
// policy author could escape the bundled Python venv and shell out to
// /bin/sh, /usr/bin/perl, etc. Allowlist enforcement closes that path.
//
// Spec anchor: 001-fix-security-vulns US4 / FR-013..FR-018a.
var ErrCommandNotAllowed = errors.New("command not in allowlist")

// ValidateCommand returns nil if cmd resolves (after symlink resolution
// and Clean) to an entry in the allowlist. Empty allowlists fall back to
// the canonical default (the bundled Python interpreter that ships with
// the Sieve Docker image).
//
// The comparison resolves symlinks via filepath.EvalSymlinks so an
// operator who tries `command: /tmp/bash-evil` where /tmp/bash-evil ->
// /bin/bash still fails the check (the resolved path is /bin/bash,
// which is not in the default allowlist).
func ValidateCommand(cmd string, allowlist []string) error {
	if cmd == "" {
		return fmt.Errorf("%w: command is empty", ErrCommandNotAllowed)
	}
	effective := allowlist
	if len(effective) == 0 {
		effective = []string{DefaultCommand}
	}
	// First pass: literal match (cheap; also handles paths that don't
	// resolve, e.g., the bundled Python interpreter in tests that don't
	// ship the venv).
	for _, allowed := range effective {
		if cmd == allowed {
			return nil
		}
	}
	// Second pass: symlink-resolved match. We only attempt resolution
	// when the literal cmd actually exists on the filesystem — non-
	// existent paths can't be the target of a symlink-escape attack.
	resolved, err := filepath.EvalSymlinks(cmd)
	if err != nil {
		// File doesn't exist or can't be read. Either way it's not an
		// allowlisted entry — the literal compare already failed.
		return fmt.Errorf("%w: %q (allowed: %v)", ErrCommandNotAllowed, cmd, effective)
	}
	resolved = filepath.Clean(resolved)
	for _, allowed := range effective {
		allowedResolved, err := filepath.EvalSymlinks(allowed)
		if err != nil {
			allowedResolved = filepath.Clean(allowed)
		} else {
			allowedResolved = filepath.Clean(allowedResolved)
		}
		if resolved == allowedResolved {
			return nil
		}
	}
	return fmt.Errorf("%w: %q resolves to %q (allowed: %v)", ErrCommandNotAllowed, cmd, resolved, effective)
}

// DefaultCommand is the bundled Python interpreter Sieve ships in its
// Docker image. Operators who haven't customised the allowlist get this
// as the sole permitted command.
const DefaultCommand = "/opt/sieve-py/bin/python3"
