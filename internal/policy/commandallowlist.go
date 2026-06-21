package policy

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Package-level command allowlist. The web server's startup wires the
// operator-configured value via SetCommandAllowlist after reading
// settings.CommandAllowlist; the rules engine and script evaluator
// pick it up implicitly through CurrentCommandAllowlist.
// Using a package var avoids cascading signature changes through
// CreateEvaluator/NewScriptEvaluator/NewRulesEvaluator (each of which
// has multiple call sites in production code and tests). The trade-off
// is that tests must reset the var on entry to avoid cross-test leak;
// they do so with `t.Cleanup(func() { policy.SetCommandAllowlist(nil) })`
// at the start of each test that mutates it.
var (
	cmdAllowlistMu sync.RWMutex
	cmdAllowlist   []string // nil = caller has not configured; ValidateCommand uses DefaultCommand
)

// SetCommandAllowlist replaces the package-level command allowlist.
// Pass nil or an empty slice to revert to the bundled-Python default.
// Entries that don't contain a path separator are dropped — a bare
// "python3" would resolve via PATH at exec time, which depends on the
// runtime environment of the script process and effectively bypasses
// the allowlist. Absolute paths only.
func SetCommandAllowlist(list []string) {
	cmdAllowlistMu.Lock()
	defer cmdAllowlistMu.Unlock()
	if len(list) == 0 {
		cmdAllowlist = nil
		return
	}
	cleaned := make([]string, 0, len(list))
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Reject bare PATH-relative entries. `filepath.IsAbs` catches both
		// Unix /foo/bar and Windows C:\foo\bar so future cross-platform
		// builds don't silently relax this check.
		if !filepath.IsAbs(entry) {
			continue
		}
		cleaned = append(cleaned, entry)
	}
	if len(cleaned) == 0 {
		cmdAllowlist = nil
		return
	}
	cmdAllowlist = cleaned
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
// Without the check, the raw value flows to exec.CommandContext, letting
// a policy author shell out to any binary on the host. Allowlist
// enforcement keeps script policies inside the bundled-Python sandbox.
var ErrCommandNotAllowed = errors.New("command not in allowlist")

// ValidateCommand returns nil if cmd resolves (after symlink resolution
// and Clean) to an entry in the allowlist. Empty allowlists fall back to
// the canonical default (the bundled Python interpreter that ships with
// the Sieve Docker image).
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
		effective = defaultCommands()
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
// Docker image. Guards/filters can be written in Python or JavaScript;
// DefaultCommand + DefaultNodeCommand are the two runtimes permitted when the
// operator hasn't customised the allowlist.
const DefaultCommand = "/opt/sieve-py/bin/python3"

// DefaultNodeCommand is the Node.js runtime for JavaScript guards/filters,
// resolved from PATH at startup (falls back to /usr/bin/node if not found).
var DefaultNodeCommand = func() string {
	if p, err := exec.LookPath("node"); err == nil {
		return p
	}
	return "/usr/bin/node"
}()

// defaultCommands is the effective command allowlist when the operator hasn't
// configured one: the bundled Python plus Node — the two supported script
// languages (same trust level; both gated by this allowlist + the script-path
// allowlist).
func defaultCommands() []string {
	return []string{DefaultCommand, DefaultNodeCommand}
}

// --- script path allowlist ---
// script_guard/script_filter reference a script FILE by path (operators point
// at a curated script, rather than pasting it inline). The path must live under
// an allowlisted base directory so the interpreter can't be aimed at an
// arbitrary host file. Mirrors the command allowlist above.

var (
	scriptDirsMu sync.RWMutex
	scriptDirs   []string // nil = use DefaultScriptDir
)

// DefaultScriptDir is where Sieve's bundled runtime + operator scripts live in
// the Docker image (the venv root that contains the bundled Python).
var DefaultScriptDir = filepath.Dir(filepath.Dir(DefaultCommand)) // /opt/sieve-py

// SetScriptDirs replaces the package-level scripts-base allowlist. nil/empty
// reverts to DefaultScriptDir. Absolute paths only (relative entries dropped).
func SetScriptDirs(dirs []string) {
	scriptDirsMu.Lock()
	defer scriptDirsMu.Unlock()
	if len(dirs) == 0 {
		scriptDirs = nil
		return
	}
	cleaned := make([]string, 0, len(dirs))
	for _, d := range dirs {
		d = strings.TrimSpace(d)
		if d == "" || !filepath.IsAbs(d) {
			continue
		}
		cleaned = append(cleaned, filepath.Clean(d))
	}
	if len(cleaned) == 0 {
		scriptDirs = nil
		return
	}
	scriptDirs = cleaned
}

func currentScriptDirs() []string {
	scriptDirsMu.RLock()
	defer scriptDirsMu.RUnlock()
	if len(scriptDirs) == 0 {
		return []string{DefaultScriptDir}
	}
	return append([]string(nil), scriptDirs...)
}

// ErrScriptPathNotAllowed is returned when a script_guard/filter path is not an
// absolute path under an allowlisted scripts directory.
var ErrScriptPathNotAllowed = errors.New("script path not allowed")

// ValidateScriptPath enforces that path is absolute, contains no "..", and
// resolves (after symlinks) to a real file under an allowlisted scripts
// directory — so the interpreter only ever runs operator-curated scripts.
func ValidateScriptPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: path is empty", ErrScriptPathNotAllowed)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: %q must be an absolute path", ErrScriptPathNotAllowed, path)
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("%w: %q must not contain '..'", ErrScriptPathNotAllowed, path)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("%w: %q (not found or unreadable)", ErrScriptPathNotAllowed, path)
	}
	for _, d := range currentScriptDirs() {
		base, err := filepath.EvalSymlinks(d)
		if err != nil {
			base = filepath.Clean(d)
		}
		if resolved == base || strings.HasPrefix(resolved, base+string(filepath.Separator)) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q must be under one of %v", ErrScriptPathNotAllowed, path, currentScriptDirs())
}
