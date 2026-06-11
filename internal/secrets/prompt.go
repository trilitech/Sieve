package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/term"
)

// PassphraseFileEnv names the environment variable that points to a file
// containing the passphrase. Mirrors the pattern systemd's LoadCredential=
// uses, and lets operators mount a secret file into the container.
const PassphraseFileEnv = "SIEVE_PASSPHRASE_FILE"

// passphraseSourceFD3 is FD 3 — the conventional handoff slot used by
// systemd-supplied credentials and other supervisor patterns.
const passphraseSourceFD3 = 3

// PromptOptions controls how Acquire reads the passphrase.
type PromptOptions struct {
	// Confirm, when true, prompts twice and verifies the two entries match.
	// First-run setup uses this; routine startup does not.
	Confirm bool

	// Prompt is the human-facing label printed before the read. Defaults
	// to "Sieve passphrase: ".
	Prompt string
}

// IsStdinTerminal reports whether stdin is connected to a TTY. Centralized
// here so callers outside this package (notably cmd/sieve, which gates the
// destructive --reset-keyring flag on a TTY confirmation) use the same
// check `Acquire` uses below — different definitions of "is a TTY" can
// disagree on edge cases (PTY-wrapped pipes, virtio consoles), and a
// reset path that disagrees with the prompt path is a UX trap.
func IsStdinTerminal() bool {
	return term.IsTerminal(int(syscall.Stdin))
}

// Acquire reads a passphrase using the documented priority order:
// 1. If stdin is a TTY → prompt with echo off (golang.org/x/term).
// 2. Else if SIEVE_PASSPHRASE_FILE is set → read that file. If the path
// starts with /run/secrets or is otherwise an ephemeral mount the
// operator manages, the file is *not* deleted; it's the operator's
// responsibility. Reading it once into memory is enough.
// 3. Else if FD 3 is open → read until EOF (matches systemd LoadCredential).
// 4. Else → return an error so startup fails loudly.
// Environment variables (other than the file pointer) are deliberately
// not supported — env leaks through /proc/<pid>/environ, ps, and crash
// dumps. If you need to plumb a passphrase from CI, write it to a file
// and point SIEVE_PASSPHRASE_FILE at it.
func Acquire(opts PromptOptions) ([]byte, error) {
	prompt := opts.Prompt
	if prompt == "" {
		prompt = "Sieve passphrase: "
	}

	if IsStdinTerminal() {
		return acquireTTY(prompt, opts.Confirm)
	}

	if path := os.Getenv(PassphraseFileEnv); path != "" {
		return acquireFile(path)
	}

	if fd3Open() {
		return acquireFD3()
	}

	return nil, errors.New("no passphrase source available: stdin is not a TTY, " +
		PassphraseFileEnv + " is unset, and FD 3 is closed")
}

func acquireTTY(prompt string, confirm bool) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pp, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	if len(pp) == 0 {
		return nil, errors.New("empty passphrase")
	}

	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		pp2, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read confirm: %w", err)
		}
		if !bytes.Equal(pp, pp2) {
			return nil, errors.New("passphrases do not match")
		}
		// Zero the duplicate before discarding.
		for i := range pp2 {
			pp2[i] = 0
		}
	}

	return pp, nil
}

func acquireFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read passphrase file %q: %w", path, err)
	}
	pp := bytes.TrimRight(data, "\r\n")
	if len(pp) == 0 {
		return nil, fmt.Errorf("passphrase file %q is empty", path)
	}
	return pp, nil
}

func acquireFD3() ([]byte, error) {
	f := os.NewFile(passphraseSourceFD3, "passphrase-fd3")
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read FD 3: %w", err)
	}
	pp := bytes.TrimRight(data, "\r\n")
	if len(pp) == 0 {
		return nil, errors.New("FD 3 supplied an empty passphrase")
	}
	return pp, nil
}

// fd3Open returns true if file descriptor 3 is open in the current process.
// We probe via Stat — open FDs return a file mode; closed FDs error.
func fd3Open() bool {
	var st syscall.Stat_t
	return syscall.Fstat(passphraseSourceFD3, &st) == nil
}
