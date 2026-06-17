// Package operator — see doc.go for the contract.
package operator

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/trilitech/Sieve/internal/database"
)

// Defaults chosen per research.md §1: Argon2id with time=3, memory=64 MiB,
// parallelism=2, salt=16 bytes, key=32 bytes. Lands a verification at
// ~150–300 ms on commodity hardware — under the / SC-012 budgets
// while keeping the offline-attack cost prohibitive.
const (
	DefaultArgon2Time        uint32 = 3
	DefaultArgon2MemoryKiB   uint32 = 64 * 1024
	DefaultArgon2Parallelism uint8  = 2
	DefaultArgon2SaltLen            = 16
	DefaultArgon2KeyLen      uint32 = 32

	// MaxDisplayName is the spec bound on the audit-identity label.
	MaxDisplayName = 64
)

// ErrNoCredential is returned by Verify when no operator credential has
// been set up yet. Callers use this to drive the first-run setup UX —
// the admin listener stays in 503 "locked" mode until a credential is
// installed.
var ErrNoCredential = errors.New("operator: no credential configured")

// ErrInvalidCredential is returned by Verify when the supplied plaintext
// does not match the stored verifier. Indistinguishable in latency from
// the success path (Argon2id runs in both branches).
var ErrInvalidCredential = errors.New("operator: invalid credential")

// SessionTerminator is the seam that lets Rotate invalidate every active
// admin session after a credential change. Implemented by
// session.Manager.DeleteAll; kept as an interface here so the operator
// package doesn't import session (and so tests can stub a no-op).
type SessionTerminator interface {
	DeleteAll() error
}

// Service stores and verifies the single shared admin credential.
type Service struct {
	db *database.DB

	// Tunables exposed for tests — production code uses the Default* constants.
	Time        uint32
	MemoryKiB   uint32
	Parallelism uint8
	SaltLen     int
	KeyLen      uint32

	// sessions, when non-nil, is invoked by Rotate after a successful
	// credential update to invalidate every active operator_session row.
	sessions SessionTerminator
}

// NewService constructs an operator.Service backed by the supplied DB.
// The schema table operator_credential is expected to exist (created by
// the security-hardening migration).
func NewService(db *database.DB) *Service {
	return &Service{
		db:          db,
		Time:        DefaultArgon2Time,
		MemoryKiB:   DefaultArgon2MemoryKiB,
		Parallelism: DefaultArgon2Parallelism,
		SaltLen:     DefaultArgon2SaltLen,
		KeyLen:      DefaultArgon2KeyLen,
	}
}

// SetSessionTerminator wires the session-invalidation callback used by
// Rotate. Pass nil to disable (tests). Production wiring lives in
// cmd/sieve/main.go and supplies the live *session.Manager.
func (s *Service) SetSessionTerminator(st SessionTerminator) {
	s.sessions = st
}

// Exists reports whether a credential has been set up.
func (s *Service) Exists() (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM operator_credential WHERE id = 1`).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("operator: count: %w", err)
	}
	return n > 0, nil
}

// Setup creates the singleton credential row. Refuses to overwrite an
// existing row — use Rotate for credential changes. Trims and validates
// the display name; rejects empty plaintext.
func (s *Service) Setup(credential, displayName string) error {
	if credential == "" {
		return errors.New("operator: credential is empty")
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return errors.New("operator: display name is empty")
	}
	if len(displayName) > MaxDisplayName {
		return fmt.Errorf("operator: display name exceeds %d chars", MaxDisplayName)
	}
	exists, err := s.Exists()
	if err != nil {
		return err
	}
	if exists {
		return errors.New("operator: credential already configured; use Rotate")
	}

	salt := make([]byte, s.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("operator: generate salt: %w", err)
	}
	verifier := argon2.IDKey([]byte(credential), salt, s.Time, s.MemoryKiB, s.Parallelism, s.KeyLen)

	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.Exec(`
		INSERT INTO operator_credential
			(id, display_name, argon2_salt, argon2_time, argon2_memory_kib, argon2_parallelism, verifier, created_at, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)`,
		displayName, salt, s.Time, s.MemoryKiB, s.Parallelism, verifier, now, now,
	)
	if err != nil {
		return fmt.Errorf("operator: insert: %w", err)
	}
	return nil
}

// Verify checks the supplied plaintext against the stored verifier and
// returns the configured display name on success. Indistinguishable in
// latency from a failure (argon2 runs either way).
func (s *Service) Verify(credential string) (displayName string, err error) {
	row := s.db.QueryRow(`
		SELECT display_name, argon2_salt, argon2_time, argon2_memory_kib, argon2_parallelism, verifier
		FROM operator_credential WHERE id = 1`)
	var stored struct {
		Name        string
		Salt        []byte
		Time        uint32
		Memory      uint32
		Parallelism uint8
		Verifier    []byte
	}
	if err := row.Scan(&stored.Name, &stored.Salt, &stored.Time, &stored.Memory, &stored.Parallelism, &stored.Verifier); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNoCredential
		}
		return "", fmt.Errorf("operator: scan: %w", err)
	}
	// Derive a candidate using the row's stored parameters (NOT the
	// service's current defaults — those may have changed since setup).
	candidate := argon2.IDKey(
		[]byte(credential), stored.Salt,
		stored.Time, stored.Memory, stored.Parallelism, uint32(len(stored.Verifier)),
	)
	if subtle.ConstantTimeCompare(candidate, stored.Verifier) != 1 {
		return "", ErrInvalidCredential
	}
	return stored.Name, nil
}

// Rotate replaces the credential and/or the display name. Both newCredential
// and newDisplayName are optional in the sense that an empty value means
// "keep current"; at least one MUST be non-empty. Caller is expected to
// have already verified the operator's right to rotate (i.e., the request
// arrived via an authenticated session).
// On a successful credential change, every active operator session is
// invalidated via the SessionTerminator wired by SetSessionTerminator.
// (Before that hook landed, callers had to remember to call DeleteAll
// themselves — easy to forget when adding a new rotate endpoint.)
// Display-name-only changes do NOT invalidate sessions: the operator's
// identity is unchanged, only their label.
func (s *Service) Rotate(newCredential, newDisplayName string) error {
	if newCredential == "" && newDisplayName == "" {
		return errors.New("operator: nothing to rotate")
	}
	exists, err := s.Exists()
	if err != nil {
		return err
	}
	if !exists {
		return ErrNoCredential
	}

	updates := []string{"updated_at = ?"}
	args := []any{time.Now().UTC().Format(time.RFC3339Nano)}

	if newDisplayName != "" {
		newDisplayName = strings.TrimSpace(newDisplayName)
		if len(newDisplayName) > MaxDisplayName {
			return fmt.Errorf("operator: display name exceeds %d chars", MaxDisplayName)
		}
		updates = append(updates, "display_name = ?")
		args = append(args, newDisplayName)
	}

	if newCredential != "" {
		salt := make([]byte, s.SaltLen)
		if _, err := rand.Read(salt); err != nil {
			return fmt.Errorf("operator: generate salt: %w", err)
		}
		verifier := argon2.IDKey([]byte(newCredential), salt, s.Time, s.MemoryKiB, s.Parallelism, s.KeyLen)
		updates = append(updates,
			"argon2_salt = ?", "argon2_time = ?", "argon2_memory_kib = ?",
			"argon2_parallelism = ?", "verifier = ?")
		args = append(args, salt, s.Time, s.MemoryKiB, s.Parallelism, verifier)
	}

	args = append(args, 1) // WHERE id = 1
	q := "UPDATE operator_credential SET " + strings.Join(updates, ", ") + " WHERE id = ?"
	if _, err := s.db.Exec(q, args...); err != nil {
		return fmt.Errorf("operator: update: %w", err)
	}
	// Invalidate every live session when the credential itself changed.
	// Display-name-only updates keep sessions alive.
	if newCredential != "" && s.sessions != nil {
		if err := s.sessions.DeleteAll(); err != nil {
			return fmt.Errorf("operator: invalidate sessions: %w", err)
		}
	}
	return nil
}

// DisplayName returns the current display name without verifying the
// credential. Returns "" + ErrNoCredential when no row exists.
func (s *Service) DisplayName() (string, error) {
	var name string
	err := s.db.QueryRow(`SELECT display_name FROM operator_credential WHERE id = 1`).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoCredential
	}
	if err != nil {
		return "", fmt.Errorf("operator: read display name: %w", err)
	}
	return name, nil
}

// FastParams returns the Service tuned for test environments — the same
// shape used by internal/testing/testenv for the keyring (cheap argon2
// params that don't blow the test wall clock).
func FastParams() (time, memory uint32, parallelism uint8) {
	return 1, 16 * 1024, 1
}
