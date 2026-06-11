// Package session — see doc.go for the contract.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/trilitech/Sieve/internal/database"
)

// CookieName is the cookie that carries the opaque session identifier.
// HttpOnly + SameSite=Strict + Secure (when TLS is on) are set by Issue.
const CookieName = "sieve_session"

// DefaultIdleTimeout is the documented sliding-window expiry. Settings
// can override via the session.idle_timeout_minutes key.
const DefaultIdleTimeout = 8 * time.Hour

// DefaultAbsoluteTimeout is the upper bound a session can live for,
// regardless of activity. A session refreshed every 7h forever, or a
// stolen cookie pinged from a script, must still terminate eventually.
// 24h is the documented cap; the operator can re-authenticate.
const DefaultAbsoluteTimeout = 24 * time.Hour

// sessionIDLen is the byte length of the opaque cookie value, base64url-
// encoded (no padding) — 32 bytes → 43 chars in the cookie, 64-char
// SHA-256 hex stored in the DB.
const sessionIDLen = 32

// ErrNoSession means the cookie value did not match a live session row.
// Includes both "no cookie" and "cookie present but unknown to server"
// since the caller's response is identical (401).
var ErrNoSession = errors.New("session: no live session")

// ErrExpired means the session row exists but its sliding-window expiry
// has elapsed. Caller deletes the row and returns 401.
var ErrExpired = errors.New("session: expired")

// Session is the in-process projection of an operator_session row.
// Plaintext SessionID is only populated by Issue (returned to the
// browser); subsequent reads from Lookup return the stored hash form
// for comparison only — the plaintext is never re-derivable from the
// DB.
type Session struct {
	// Plaintext is the opaque session ID handed back to the browser at
	// Issue time. ONLY set by Issue — Lookup leaves it empty because
	// the server stores only the hash.
	Plaintext string

	IDHash         string // hex(sha256(plaintext))
	CSRFToken      string // plaintext CSRF token (set only at Issue)
	CSRFHash       []byte // sha256(CSRFToken) stored in DB
	IP, UserAgent  string
	CreatedAt      time.Time
	LastSeenAt     time.Time
	ExpiresAt      time.Time
	IdleTimeoutDur time.Duration
}

// Manager owns the session storage and lifecycle.
type Manager struct {
	db              *database.DB
	idleTimeout     time.Duration
	absoluteTimeout time.Duration

	// now is injected for tests; production code uses time.Now.
	now func() time.Time
}

// NewManager constructs a session manager. Pass time.Duration(0) for
// the default idle timeout (8h); the absolute timeout uses DefaultAbsoluteTimeout.
func NewManager(db *database.DB, idleTimeout time.Duration) *Manager {
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}
	return &Manager{
		db:              db,
		idleTimeout:     idleTimeout,
		absoluteTimeout: DefaultAbsoluteTimeout,
		now:             time.Now,
	}
}

// SetAbsoluteTimeout overrides the absolute (creation-anchored) expiry
// cap. Used by tests to validate the cap; production wiring sticks with
// DefaultAbsoluteTimeout.
func (m *Manager) SetAbsoluteTimeout(d time.Duration) {
	if d <= 0 {
		d = DefaultAbsoluteTimeout
	}
	m.absoluteTimeout = d
}

// Issue creates a new session row. Returns the Session struct populated
// with the plaintext cookie value (Plaintext) and CSRF token (CSRFToken)
// that the caller hands back to the browser. The server stores only the
// SHA-256 hash of each.
func (m *Manager) Issue(ip, userAgent string) (*Session, error) {
	plaintext, err := randString(sessionIDLen)
	if err != nil {
		return nil, fmt.Errorf("session: generate id: %w", err)
	}
	csrfPlain, err := randString(sessionIDLen)
	if err != nil {
		return nil, fmt.Errorf("session: generate csrf: %w", err)
	}
	idHash := sha256Hex(plaintext)
	csrfHash := sha256.Sum256([]byte(csrfPlain))

	now := m.now().UTC()
	expires := now.Add(m.idleTimeout)

	_, err = m.db.Exec(`
		INSERT INTO operator_session
			(id, created_at, last_seen_at, expires_at, csrf_token_hash, ip, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		idHash,
		now.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
		expires.Format(time.RFC3339Nano),
		csrfHash[:],
		ip, userAgent,
	)
	if err != nil {
		return nil, fmt.Errorf("session: insert: %w", err)
	}
	return &Session{
		Plaintext:      plaintext,
		IDHash:         idHash,
		CSRFToken:      csrfPlain,
		CSRFHash:       csrfHash[:],
		IP:             ip,
		UserAgent:      userAgent,
		CreatedAt:      now,
		LastSeenAt:     now,
		ExpiresAt:      expires,
		IdleTimeoutDur: m.idleTimeout,
	}, nil
}

// Lookup hashes the supplied cookie value and looks up the row. Returns:
// - ErrNoSession when no row matches.
// - ErrExpired when the row exists but is past its sliding expiry.
// The row is deleted as part of this call.
// - a populated Session (Plaintext empty) and no error otherwise.
// Bumps LastSeenAt + ExpiresAt on success (sliding window).
func (m *Manager) Lookup(cookieValue string) (*Session, error) {
	if cookieValue == "" {
		return nil, ErrNoSession
	}
	idHash := sha256Hex(cookieValue)
	row := m.db.QueryRow(`
		SELECT id, created_at, last_seen_at, expires_at, csrf_token_hash, ip, user_agent
		FROM operator_session WHERE id = ?`, idHash)
	var s Session
	var createdAt, lastSeen, expires string
	if err := row.Scan(&s.IDHash, &createdAt, &lastSeen, &expires, &s.CSRFHash, &s.IP, &s.UserAgent); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoSession
		}
		return nil, fmt.Errorf("session: scan: %w", err)
	}
	s.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	s.LastSeenAt, _ = time.Parse(time.RFC3339Nano, lastSeen)
	s.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	s.IdleTimeoutDur = m.idleTimeout

	now := m.now().UTC()
	if !now.Before(s.ExpiresAt) {
		// Sliding window has elapsed. Sweep this row; caller treats this as a 401.
		_, _ = m.db.Exec(`DELETE FROM operator_session WHERE id = ?`, idHash)
		return nil, ErrExpired
	}
	// Absolute cap: a session refreshed indefinitely must still terminate.
	// A stolen cookie pinged on a timer survives sliding-window expiry but
	// cannot outrun the creation-anchored cap.
	if m.absoluteTimeout > 0 && !now.Before(s.CreatedAt.Add(m.absoluteTimeout)) {
		_, _ = m.db.Exec(`DELETE FROM operator_session WHERE id = ?`, idHash)
		return nil, ErrExpired
	}

	// Bump sliding expiry. Clamp to the absolute cap so a session approaching
	// its absolute deadline doesn't appear to renew past it.
	newExpires := now.Add(m.idleTimeout)
	if m.absoluteTimeout > 0 {
		absoluteDeadline := s.CreatedAt.Add(m.absoluteTimeout)
		if newExpires.After(absoluteDeadline) {
			newExpires = absoluteDeadline
		}
	}
	_, err := m.db.Exec(`UPDATE operator_session
		SET last_seen_at = ?, expires_at = ?
		WHERE id = ?`,
		now.Format(time.RFC3339Nano),
		newExpires.Format(time.RFC3339Nano),
		idHash)
	if err != nil {
		return nil, fmt.Errorf("session: bump: %w", err)
	}
	s.LastSeenAt = now
	s.ExpiresAt = newExpires
	return &s, nil
}

// Logout deletes a session by its plaintext cookie value. No-op when
// the row is already gone — operator clicking logout twice is fine.
func (m *Manager) Logout(cookieValue string) error {
	if cookieValue == "" {
		return nil
	}
	idHash := sha256Hex(cookieValue)
	_, err := m.db.Exec(`DELETE FROM operator_session WHERE id = ?`, idHash)
	if err != nil {
		return fmt.Errorf("session: delete: %w", err)
	}
	return nil
}

// SweepExpired deletes session rows whose expires_at < now. Called from
// a background goroutine in production with a 5-minute cadence; tests
// invoke it directly.
func (m *Manager) SweepExpired() (deleted int, err error) {
	res, err := m.db.Exec(`DELETE FROM operator_session WHERE expires_at < ?`,
		m.now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("session: sweep: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// DeleteAll removes every session row. Called on credential rotation
// so live sessions cannot survive a credential change.
func (m *Manager) DeleteAll() error {
	_, err := m.db.Exec(`DELETE FROM operator_session`)
	if err != nil {
		return fmt.Errorf("session: delete all: %w", err)
	}
	return nil
}

// VerifyCSRF compares the submitted plaintext CSRF token against the
// session's stored hash. Constant-time. Returns true iff the token
// matches.
func (m *Manager) VerifyCSRF(s *Session, submitted string) bool {
	if s == nil || submitted == "" {
		return false
	}
	candidate := sha256.Sum256([]byte(submitted))
	return subtle.ConstantTimeCompare(candidate[:], s.CSRFHash) == 1
}

// NewCookie returns the http.Cookie the server should set after Issue.
// `secure` is true when the listener serves over TLS.
func NewCookie(plaintext string, secure bool) *http.Cookie {
	c := &http.Cookie{
		Name:     CookieName,
		Value:    plaintext,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	}
	return c
}

// ClearCookie returns a cookie that the browser treats as deletion
// (Max-Age=0). Used by the logout handler.
func ClearCookie(secure bool) *http.Cookie {
	c := NewCookie("", secure)
	c.MaxAge = -1
	return c
}

// --- helpers ---

func randString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
