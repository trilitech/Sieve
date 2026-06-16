package session_test

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/session"
)


func newTestManager(t *testing.T, idle time.Duration) *session.Manager {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return session.NewManager(db, idle)
}

func TestIssue_ReturnsOpaqueValues(t *testing.T) {
	m := newTestManager(t, 0)
	s, err := m.Issue("127.0.0.1", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	if s.Plaintext == "" {
		t.Error("Issue did not return a plaintext cookie value")
	}
	if s.CSRFToken == "" {
		t.Error("Issue did not return a CSRF token")
	}
	// Plaintext must NOT equal its hash — a sanity check that the
	// stored form is distinct from the cookie value.
	if s.Plaintext == s.IDHash {
		t.Error("Plaintext == IDHash — hash never applied")
	}
	if len(s.CSRFHash) != 32 {
		t.Errorf("CSRFHash length = %d, want 32 (sha256)", len(s.CSRFHash))
	}
}

func TestIssue_UniquePerCall(t *testing.T) {
	m := newTestManager(t, 0)
	a, _ := m.Issue("1.1.1.1", "ua-a")
	b, _ := m.Issue("1.1.1.1", "ua-b")
	if a.Plaintext == b.Plaintext {
		t.Error("two Issues returned the same plaintext")
	}
	if a.CSRFToken == b.CSRFToken {
		t.Error("two Issues returned the same CSRF token")
	}
}

func TestLookup_SuccessBumpsExpiry(t *testing.T) {
	m := newTestManager(t, 1*time.Hour)
	s, _ := m.Issue("ip", "ua")
	orig := s.ExpiresAt

	// Lookup should return the row and bump expires_at to ~now + idle.
	time.Sleep(20 * time.Millisecond)
	got, err := m.Lookup(s.Plaintext)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.IDHash != s.IDHash {
		t.Errorf("IDHash mismatch")
	}
	if !got.ExpiresAt.After(orig) {
		t.Errorf("ExpiresAt not bumped: orig=%v new=%v", orig, got.ExpiresAt)
	}
}

func TestLookup_NoCookie(t *testing.T) {
	m := newTestManager(t, 0)
	_, err := m.Lookup("")
	if !errors.Is(err, session.ErrNoSession) {
		t.Errorf("got %v, want ErrNoSession", err)
	}
}

func TestLookup_UnknownCookie(t *testing.T) {
	m := newTestManager(t, 0)
	_, err := m.Lookup("totally-fake-cookie-value-not-in-db")
	if !errors.Is(err, session.ErrNoSession) {
		t.Errorf("got %v, want ErrNoSession", err)
	}
}

func TestLookup_ExpiredRowDeleted(t *testing.T) {
	// Use a very short idle timeout; sleep past it; Lookup returns
	// ErrExpired and removes the row.
	m := newTestManager(t, 10*time.Millisecond)
	s, _ := m.Issue("ip", "ua")
	time.Sleep(50 * time.Millisecond)
	_, err := m.Lookup(s.Plaintext)
	if !errors.Is(err, session.ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
	// Subsequent Lookup of the same value should now report NoSession.
	_, err = m.Lookup(s.Plaintext)
	if !errors.Is(err, session.ErrNoSession) {
		t.Errorf("after expiry sweep got %v, want ErrNoSession", err)
	}
}

func TestLookup_AbsoluteCapTerminatesRefreshedSession(t *testing.T) {
	// A session that gets pinged on a short cadence (sliding window stays
	// fresh) MUST still expire at the absolute cap. Otherwise a stolen
	// cookie + refresh-on-timer lives forever.
	m := newTestManager(t, 10*time.Second) // idle: plenty of headroom
	m.SetAbsoluteTimeout(50 * time.Millisecond)
	s, _ := m.Issue("ip", "ua")

	// First Lookup well inside the absolute window: succeeds and bumps idle.
	time.Sleep(10 * time.Millisecond)
	if _, err := m.Lookup(s.Plaintext); err != nil {
		t.Fatalf("Lookup inside absolute window: %v", err)
	}

	// Sleep past the absolute cap. Idle window is still way in the future,
	// so without the absolute cap this would happily refresh forever.
	time.Sleep(60 * time.Millisecond)
	_, err := m.Lookup(s.Plaintext)
	if !errors.Is(err, session.ErrExpired) {
		t.Fatalf("past absolute cap: got %v, want ErrExpired", err)
	}
}

func TestLogout_DeletesRow(t *testing.T) {
	m := newTestManager(t, 0)
	s, _ := m.Issue("ip", "ua")
	if err := m.Logout(s.Plaintext); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Lookup(s.Plaintext); !errors.Is(err, session.ErrNoSession) {
		t.Errorf("post-logout lookup got %v, want ErrNoSession", err)
	}
}

func TestLogout_IdempotentOnUnknown(t *testing.T) {
	m := newTestManager(t, 0)
	if err := m.Logout("not-a-session"); err != nil {
		t.Errorf("Logout on unknown value should be a no-op: %v", err)
	}
}

func TestSweepExpired_RemovesOnlyExpired(t *testing.T) {
	m := newTestManager(t, 50*time.Millisecond)
	expired, _ := m.Issue("ip-a", "ua")
	time.Sleep(60 * time.Millisecond)
	live, _ := m.Issue("ip-b", "ua")

	deleted, err := m.SweepExpired()
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Errorf("swept %d, want 1", deleted)
	}
	if _, err := m.Lookup(live.Plaintext); err != nil {
		t.Errorf("live session got %v after sweep", err)
	}
	if _, err := m.Lookup(expired.Plaintext); !errors.Is(err, session.ErrNoSession) {
		t.Errorf("expired session still present: %v", err)
	}
}

func TestDeleteAll_InvalidatesEverySession(t *testing.T) {
	m := newTestManager(t, 0)
	a, _ := m.Issue("ip", "ua")
	b, _ := m.Issue("ip", "ua")
	if err := m.DeleteAll(); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{a.Plaintext, b.Plaintext} {
		if _, err := m.Lookup(s); !errors.Is(err, session.ErrNoSession) {
			t.Errorf("DeleteAll left session intact: %v", err)
		}
	}
}

func TestVerifyCSRF_Match(t *testing.T) {
	m := newTestManager(t, 0)
	s, _ := m.Issue("ip", "ua")
	if !m.VerifyCSRF(s, s.CSRFToken) {
		t.Error("matching CSRF should verify")
	}
}

func TestVerifyCSRF_Mismatch(t *testing.T) {
	m := newTestManager(t, 0)
	s, _ := m.Issue("ip", "ua")
	if m.VerifyCSRF(s, "wrong-token") {
		t.Error("wrong CSRF must NOT verify")
	}
	if m.VerifyCSRF(s, "") {
		t.Error("empty CSRF must NOT verify")
	}
	if m.VerifyCSRF(nil, s.CSRFToken) {
		t.Error("nil session must NOT verify")
	}
}

func TestNewCookie_AttributesAreSafe(t *testing.T) {
	c := session.NewCookie("opaque-value", true)
	if !c.HttpOnly {
		t.Error("cookie MUST be HttpOnly")
	}
	// SameSite=Lax (not Strict) because the OAuth callback flow returns
	// the operator via a top-level cross-site navigation from an external
	// identity provider; under Strict the session cookie wouldn't ride
	// along and the OAuth callback's session-hash check would 403 every
	// flow. CSRF defense relies on the explicit token check, not on
	// SameSite=Strict; see session.go NewCookie for the rationale.
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if !c.Secure {
		t.Error("Secure should be true when TLS is on")
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want /", c.Path)
	}
	if !strings.Contains(c.String(), "opaque-value") {
		t.Errorf("cookie value missing from serialization: %s", c.String())
	}
}

func TestNewCookie_SecureFalseOnPlaintext(t *testing.T) {
	c := session.NewCookie("v", false)
	if c.Secure {
		t.Error("Secure should be false when TLS is off")
	}
}

func TestClearCookie_NegativeMaxAge(t *testing.T) {
	c := session.ClearCookie(false)
	if c.MaxAge >= 0 {
		t.Errorf("ClearCookie MaxAge = %d, want < 0", c.MaxAge)
	}
}
