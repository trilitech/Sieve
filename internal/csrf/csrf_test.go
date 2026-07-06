package csrf_test

import (
	"crypto/sha256"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/csrf"
	"github.com/trilitech/Sieve/internal/session"
)

// mockVerifier matches the signature session.Manager.VerifyCSRF expects.
// Used to drive Check tests without standing up a DB.
func mockVerifier(expected string) func(*session.Session, string) bool {
	return func(_ *session.Session, submitted string) bool {
		return submitted == expected
	}
}

// makeSession returns a session whose CSRFHash matches `token` so the
// real session.Manager.VerifyCSRF would accept it. The Check tests
// use mockVerifier; this helper is for tests that exercise both.
func makeSession(token string) *session.Session {
	sum := sha256.Sum256([]byte(token))
	return &session.Session{CSRFHash: sum[:]}
}

func TestExtract_FormField(t *testing.T) {
	form := url.Values{csrf.FormField: {"the-token"}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := csrf.Extract(r); got != "the-token" {
		t.Errorf("Extract = %q, want %q", got, "the-token")
	}
}

func TestExtract_HeaderFallback(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set(csrf.HeaderName, "header-token")
	if got := csrf.Extract(r); got != "header-token" {
		t.Errorf("Extract = %q", got)
	}
}

func TestExtract_FormBeatsHeader(t *testing.T) {
	form := url.Values{csrf.FormField: {"form"}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set(csrf.HeaderName, "header")
	if got := csrf.Extract(r); got != "form" {
		t.Errorf("Extract = %q, want form-field winner", got)
	}
}

func TestExtract_NeitherSet(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	if got := csrf.Extract(r); got != "" {
		t.Errorf("Extract = %q, want empty", got)
	}
}

func TestCheck_Success(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set(csrf.HeaderName, "good")
	if err := csrf.Check(r, makeSession("good"), mockVerifier("good")); err != nil {
		t.Errorf("Check: %v", err)
	}
}

func TestCheck_Missing(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	if err := csrf.Check(r, makeSession("x"), mockVerifier("x")); !errors.Is(err, csrf.ErrMissing) {
		t.Errorf("got %v, want ErrMissing", err)
	}
}

func TestCheck_Mismatch(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set(csrf.HeaderName, "wrong")
	if err := csrf.Check(r, makeSession("right"), mockVerifier("right")); !errors.Is(err, csrf.ErrMismatch) {
		t.Errorf("got %v, want ErrMismatch", err)
	}
}

func TestMethodRequiresCSRF(t *testing.T) {
	tests := map[string]bool{
		"GET":     false,
		"HEAD":    false,
		"OPTIONS": false,
		"POST":    true,
		"PUT":     true,
		"PATCH":   true,
		"DELETE":  true,
		"":        false,
	}
	for m, want := range tests {
		if got := csrf.MethodRequiresCSRF(m); got != want {
			t.Errorf("MethodRequiresCSRF(%q) = %v, want %v", m, got, want)
		}
	}
}
