package testenv_test

import (
	"net/http"
	"testing"

	"github.com/trilitech/Sieve/internal/csrf"
	"github.com/trilitech/Sieve/internal/operator"
	"github.com/trilitech/Sieve/internal/session"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// Spec 001-fix-security-vulns Phase 2 / T009-T010: testenv must let
// tests seed an operator and attach an admin session cookie + CSRF
// token to outgoing requests with one helper call. Without these,
// every test that exercises the (future) authenticated admin surface
// would re-implement the same boilerplate.

func TestNew_ExposesOperatorAndSession(t *testing.T) {
	env := testenv.New(t)
	if env.Operator == nil {
		t.Fatal("Env.Operator must be populated by New()")
	}
	if env.Session == nil {
		t.Fatal("Env.Session must be populated by New()")
	}
	// No credential yet; Exists() should report false.
	exists, err := env.Operator.Exists()
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("fresh testenv must not have an operator credential")
	}
}

func TestWithOperator_SeedsCredentialAndSession(t *testing.T) {
	env := testenv.New(t).WithOperator("test-pass", "test-operator")
	// Operator credential now exists.
	exists, _ := env.Operator.Exists()
	if !exists {
		t.Fatal("WithOperator did not seed credential")
	}
	// Verify works with the seeded value.
	name, err := env.Operator.Verify("test-pass")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if name != "test-operator" {
		t.Errorf("display name = %q, want test-operator", name)
	}
	// SessionCookie returns the active session.
	cookie := env.SessionCookie()
	if cookie == nil {
		t.Fatal("SessionCookie returned nil after WithOperator")
	}
	if cookie.Name != session.CookieName {
		t.Errorf("cookie name = %q, want %q", cookie.Name, session.CookieName)
	}
	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	// CSRFToken returns a non-empty plaintext token.
	if env.CSRFToken() == "" {
		t.Error("CSRFToken returned empty after WithOperator")
	}
}

func TestWithOperator_IdempotentRotation(t *testing.T) {
	env := testenv.New(t).WithOperator("first", "alice")
	firstCookie := env.SessionCookie()

	// Second call should rotate, invalidating the first session and
	// issuing a new one.
	env.WithOperator("second", "alice-renamed")

	if _, err := env.Operator.Verify("second"); err != nil {
		t.Errorf("after rotation, new credential should verify: %v", err)
	}
	if _, err := env.Operator.Verify("first"); err == nil {
		t.Error("after rotation, first credential should NOT verify")
	}
	// Old session cookie should no longer look up.
	if _, err := env.Session.Lookup(firstCookie.Value); err == nil {
		t.Error("rotation should have invalidated the first session")
	}
}

func TestLogin_AfterSetup(t *testing.T) {
	env := testenv.New(t).WithOperator("password", "alice")
	c := env.Login()
	if c == nil || c.Value == "" {
		t.Fatal("Login returned empty cookie")
	}
	// The cookie value should round-trip through the session manager.
	got, err := env.Session.Lookup(c.Value)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got == nil {
		t.Fatal("Lookup returned nil session")
	}
}

func TestCSRFToken_EmptyBeforeSetup(t *testing.T) {
	env := testenv.New(t)
	if env.CSRFToken() != "" {
		t.Error("CSRFToken should be empty before WithOperator/Login")
	}
	if env.SessionCookie() != nil {
		t.Error("SessionCookie should be nil before WithOperator/Login")
	}
}

// TestCSRFTokenVerifies — the token returned by env.CSRFToken() must
// actually verify against the session that env.SessionCookie() points
// at. Otherwise tests would seed a session but the middleware would
// reject every state-changing call.
func TestCSRFTokenVerifies(t *testing.T) {
	env := testenv.New(t).WithOperator("p", "a")
	cookie := env.SessionCookie()
	if cookie == nil {
		t.Fatal("setup failed")
	}
	s, err := env.Session.Lookup(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if !env.Session.VerifyCSRF(s, env.CSRFToken()) {
		t.Error("env.CSRFToken() must verify against env's active session")
	}
}

// Sanity guard: the operator service is using the fast argon2 params
// the testenv configures. If tests start blocking on argon2 we'd
// regress on coverage runtimes.
func TestOperatorUsesFastParams(t *testing.T) {
	env := testenv.New(t)
	wantT, wantM, wantP := operator.FastParams()
	if env.Operator.Time != wantT || env.Operator.MemoryKiB != wantM || env.Operator.Parallelism != wantP {
		t.Errorf("operator params = (%d, %d, %d), want fast params (%d, %d, %d)",
			env.Operator.Time, env.Operator.MemoryKiB, env.Operator.Parallelism,
			wantT, wantM, wantP)
	}
}

// Compile-time guard: ensure the csrf package is importable from
// testenv consumers (some tests use it directly to build CSRF-bearing
// requests).
var _ = csrf.HeaderName
var _ = http.MethodPost
