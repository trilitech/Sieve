// Package csrf — see doc.go for the contract.
package csrf

import (
	"errors"
	"net/http"

	"github.com/trilitech/Sieve/internal/session"
)

// FormField is the name of the hidden form input that carries the
// CSRF token on POST submissions.
const FormField = "csrf_token"

// HeaderName is the name of the request header that carries the CSRF
// token for fetch-style admin JS callers.
const HeaderName = "X-CSRF-Token"

// MetaName is the value of the <meta name=...> attribute used in
// admin templates to expose the CSRF token to JS.
const MetaName = "csrf-token"

// ErrMissing means the request was a state-changing method but
// neither the form field nor the header carried a CSRF token.
var ErrMissing = errors.New("csrf: token missing")

// ErrMismatch means a CSRF token WAS submitted but didn't match the
// session's stored hash.
var ErrMismatch = errors.New("csrf: token mismatch")

// Extract pulls the CSRF token from the request. Looks at the form
// field first (matches the documented synchronizer-token-in-hidden-
// input pattern); falls back to the X-CSRF-Token header (for fetch-
// style admin JS). Returns the empty string when neither is set.
func Extract(r *http.Request) string {
	if v := r.FormValue(FormField); v != "" {
		return v
	}
	return r.Header.Get(HeaderName)
}

// Check verifies the submitted CSRF token against the session's
// stored hash. Returns ErrMissing when no token was submitted,
// ErrMismatch when a token was submitted but didn't match, nil
// on success.
//
// Callers should invoke this BEFORE any side-effecting code runs
// (DB write, OAuth start, audit emit, etc.). The middleware in
// internal/web wraps this for the admin handler chain.
func Check(r *http.Request, s *session.Session, verify func(*session.Session, string) bool) error {
	submitted := Extract(r)
	if submitted == "" {
		return ErrMissing
	}
	if !verify(s, submitted) {
		return ErrMismatch
	}
	return nil
}

// MethodRequiresCSRF returns true for HTTP methods that change server
// state and therefore need CSRF protection. GET/HEAD/OPTIONS are exempt
// per RFC 9110 safe-method semantics.
func MethodRequiresCSRF(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}
