// Package session manages opaque cookie sessions for the Sieve admin UI.
//
// A session is a random 32-byte identifier held by the browser in an
// HttpOnly + SameSite=Strict cookie (Secure when TLS is configured).
// The server stores only sha256(id), the issue/last-seen/expires timestamps,
// the per-session CSRF token hash, and audit metadata (ip, user-agent).
//
// Lifecycle:
//   - Issue on successful POST /login.
//   - Bump last_seen_at on every authenticated request (sliding idle).
//   - Delete on POST /logout, on idle expiry sweep, or on credential rotation.
package session
