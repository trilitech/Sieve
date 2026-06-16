// Package session manages opaque cookie sessions for the Sieve admin UI.
// A session is a random 32-byte identifier held by the browser in an
// HttpOnly + SameSite=Lax cookie (Secure when TLS is configured). Lax
// (not Strict) so OAuth callbacks — top-level cross-site navigations
// from accounts.google.com / slack.com — still carry the cookie;
// CSRF defence is the explicit per-session token check, not SameSite.
// The server stores only sha256(id), the issue/last-seen/expires timestamps,
// the per-session CSRF token hash, and audit metadata (ip, user-agent).
// Lifecycle:
// - Issue on successful POST /login.
// - Bump last_seen_at on every authenticated request (sliding idle).
// - Delete on POST /logout, on idle expiry sweep, or on credential rotation.
package session
