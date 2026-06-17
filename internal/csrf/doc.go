// Package csrf provides per-session synchronizer-token CSRF protection
// for Sieve's admin UI.
// A 32-byte random token is issued at login and bound to the session row.
// It is embedded in every rendered admin page two ways:
// - As <input type="hidden" name="csrf_token"> in every server-rendered form.
// - As <meta name="csrf-token"> in <head> for fetch-based admin JS callers.
// Verification: the server compares sha256(submitted) against the stored
// session.csrf_token_hash using constant-time compare. Mismatches return
// HTTP 403 and are recorded in the audit log.
// Scope: POST/PUT/PATCH/DELETE on the admin listener. GET/HEAD/OPTIONS exempt
// per HTTP semantics. OAuth callback endpoints exempt — they are protected by
// the OAuth state parameter, which is functionally equivalent.
package csrf
