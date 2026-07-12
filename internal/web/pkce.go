package web

import (
	"net/url"

	"golang.org/x/oauth2"
)

// PKCE (RFC 7636) lets Sieve run the OAuth authorization-code flow as a PUBLIC
// client — no confidential client_secret embedded in the distributed binary.
// A fresh random "verifier" is minted per flow and held ONLY server-side in the
// pendingOAuth entry (state-keyed, TTL'd, single-use); only its SHA-256
// "challenge" is sent to the provider on the authorize redirect, and the raw
// verifier is replayed at token exchange. A stolen authorization code is
// useless without the verifier, which never leaves this process.
//
// This layer is deliberately provider-agnostic so every OAuth connector Sieve
// has today (google, slack) or adds later (asana, linear) reuses the exact
// same verifier lifecycle. The contract for a new provider is four steps:
//
//  1. at /start: v := newPKCEVerifier(); stash it in the pendingOAuth entry
//     (pendingOAuth.CodeVerifier) alongside the state;
//  2. on the authorize redirect: send the challenge — library-based providers
//     (google, and future asana/linear via golang.org/x/oauth2) pass
//     oauth2.S256ChallengeOption(v) to AuthCodeURL; hand-rolled providers
//     (slack builds its own URL) merge pkceChallengeParams(v) into the query;
//  3. on callback: read pending.CodeVerifier back out;
//  4. at exchange: library callers pass oauth2.VerifierOption(v) to Exchange;
//     hand-rolled callers send a "code_verifier" form field.
//
// Confidential vs public. When an operator brings their own OAuth app
// (BYO client_secret), a provider MAY keep authenticating with the secret.
// When there is no secret (Sieve's shipped, distributed app), PKCE is the sole
// client proof. Providers pick per their platform's rules:
//   - Google accepts PKCE alongside its client_secret (its installed-app secret
//     is non-confidential), so we always add the challenge on top.
//   - Slack forbids client_secret when using PKCE, so the slack path sends the
//     verifier INSTEAD of the secret whenever no secret is configured.
// Keeping the verifier plumbing uniform means a provider only has to encode
// that one platform-specific decision, not re-derive the whole flow.

// newPKCEVerifier mints a fresh high-entropy PKCE code verifier. Thin wrapper
// over the oauth2 helper so callers in this package don't each import oauth2
// just for this, and so the source of randomness is centralized.
func newPKCEVerifier() string { return oauth2.GenerateVerifier() }

// pkceChallengeParams returns the authorize-endpoint query parameters for an
// S256 PKCE challenge derived from verifier. Intended for providers that build
// the authorize URL by hand (e.g. slack); library-based providers should use
// oauth2.S256ChallengeOption(verifier) with AuthCodeURL instead.
func pkceChallengeParams(verifier string) url.Values {
	return url.Values{
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(verifier)},
		"code_challenge_method": {"S256"}, // the only method Slack (and Google) accept
	}
}
