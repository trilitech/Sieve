# OAuth PKCE — running as a public client

Sieve is self-hosted: every operator runs their own instance holding their own
credentials. That makes Sieve a **public OAuth client** — it can't safely embed
a confidential `client_secret`, because a secret shipped in a distributed binary
isn't secret. [PKCE](https://datatracker.ietf.org/doc/html/rfc7636) (Proof Key
for Code Exchange) is how a public client runs the authorization-code flow
securely without one.

## How it works

1. At install start, Sieve mints a random **verifier** and sends only its
   SHA-256 **challenge** to the provider's authorize endpoint.
2. The verifier is held server-side in the pending-OAuth entry — state-keyed,
   single-use, with a 10-minute TTL. It never leaves the process and never
   appears in a browser URL.
3. At token exchange, Sieve replays the raw verifier. The provider checks
   `SHA-256(verifier) == challenge`, binding the authorization code to the exact
   flow that started it.

A stolen authorization code is useless without the verifier, so PKCE is a
*stronger* proof than an embedded secret — not a weaker one.

## Public vs confidential

| Mode | When | Client proof |
|---|---|---|
| **Public** (PKCE) | No `client_secret` configured — Sieve's shipped app | the verifier |
| **Confidential** | A `client_secret` is present — bring-your-own (BYO) app | the secret |

Providers differ on whether the two can be combined:

- **Google** accepts PKCE *alongside* its client_secret (a "Desktop app"
  client's secret is [non-confidential by Google's definition](https://developers.google.com/identity/protocols/oauth2)),
  so Sieve always adds the challenge.
- **Slack** forbids sending `client_secret` when using PKCE, so Sieve sends the
  verifier *instead of* the secret whenever no secret is configured.

## Per-provider status

| Provider | PKCE | Notes |
|---|---|---|
| **Google / Gmail** | ✅ | Ships a Desktop client_id (see [Google OAuth setup](google-oauth-setup.md)); loopback redirect `http://127.0.0.1:<port>`. Refresh stays local. |
| **Slack** | ✅ | [GA since March 2026](https://docs.slack.dev/changelog/2026/03/30/pkce/). No secret needed. **Redirect must be HTTPS or a custom URI scheme** — Slack rejects `http://localhost`. |
| **Asana / Linear** (future) | ✅ ready | Standard OAuth2; plug in via the shared verifier plumbing — see below. |

## Adding a new provider

The verifier lifecycle is provider-agnostic (`internal/web/pkce.go`). A new
OAuth connector reuses it in four steps:

1. **/start** — `v := newPKCEVerifier()`; store it in the `pendingOAuth` entry
   alongside the state.
2. **authorize redirect** — library-based providers (Google, and future
   Asana/Linear via `golang.org/x/oauth2`) pass `oauth2.S256ChallengeOption(v)`
   to `AuthCodeURL`; hand-rolled providers (Slack) merge `pkceChallengeParams(v)`
   into the query.
3. **callback** — read `pending.CodeVerifier` back out.
4. **exchange** — library callers pass `oauth2.VerifierOption(v)` to `Exchange`;
   hand-rolled callers send a `code_verifier` form field.

The only provider-specific decision is public-vs-confidential (does the platform
allow the secret alongside PKCE, or require the verifier instead). Everything
else is shared.

## What PKCE does *not* solve

PKCE removes the *secret* from the flow. It does **not** remove a provider's app
**review/verification** requirements. For Google, Gmail's `gmail.modify` and
Drive are *restricted scopes*: a publicly distributed app requesting them must
still pass Google OAuth verification and an annual CASA security assessment,
regardless of PKCE. Keep the requested scope set minimal to reduce that review.
