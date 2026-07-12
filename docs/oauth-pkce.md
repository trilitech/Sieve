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

## Configuring the client at launch

Sieve is launched with the client ID of the OAuth app **you** publish, so users
don't register their own. Set it via CLI flag or environment variable (a `client_id`
with no secret ⇒ PKCE public client):

| Provider | Flag | Env |
|---|---|---|
| Google | `--google-oauth-client-id` / `--google-oauth-client-secret` | `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` |
| Slack | `--slack-client-id` / `--slack-client-secret` | `SLACK_CLIENT_ID` / `SLACK_CLIENT_SECRET` |

Precedence, highest first: **admin-UI stored value (Slack only) → CLI flag → env
var → build-time default** (Google's `defaultGoogleClientID`, injectable with
`-ldflags` at release time). Full flag list:
[CLI reference → OAuth app client flags](cli-reference.md#oauth-app-client-flags).

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

## Verifying the flow locally

### Smoke test — no external account (30 seconds)

Confirms the public-client authorize leg without completing consent. Launch with
any dummy client_id and no secret so the provider runs in PKCE mode:

```bash
./sieve --slack-client-id "123.456"      # or --google-oauth-client-id "dummy"
```

In the admin UI, start an install (Slack card → **Install via OAuth**). The
provider will reject the bogus id, but the **authorize URL** (address bar, or
DevTools → Network → the 302) carries the proof:

```
...oauth/v2/authorize?...&code_challenge=<hash>&code_challenge_method=S256
```

If you see `code_challenge` + `code_challenge_method=S256`, the public-client
PKCE leg is wired.

### Full round-trip — Google (~10 min, plain HTTP loopback)

Google accepts an `http://127.0.0.1` / `http://localhost` loopback redirect, so
no TLS is needed:

1. Register an OAuth client ([Google OAuth setup](google-oauth-setup.md)) with
   redirect `http://localhost:19816/oauth/callback`; download the JSON or note
   the client id/secret.
2. `./sieve --google-credentials ./data/credentials.json`
   (or `--google-oauth-client-id … --google-oauth-client-secret …`).
3. Connections → **Connect Google Account**. Before approving, confirm
   `code_challenge=` is in the authorize URL → approve → connection goes
   `active`. Token refresh runs locally, so this exercises authorize + PKCE
   exchange + refresh.

### Full round-trip — Slack (HTTPS loopback)

Slack requires an `https` redirect, but **`https://localhost` loopback works
locally — no public tunnel needed.** Enable TLS on the admin listener:

1. Generate a localhost cert/key (e.g. `mkcert localhost` or a self-signed pair).
2. In the admin UI **Settings** (`/settings`), set:
   - `public_base_url` → `https://localhost:19816`
   - `admin.tls_cert_path` / `admin.tls_key_path` → your cert/key paths

   then restart Sieve (it now serves the admin UI over HTTPS).
3. In your Slack app's **OAuth & Redirect URLs**, register
   `https://localhost:19816/oauth/callback`.
4. Launch with your Slack client id (omit the secret for the PKCE public flow):
   `./sieve --slack-client-id "…"`
5. Connections → Slack → **Install via OAuth** → approve. The connection lands
   `active`; the exchange sent `code_verifier` and no `client_secret`.

## Distribution: internal (org-only) vs external (public)

*How* you register the OAuth app — not the PKCE code — decides how much review
and compliance burden you take on. Choose by audience:

### Internal — your organization's members only (lowest friction, recommended for org rollouts)

Best when Sieve is for your own team. Register each provider so only accounts in
your own tenant can use it:

- **Google — Workspace "Internal" app.** Create the Cloud project *inside your
  Google Workspace org* and set the OAuth consent screen **User Type =
  Internal**. Then:
  - **No verification, no CASA, no "unverified app" warning, no 100-user cap** —
    even with restricted scopes (`gmail.modify`, Drive). CASA/verification are an
    *External*-app requirement; Internal apps are exempt.
  - Only `@your-domain` accounts can authorize; personal Gmail / other orgs
    cannot.
  - Optional zero-consent: in **Admin console → Security → API controls → App
    access control**, mark the app **Trusted** for its scopes so employees skip
    the consent screen entirely.
  - Register a **Desktop** client (loopback + PKCE, `http://127.0.0.1` — no TLS
    needed); ship its id via `--google-oauth-client-id`.
- **Slack — single-workspace app.** Create the app and install it only in your
  workspace; **do not submit it to the Slack Marketplace** (Marketplace review is
  only for public distribution). The HTTPS-loopback redirect still applies (see
  [connectors-slack.md](connectors-slack.md#redirect-requirement)). Ship the id
  via `--slack-client-id`.

Everything stays under your existing tenant agreement (your Google Workspace /
Slack org terms) — an internal-tool rollout, not public developer distribution.
**Boundary:** Internal covers *members of your org only*. The moment the audience
includes personal accounts, external contractors, or the public, you must switch
to External.

### External — anyone (public distribution, burdened)

Required only if non-org users install Sieve:

- **Google:** consent screen **User Type = External** + app verification +
  (for restricted Gmail/Drive scopes) an **annual CASA** assessment + a
  Limited-Use-compliant privacy policy. Your company becomes the accountable
  registered developer.
- **Slack:** submit the app to the **Slack Marketplace** for review.

> Not legal advice: the External path binds your company to each provider's
> user-data policies. Have counsel review before publishing.

## What PKCE does *not* solve

PKCE removes the *secret* from the flow. It does **not** remove a provider's app
**review/verification** requirements. For Google, Gmail's `gmail.modify` and
Drive are *restricted scopes*: a publicly distributed app requesting them must
still pass Google OAuth verification and an annual CASA security assessment,
regardless of PKCE. Keep the requested scope set minimal to reduce that review.
