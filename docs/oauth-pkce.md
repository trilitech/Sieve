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

### Full round-trip — Google (~10 min)

The admin UI serves HTTPS by default, so Google's callback rides the same
`https://localhost:19816/oauth/callback` loopback (Google accepts both `http`
and `https` loopback redirects). Your browser shows a one-time self-signed-cert
warning on the callback — accept it (visit `https://localhost:19816` once up
front to get it out of the way):

1. Register an OAuth client ([Google OAuth setup](google-oauth-setup.md)) with
   redirect `https://localhost:19816/oauth/callback`; download the JSON or note
   the client id/secret.
2. `./sieve --google-credentials ./data/credentials.json`
   (or `--google-oauth-client-id … --google-oauth-client-secret …`).
3. Connections → **Connect Google Account**. Before approving, confirm
   `code_challenge=` is in the authorize URL → approve → connection goes
   `active`. Token refresh runs locally, so this exercises authorize + PKCE
   exchange + refresh.

### Full round-trip — Slack (HTTPS loopback)

Slack requires an `https` redirect, but **`https://localhost` loopback works
locally — no public tunnel needed.** The admin UI serves HTTPS by default, so
there's nothing to enable:

1. **Nothing to generate.** On startup Sieve auto-provisions a self-signed
   loopback cert at `./data/tls/admin-{cert,key}.pem` and serves the admin UI
   over HTTPS. Browse to `https://localhost:19816` and accept the one-time
   browser warning. **For a warning-free cert, run
   `./scripts/trust-localhost-cert.sh` once** (installs `mkcert`, registers a
   locally-trusted CA — needs sudo — and writes a trusted cert to the same
   path; Sieve serves it with HSTS on the next start). `public_base_url`
   defaults to `https://localhost:19816`; leave it unset or match it. Don't set
   an `http://…` value — that opts the admin UI back to plaintext and breaks the
   Slack redirect.
2. In your Slack app's **OAuth & Redirect URLs**, register
   `https://localhost:19816/oauth/callback`.
3. Launch with your Slack client id (omit the secret for the PKCE public flow):
   `./sieve --slack-client-id "…"`
4. Connections → Slack → **Install via OAuth** → approve. The connection lands
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

## Per-connection Google client

One Sieve instance can connect Google accounts from **any number of Workspace
orgs at once**, each connection using its own org's OAuth client. This is how you
keep every org on an Internal app (no CASA) yet serve accounts from several
domains (`@org-a.com`, `@org-b.com`, …) from a single instance. There's no limit
— add one connection per org, each with that org's client.

**Why it's needed:** an Internal Google app only admits accounts from the one
Workspace domain that owns its GCP project, so a single global client is locked
to a single org. To add an account from another org, that connection must
authorize against *that org's* Internal client — in that org's project, with the
APIs enabled there. (This is exactly the failure behind "it worked for Gmail but
not Drive on the other domain": different projects, different enabled APIs.)

**How to use it:** when adding a Google connection in the admin UI, expand
**"Use a specific Google OAuth client for this connection"** and paste that org's
`client_id` + `client_secret` (from its `credentials.json`). Leave it blank to
use the server's global client (flags / env / BYO file). The chosen client is:

- used for the authorize + token exchange,
- stored (encrypted) with the connection and reused for token refresh, and
- reused automatically on **reauth** by default — a connection re-authorizes
  against the same org's client, never silently repointed at the global one. The
  **Re-authenticate** page has an optional "use a different OAuth client" field to
  move a connection to *another client for the same account* — e.g. a new GCP
  project **in the same Workspace org** (blank keeps the current client). Note
  this can't cross orgs: re-auth requires signing in as the same account, and a
  different org's Internal client won't admit that account (`org_internal`). To
  move an account to a different org, delete and re-add the connection.

**Setup, per org:** each Workspace admin creates a GCP project in their org,
enables the APIs (Gmail/Drive/Docs/Sheets), and makes an **Internal** OAuth
client (Desktop app); each connection is then given its org's client. See
[google-oauth-setup.md](google-oauth-setup.md).

### Personal Gmail (and other non-Workspace accounts)

A personal `@gmail.com` account has no Workspace org, so **no Internal client can
ever admit it** — an Internal app is domain-locked, so a personal account hits
`Error 403: org_internal` at the consent screen. This is *independent of PKCE*:
PKCE only governs how the code is exchanged, never which accounts a client
accepts. What decides it is the consent screen's **Internal vs External** setting.
(A personal account that "used to work" was almost certainly going through an
**External** client — a Cloud project owned by a personal Google account can only
be External — which accepts any account after an unverified-app warning.)

To connect a personal account, give *that connection* an **External** client:

1. In an OAuth client whose consent screen is **External**, add the account as a
   **test user** and enable the APIs you need.
2. Add the Google connection with **"Use a specific Google OAuth client for this
   connection"** set to that External client's `client_id` + `client_secret`.

The account then authorizes normally. The trade-offs are inherent to External +
testing (not to Sieve): a one-time "Google hasn't verified this app" warning, and
— for restricted Gmail/Drive scopes — refresh tokens that expire after ~7 days,
so the connection needs periodic re-auth. Publishing the External app removes
both, at the cost of verification + CASA.

You can mix freely in one instance: **Internal** clients for org accounts, an
**External** client for a personal account — each connection carries its own.

## What PKCE does *not* solve

PKCE removes the *secret* from the flow. It does **not** remove a provider's app
**review/verification** requirements. For Google, Gmail's `gmail.modify` and
Drive are *restricted scopes*: a publicly distributed app requesting them must
still pass Google OAuth verification and an annual CASA security assessment,
regardless of PKCE. Keep the requested scope set minimal to reduce that review.
