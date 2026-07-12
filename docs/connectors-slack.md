# Slack connector

Sieve's Slack connector lets agents read channels, search history, post messages, and manage threads through your Slack workspace — all gated by Sieve policies. The real Slack credential never leaves Sieve; agents only ever see scoped sub-tokens issued from a role bound to the connection.

This page covers the operator setup.

## What you get

| Operation | Effect | Required scope |
|---|---|---|
| `list_channels` | List workspace channels (public, private, MPIM, IM). | `channels:read`, `groups:read` |
| `list_users` | List members of the workspace. | `users:read` |
| `read_user_profile` | Look up a user's profile (name, email, avatar). | `users:read`, `users.profile:read` |
| `read_channel_history` | Read recent messages from a channel. | `channels:history`, `groups:history` |
| `read_thread` | Read replies under a parent message. | `channels:history`, `groups:history` |
| `search_messages` | Search workspace messages. **User-token connections only** — bot connections return `operation_not_enabled` (see Two identities). | `search:read` (user scope) |
| `post_message` | Post a message to a channel. | `chat:write` |

All `list_*` operations (and `search_messages`) follow Sieve's normalized `{items, next_cursor}` pagination shape. Agents pass `cursor` and `page_size` (default 100, max 100) into the next call to walk past the first page.

## Two identities: bot or user

A Slack connection authenticates as one of two identities, chosen at install time via `auth_kind`:

| Identity | `auth_kind` | Token | Reach | Acts as |
|---|---|---|---|---|
| **Bot** (default) | `oauth` / `token` | `xoxb-…` | channels the bot is invited to; **no** search | the app's bot user |
| **User** | `user_token` | `xoxp-…` (or `xoxe.…`) | every channel/DM the installing person can see **+ `search_messages`** | the installing human |

Both identities expose the same curated operation set; they differ in reach and attribution. The bot identity is the least-privilege default — pick a user identity only when an agent workflow genuinely needs a person's full reach or workspace search.

`search_messages` is grantable in the IAM rule builder against **any** Slack connection (so a role's grant survives a re-auth or an identity change), but at runtime it only executes on a user-token connection; a bot-token connection returns `operation_not_enabled` (HTTP 501 on REST, `operation_not_enabled:` tool error on MCP).

## Ways to install

Four paths: bot OAuth, bot token, user OAuth, user token. Options 1–2 create a **bot** identity; Options 3–4 create a **user** identity.

### Option 1 — OAuth install (recommended)

Best when you want Sieve to manage the Slack app's bot token end to end. **No env vars or restart required** — paste your Slack app's credentials directly into the Sieve UI.

1. Create a Slack app at <https://api.slack.com/apps> → **Create New App** → **From scratch**.
2. Under **OAuth & Permissions**, add the bot scopes for the operations you want to expose. The minimum set covering the curated operations is:

   ```
   channels:read groups:read users:read users.profile:read
   channels:history groups:history chat:write
   ```

   Add `channels:join` if you want the bot to join channels it's invited to.
3. Add the redirect URL `http://<your-sieve-host>:19816/oauth/callback`. This is the Sieve admin port — never expose this to agents. **Slack requires an `https` redirect** (or a custom URI scheme); plain `http://localhost` is rejected — see [Redirect requirement](#redirect-requirement) below.
4. From your Slack app's **Basic Information** page, copy the **Client ID** and **Client Secret**.
5. Open Sieve's connections page, find the **Slack** card. The card shows a **Set up Slack OAuth** form when no credentials are configured.
6. Paste the Client ID and Client Secret, click **Save Slack OAuth credentials**. Sieve persists them and the page reloads.
7. The card now shows the **Install via OAuth** button. Enter a Connection Alias and Display Name, click the button. Slack opens in a new tab — approve the install.
8. The redirect lands you back on Sieve with the connection in `status: active`.

**Where credentials are stored.** When you paste creds in the UI, Sieve stores them as an envelope-encrypted reserved row in the `connections` table (`connector_type = '_oauth_app:slack'`, id `oauth_app__slack`). Same encryption path as connection configs: per-record DEK, KEK-wrapped, picked up automatically by passphrase rotation. The encrypted row is hidden from the per-tenant connections list and is not addressable by agent traffic. **Reading the credentials requires the keyring** — if Sieve is started with the keyring locked, the OAuth install flow returns HTTP 503 "service locked" until an operator supplies the passphrase. Direct bot-token entry remains available without the keyring (it goes through the standard connection config path, which is also encrypted but operates per-connection).

**Alternative: pre-set via environment variables.** If you'd rather configure via deployment automation, set `SLACK_CLIENT_ID` and `SLACK_CLIENT_SECRET` in Sieve's environment before startup. Stored credentials in the encrypted row take precedence, so a value pasted in the UI overrides any env var. The env-var path is for 12-factor escape hatches and is not encrypted; if you're using deployment-managed secrets (Vault, Kubernetes Secret, etc.), the env-var path is the right home for those.

**Public-client (PKCE) install — no secret.** A `client_secret` is optional. When only a `client_id` is configured — via the `--slack-client-id` launch flag, the `SLACK_CLIENT_ID` env var, or a client ID shipped with your build — Sieve installs via [PKCE](oauth-pkce.md) as a public client, and no secret is stored or sent. When a secret *is* configured (the `--slack-client-secret` flag, `SLACK_CLIENT_SECRET`, or the paste-creds form, which requires both), Sieve uses the confidential (BYO-app) flow instead. Slack forbids sending both, so it's strictly one or the other; either way IAM grants bind to the connection id unchanged. See [CLI reference → OAuth app client flags](cli-reference.md#oauth-app-client-flags).

### Org-only vs public distribution

For your **own workspace** (the common case), just create the app and install it
in your workspace — **do not submit it to the Slack Marketplace.** Marketplace
review is only for *public* distribution to other workspaces; a single-workspace
app needs no directory listing and no review, so there's nothing to wait on. Ship
its client id to your team's Sieve installs via `--slack-client-id`. This mirrors
Google's "Internal" app model — see
[Distribution: internal vs external](oauth-pkce.md#distribution-internal-org-only-vs-external-public).
Submit to the Marketplace only when you need other organizations to install it.

### Redirect requirement

Slack rejects a plain `http://localhost` / `http://127.0.0.1` redirect — it requires an `https` redirect URL registered on the app. **`https://localhost` loopback works fine, though — no public tunnel is needed.** Serve the admin UI over TLS and register `https://localhost:19816/oauth/callback` on your Slack app:

1. Generate a localhost cert/key (e.g. `mkcert localhost`, or a self-signed pair).
2. In the admin UI **Settings** (`/settings`), set `public_base_url` to `https://localhost:19816` and `admin.tls_cert_path` / `admin.tls_key_path` to your cert/key; restart Sieve.
3. Register `https://localhost:19816/oauth/callback` under your Slack app's **OAuth & Permissions → Redirect URLs**.

This is a Slack platform constraint, independent of the PKCE vs confidential flow. (Google, by contrast, permits `http://127.0.0.1` loopback, so Gmail installs need no TLS locally.) See [Verifying the flow locally](oauth-pkce.md#verifying-the-flow-locally) for the full round-trip.

**Resetting credentials.** Below the install button, a small "Reset Slack OAuth credentials" link wipes the persisted encrypted row. Use this when rotating the Slack app or moving to a different OAuth app.

### Option 2 — Direct bot-token entry

Best when your Slack app is already installed in your workspace and you have the bot token already (e.g., from another tool).

1. From your Slack app's **OAuth & Permissions** page, copy the bot token (`xoxb-…`).
2. In Sieve, **Add Connection** → **Slack** → **Use existing bot token**. Paste and submit.
3. Sieve calls `auth.test` against Slack; on success the connection lands `status: active`.

The pasted token is encrypted at rest — it is never written to a plaintext column or logged.

### Option 3 — User OAuth install

Best when an agent needs your full personal reach or workspace search, and you want Sieve to manage the user token end to end. Requires the same one-time Slack-app OAuth setup as Option 1.

1. Under your Slack app's **OAuth & Permissions → User Token Scopes**, add the user scopes you want, including `search:read` for `search_messages`. A reasonable set:

   ```
   channels:read channels:history groups:read groups:history
   im:read im:history mpim:read mpim:history
   users:read users:read.email users.profile:read search:read chat:write
   ```

2. On the Slack card, click **Install via OAuth (as user)**, enter a Connection Alias and Display Name, and approve the install **as yourself**. The connection lands `status: active` with `auth_kind = user_token`. The connection now acts as you, with your full reach.

### Option 4 — Direct user-token entry

Best when you already have a user token (`xoxp-…`) from your Slack app's **OAuth & Permissions → User OAuth Token**.

1. Copy the `xoxp-…` (or Enterprise Grid `xoxe.…`) token.
2. On the Slack card, use **Add via user token**. Paste and submit.
3. Sieve calls `auth.test`, then persists the connection as `auth_kind = user_token`. Sieve refuses a `xoxb-` bot token on this path, so a user connection can't be silently downgraded to a bot identity.

The pasted user token is encrypted at rest — never written to a plaintext column or logged.

## Multi-workspace setups

Add a second Slack connection with a different alias (e.g., `acme-slack` and `engineering-slack`). Agents address each workspace by alias when there are multiple Slack connections on a token; Sieve adds a `slack_` prefix to the MCP tool names automatically (e.g., `acme-slack_post_message`).

## Connection status lifecycle

| Status | Meaning | How it's set |
|---|---|---|
| `active` | Connection is healthy. | After successful OAuth or token validation. |
| `reauth_required` | Slack returned a terminal-auth error (`invalid_auth`, `token_revoked`, etc.). | Set automatically by the connector on the first failed call. |
| `disabled` | Operator hard-stopped the connection. | Click **Disable** in the admin UI; clears only via **Enable** (does NOT clear via OAuth re-install). |

When status is `reauth_required`, agent calls fail fast with HTTP 403 `{"error": "reauth_required", ...}` (REST) or `IsError` with text `reauth_required: …` (MCP) — Sieve does not attempt the upstream call. To recover, click **Re-install** on the row and complete a fresh OAuth flow, or paste a fresh bot token.

## Verifying the install

```bash
# Replace <conn-id> with your Slack connection's alias.
curl -s -X POST http://localhost:19817/api/v1/connections/<conn-id>/ops/list_channels \
  -H "Authorization: Bearer sieve_tok_…" \
  -H "Content-Type: application/json" \
  -d '{"page_size": 5}'
```

Expected: `200` with a `{ items: [...], next_cursor: "..." }` body. Posting:

```bash
curl -s -X POST http://localhost:19817/api/v1/connections/<conn-id>/ops/post_message \
  -H "Authorization: Bearer sieve_tok_…" \
  -H "Content-Type: application/json" \
  -d '{"channel": "#bot-test", "text": "hello from sieve"}'
```

If the policy on the role allows posting only to `#bot-test`, posting to `#general` returns `{"error": "policy_denied", ...}`.

## Limitations

- **`search_messages` needs a user connection.** Slack's `search.messages` API requires a *user* token (`xoxp-…`), not a bot token. On a user-identity connection the operation runs for real; on a bot-identity connection it returns the typed `connector.ErrOperationNotEnabled` sentinel — **HTTP 501 Not Implemented** with body `{"error":"operation_not_enabled","connection_id":...,"operation":"search_messages","message":...}` on REST, or a tool error with the `operation_not_enabled:` text prefix on MCP. The op is still grantable against either kind so a role's grant is stable across re-auth.
- **No Slack Enterprise Grid org-level installs.** Per-workspace bot/user installs are supported. If you operate across multiple workspaces, add a Sieve connection per workspace.
- **No inbound webhooks.** Slack Events API (real-time message ingestion) is out of scope for v1 — Sieve is outbound-only. Agents that need event-driven workflows poll the `read_channel_history` operation.
- **No granular-scope token rotation.** v1 uses classic non-rotating bot tokens. Granular scopes with refresh-token rotation are a future feature.

## Troubleshooting

**Q: I see the OAuth button is missing in the connector picker.**
A: Neither the encrypted `_oauth_app:slack` row nor the env-var fallback resolves to a complete `client_id`/`client_secret` pair. Either paste creds via **Add Connection → Slack → Set up Slack OAuth** (the recommended path), or set `SLACK_CLIENT_ID` and `SLACK_CLIENT_SECRET` in Sieve's environment and restart. If you stored creds via the UI but the button still won't appear, check that the keyring is loaded — the OAuth handlers can't read encrypted credentials with the keyring locked.

**Q: My connection went to `reauth_required` after I rotated the bot token in Slack.**
A: Expected — the old token is now revoked. Click **Re-install** on the row (OAuth) or paste the new token via the reauth form.

**Q: `auth.test` rejects my pasted token with `invalid_auth`.**
A: Confirm you pasted the token into the matching form. The **bot** token form accepts only `xoxb-…`; the **user** token form accepts only `xoxp-…` / `xoxe.…`. Sieve rejects a mismatched prefix before calling Slack so an identity can't be set by the wrong token. If you re-issued the token, copy the latest value from **OAuth & Permissions**.

**Q: Should I use a bot or a user connection?**
A: Prefer **bot** (the default, least privilege) unless an agent workflow needs a person's full reach — every channel/DM they can see — or workspace search (`search_messages`), which Slack only allows with a user token. A user connection acts as, and is attributed to, the installing human.

**Q: `post_message` returns "channel not found" but the channel exists.**
A: The bot must be a member of private channels before it can post. Invite the bot user (the `bot_user_id` from `auth.test`) to the channel manually, or grant `channels:join` and call a separate join op (not yet curated).

## How the connector handles credentials

Per Sieve's [credential encryption design](./credential-encryption.md), the bot token (or OAuth-issued bearer) lives only inside the encrypted `config_ciphertext` blob on the `connections` row. The keyring KEK is derived from the operator's passphrase at startup; if the keyring is unloaded, every connector path returns HTTP 503 "service locked" rather than touching plaintext credentials.

The Slack connector does **not** participate in refresh-token rotation because classic Slack tokens — bot (`xoxb-`) and user (`xoxp-`) alike — don't expire or rotate. Linear, Jira, and Asana — when they ship — will use that path.
