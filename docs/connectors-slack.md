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
| `search_messages` | Search workspace messages. **Requires a user-token install** (see Option 3) — bot-token connections return `operation_not_enabled`. | `search:read` (user scope) |
| `post_message` | Post a message to a channel. | `chat:write` |

All `list_*` operations follow Sieve's normalized `{items, next_cursor}` pagination shape. Agents pass `cursor` and `page_size` (default 100, max 100) into the next call to walk past the first page.

## Two ways to install

### Option 1 — OAuth install (recommended)

Best when you want Sieve to manage the Slack app's bot token end to end. **No env vars or restart required** — paste your Slack app's credentials directly into the Sieve UI.

1. Create a Slack app at <https://api.slack.com/apps> → **Create New App** → **From scratch**.
2. Under **OAuth & Permissions**, add the bot scopes for the operations you want to expose. The minimum set covering the curated operations is:

   ```
   channels:read groups:read users:read users.profile:read
   channels:history groups:history chat:write
   ```

   Add `channels:join` if you want the bot to join channels it's invited to.
3. Add the redirect URL `http://<your-sieve-host>:19816/oauth/callback`. This is the Sieve admin port — never expose this to agents.
4. From your Slack app's **Basic Information** page, copy the **Client ID** and **Client Secret**.
5. Open Sieve's connections page, find the **Slack** card. The card shows a **Set up Slack OAuth** form when no credentials are configured.
6. Paste the Client ID and Client Secret, click **Save Slack OAuth credentials**. Sieve persists them and the page reloads.
7. The card now shows the **Install via OAuth** button. Enter a Connection Alias and Display Name, click the button. Slack opens in a new tab — approve the install.
8. The redirect lands you back on Sieve with the connection in `status: active`.

**Where credentials are stored.** When you paste creds in the UI, Sieve stores them as an envelope-encrypted reserved row in the `connections` table (`connector_type = '_oauth_app:slack'`, id `oauth_app__slack`). Same encryption path as connection configs: per-record DEK, KEK-wrapped, picked up automatically by passphrase rotation. The encrypted row is hidden from the per-tenant connections list and is not addressable by agent traffic. **Reading the credentials requires the keyring** — if Sieve is started with the keyring locked, the OAuth install flow returns HTTP 503 "service locked" until an operator supplies the passphrase. Direct bot-token entry remains available without the keyring (it goes through the standard connection config path, which is also encrypted but operates per-connection).

**Alternative: pre-set via environment variables.** If you'd rather configure via deployment automation, set `SLACK_CLIENT_ID` and `SLACK_CLIENT_SECRET` in Sieve's environment before startup. Stored credentials in the encrypted row take precedence, so a value pasted in the UI overrides any env var. The env-var path is for 12-factor escape hatches and is not encrypted; if you're using deployment-managed secrets (Vault, Kubernetes Secret, etc.), the env-var path is the right home for those.

**Resetting credentials.** Below the install button, a small "Reset Slack OAuth credentials" link wipes the persisted encrypted row. Use this when rotating the Slack app or moving to a different OAuth app.

### Option 2 — Direct bot-token entry

Best when your Slack app is already installed in your workspace and you have the bot token already (e.g., from another tool).

1. From your Slack app's **OAuth & Permissions** page, copy the bot token (`xoxb-…`).
2. In Sieve, **Add Connection** → **Slack** → **Use existing bot token**. Paste and submit.
3. Sieve calls `auth.test` against Slack; on success the connection lands `status: active`.

The pasted token is encrypted at rest — it is never written to a plaintext column or logged.

### Option 3 — User-token install ("Connect as me")

Best when you want Sieve to act with **your own Slack access** rather than a bot identity — for example to use message search (`search_messages`, which Slack only allows with a user token) or to reach every channel and DM you can personally see, and to post as yourself.

> ⚠️ **Security implication.** A user-token connection can reach and act on **everything the authorizing person can** in Slack: private channels and DMs they're in, workspace search, and posting as them. This is a deliberately broader blast radius than a bot install. Bind restrictive Sieve policies to the connection, and prefer bot-token mode unless you specifically need user-level reach. Every operation is still gated by the policy pipeline and recorded in the audit log, attributed to the acting Slack identity.

1. Configure the Slack OAuth app credentials as in Option 1 (the "Set up Slack OAuth" form).
2. On your Slack app's **OAuth & Permissions** page, add the **User Token Scopes**:

   ```
   search:read channels:read groups:read im:read mpim:read
   channels:history groups:history im:history mpim:history
   users:read users.profile:read chat:write
   ```

3. (Optional) Enable **Token Rotation** (Slack app → *Install App* / *OAuth & Permissions*). With rotation on, Slack issues a short-lived user token plus a refresh token; Sieve renews it transparently in the background and only prompts for re-authorization if renewal fails. With rotation off, the user token is long-lived and never refreshed.
4. On the Sieve **Slack** card, use the **Connect as me (user token)** form: enter a Connection Alias and Display Name, click the button, and approve the authorization screen in Slack (it lists the access being granted on your behalf).
5. The connection lands `status: active`, labeled **User token** with your Slack identity as the acting user.

The user token (and its refresh token, if any) is stored through the same envelope-encryption path as every other credential — never a plaintext column. `search_messages` is now executable for this connection (subject to policy); bot-token connections continue to reject it.

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

- **`search_messages` requires a user-token install.** Slack's `search.messages` API rejects bot tokens. For **bot-token** connections (Options 1 and 2) the operation stays in the catalog (so policies binding `search_messages` keep working) but returns the typed `connector.ErrOperationNotEnabled` sentinel — **HTTP 501 Not Implemented** with body `{"error":"operation_not_enabled","connection_id":...,"operation":"search_messages","message":...}` on REST, or a tool error with the `operation_not_enabled:` text prefix on MCP. Install with Option 3 (**Connect as me**) to enable search.
- **No Slack Enterprise Grid org-level installs.** Per-workspace installs only. If you operate across multiple workspaces, add a Sieve connection per workspace.
- **No inbound webhooks.** Slack Events API (real-time message ingestion) is out of scope — Sieve is outbound-only. Agents that need event-driven workflows poll the `read_channel_history` operation.
- **Bot tokens don't rotate.** Classic bot tokens (Options 1 and 2) are non-rotating. User-token installs (Option 3) support Slack Token Rotation: Sieve renews the user token transparently and falls back to `reauth_required` only if renewal fails.
- **One acting identity per user-token connection.** A user-token connection acts as exactly one Slack user (the operator who authorized it). "Act as different users per request" is out of scope.

## Troubleshooting

**Q: I see the OAuth button is missing in the connector picker.**
A: Neither the encrypted `_oauth_app:slack` row nor the env-var fallback resolves to a complete `client_id`/`client_secret` pair. Either paste creds via **Add Connection → Slack → Set up Slack OAuth** (the recommended path), or set `SLACK_CLIENT_ID` and `SLACK_CLIENT_SECRET` in Sieve's environment and restart. If you stored creds via the UI but the button still won't appear, check that the keyring is loaded — the OAuth handlers can't read encrypted credentials with the keyring locked.

**Q: My connection went to `reauth_required` after I rotated the bot token in Slack.**
A: Expected — the old token is now revoked. Click **Re-install** on the row (OAuth) or paste the new token via the reauth form.

**Q: `auth.test` rejects my pasted token with `invalid_auth`.**
A: The direct-paste path (Option 2) expects a bot token (`xoxb-…`). Sieve refuses `xoxp-` (user) tokens there — to install with a user token, use the **Connect as me** OAuth flow (Option 3) instead, which validates the `xoxp-`/`xoxe.xoxp-` prefix. If you re-issued the token, copy the latest value from **OAuth & Permissions**.

**Q: `search_messages` returns `operation_not_enabled`.**
A: That connection is a bot-token install; Slack only allows search with a user token. Re-install the connection with **Connect as me** (Option 3), or add a separate user-token connection.

**Q: `post_message` returns "channel not found" but the channel exists.**
A: The bot must be a member of private channels before it can post. Invite the bot user (the `bot_user_id` from `auth.test`) to the channel manually, or grant `channels:join` and call a separate join op (not yet curated).

## How the connector handles credentials

Per Sieve's [credential encryption design](./credential-encryption.md), the bot token, OAuth-issued bot bearer, or user token (and its refresh token, for rotating user installs) lives only inside the encrypted `config_ciphertext` blob on the `connections` row. The keyring KEK is derived from the operator's passphrase at startup; if the keyring is unloaded, every connector path returns HTTP 503 "service locked" rather than touching plaintext credentials.

For a user-token install with Slack Token Rotation enabled, the connector renews the user token in the background via `oauth.v2.access?grant_type=refresh_token` and persists the rotated pair through the same `_on_token_refresh` callback Gmail/Linear/Jira use; an unrecoverable renewal failure transitions the connection to `reauth_required` and surfaces the standard agent re-auth contract.

The Slack connector does **not** participate in refresh-token rotation because classic bot tokens don't expire or rotate. Linear, Jira, and Asana — when they ship — will use that path.
