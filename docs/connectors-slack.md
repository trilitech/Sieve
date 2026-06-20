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
| `search_messages` | Search workspace messages. **User-token connections only** (Slack's `search.messages` rejects bot tokens). | `search:read` |
| `post_message` | Post a message to a channel. | `chat:write` |

All `list_*` operations (and `search_messages`) follow Sieve's normalized `{items, next_cursor}` pagination shape. Agents pass `cursor` and `page_size` (default 100, max 100) into the next call to walk past the first page.

## Two identities: bot or user

A Slack connection authenticates as **one of two identities**, recorded in its `auth_kind`:

| Identity | `auth_kind` | Token | Sees | Acts as |
|---|---|---|---|---|
| **Bot** | `oauth` / `token` | `xoxb-…` | Only channels the app's bot user is invited to. No `search.messages`. | The Slack app's bot user. |
| **User** | `user_token` | `xoxp-…` | Everything the installing human can see — every channel, private channel, DM, and the search index. | The installing human. |

Both identities expose the **same curated operations**; the difference is reach and attribution. The bot path is the safer default (least privilege, posts under a clearly-non-human identity). The **user path** is for when an agent genuinely needs a human's full reach — e.g. searching across all of a person's conversations, or reading private channels the bot can't be added to. Because a user token carries the human's *full* permissions, scope it tightly with a Sieve role + policy.

You can run both at once: add one bot connection and one user connection (different aliases) on the same workspace and bind each to whatever role fits.

## Ways to install

Options 1 and 2 install a **bot** identity. Options 3 and 4 install a **user** identity (see "Two identities" above). Pick the identity first, then OAuth vs paste-token.

### Option 1 — OAuth install, bot (recommended)

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

### Option 3 — OAuth install, user ("act as me")

Installs a `user_token` connection that acts as **you** with your full permissions.

1. In your Slack app's **OAuth & Permissions** page, add the scopes you need under **User Token Scopes** (note: *User* Token Scopes, not Bot Token Scopes). The set Sieve requests for a full-permission install is:

   ```
   channels:read channels:history groups:read groups:history
   im:read im:history mpim:read mpim:history
   users:read users:read.email users.profile:read search:read chat:write
   ```

   `search:read` is the scope that unlocks `search_messages` — impossible with a bot token.
2. Make sure the same redirect URL as Option 1 is registered (`http://<your-sieve-host>:19816/oauth/callback`) and the Client ID / Secret are configured (Option 1, steps 5–6).
3. On the **Slack** card, use the **Install via OAuth (as user)** button. Approve the install in Slack — you're approving access *as yourself*.
4. Slack returns a user token (`xoxp-…`) under `authed_user.access_token`; Sieve persists it as an `auth_kind=user_token` connection in `status: active`.

### Option 4 — Direct user-token entry

Best when you already have a user token (the **User OAuth Token**, `xoxp-…`, from your Slack app's **OAuth & Permissions** page).

1. Copy the **User OAuth Token** (`xoxp-…`).
2. On the **Slack** card, use the **Add via user token** form. Paste and submit.
3. Sieve calls `auth.test`; on success the connection lands `status: active` as `auth_kind=user_token`.

The pasted token is encrypted at rest exactly like the bot token — never a plaintext column, never logged.

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

- **`search_messages` requires a user-token connection.** Slack's `search.messages` API only accepts a *user* token (`xoxp-…`), never a bot token. On a **user** connection (`auth_kind=user_token`, Options 3–4) the operation works normally and returns the standard `{items, next_cursor}` shape. On a **bot** connection it is exposed for policy-binding stability but returns the typed `connector.ErrOperationNotEnabled` sentinel — agents see **HTTP 501 Not Implemented** with body `{"error":"operation_not_enabled","connection_id":...,"operation":"search_messages","message":...}` on REST, or a tool error with the `operation_not_enabled:` text prefix on MCP.
- **No Slack Enterprise Grid org-level installs.** Per-workspace installs only. If you operate across multiple workspaces, add a Sieve connection per workspace.
- **No inbound webhooks.** Slack Events API (real-time message ingestion) is out of scope for v1 — Sieve is outbound-only. Agents that need event-driven workflows poll the `read_channel_history` operation.
- **No granular-scope token rotation.** v1 uses classic non-rotating bot tokens. Granular scopes with refresh-token rotation are a future feature.

## Troubleshooting

**Q: I see the OAuth button is missing in the connector picker.**
A: Neither the encrypted `_oauth_app:slack` row nor the env-var fallback resolves to a complete `client_id`/`client_secret` pair. Either paste creds via **Add Connection → Slack → Set up Slack OAuth** (the recommended path), or set `SLACK_CLIENT_ID` and `SLACK_CLIENT_SECRET` in Sieve's environment and restart. If you stored creds via the UI but the button still won't appear, check that the keyring is loaded — the OAuth handlers can't read encrypted credentials with the keyring locked.

**Q: My connection went to `reauth_required` after I rotated the bot token in Slack.**
A: Expected — the old token is now revoked. Click **Re-install** on the row (OAuth) or paste the new token via the reauth form.

**Q: `auth.test` rejects my pasted token with `invalid_auth`.**
A: Confirm you pasted the token into the matching form. The **bot-token** form requires an `xoxb-…` token; the **user-token** form requires an `xoxp-…` token. Sieve refuses the wrong prefix for each form (and `xoxa-` legacy app tokens entirely). If you re-issued the token, copy the latest value from **OAuth & Permissions**.

**Q: Should I use a bot or a user connection?**
A: Default to **bot** — least privilege, and it posts under a clearly-non-human identity. Use a **user** connection only when the agent genuinely needs a human's full reach (searching across all conversations, reading private channels the bot can't join). A user token carries the human's full permissions, so always pair it with a tight Sieve role + policy.

**Q: `post_message` returns "channel not found" but the channel exists.**
A: The bot must be a member of private channels before it can post. Invite the bot user (the `bot_user_id` from `auth.test`) to the channel manually, or grant `channels:join` and call a separate join op (not yet curated).

## How the connector handles credentials

Per Sieve's [credential encryption design](./credential-encryption.md), the bot token (or OAuth-issued bearer) lives only inside the encrypted `config_ciphertext` blob on the `connections` row. The keyring KEK is derived from the operator's passphrase at startup; if the keyring is unloaded, every connector path returns HTTP 503 "service locked" rather than touching plaintext credentials.

The Slack connector does **not** participate in refresh-token rotation because classic bot tokens don't expire or rotate. Linear, Jira, and Asana — when they ship — will use that path.
