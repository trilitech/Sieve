# Slack connector

Sieve's Slack connector lets agents read channels, search history, post messages, and manage threads through your Slack workspace — all gated by Sieve policies. The real Slack credential never leaves Sieve; agents only ever see scoped sub-tokens issued from a role bound to the connection.

This page covers the operator setup. For the contract that agents see (operation names, params, responses), see [`specs/001-slack-linear-jira-connectors/contracts/slack.md`](../specs/001-slack-linear-jira-connectors/contracts/slack.md).

## What you get

| Operation | Effect | Required scope |
|---|---|---|
| `list_channels` | List workspace channels (public, private, MPIM, IM). | `channels:read`, `groups:read` |
| `list_users` | List members of the workspace. | `users:read` |
| `read_user_profile` | Look up a user's profile (name, email, avatar). | `users:read`, `users.profile:read` |
| `read_channel_history` | Read recent messages from a channel. | `channels:history`, `groups:history` |
| `read_thread` | Read replies under a parent message. | `channels:history`, `groups:history` |
| `search_messages` | Search workspace messages. **Not enabled in v1** — requires user-token install (see Limitations). | `search:read` |
| `post_message` | Post a message to a channel. | `chat:write` |

All `list_*` operations follow Sieve's normalized `{items, next_cursor}` pagination shape (FR-014). Agents pass `cursor` and `page_size` (default 100, max 100) into the next call to walk past the first page.

## Two ways to install

### Option 1 — OAuth install (recommended)

Best when you want Sieve to manage the Slack app's bot token end to end.

**Prereqs.** Set Slack OAuth client credentials before starting Sieve:

```bash
export SLACK_CLIENT_ID="…"
export SLACK_CLIENT_SECRET="…"
```

These come from your Slack app's **Basic Information** page (<https://api.slack.com/apps>). They are the OAuth app credentials, **not** the bot token.

**Setup steps.**

1. Create a Slack app at <https://api.slack.com/apps> → **Create New App** → **From scratch**.
2. Under **OAuth & Permissions**, add the bot scopes for the operations you want to expose. The minimum set covering the curated operations is:

   ```
   channels:read groups:read users:read users.profile:read
   channels:history groups:history chat:write
   ```

   Add `channels:join` if you want the bot to join channels it's invited to.
3. Add the redirect URL `http://<your-sieve-host>:19816/oauth/callback`. This is the Sieve admin port — never expose this to agents.
4. Install the app to your workspace once via the **Install App** page (or skip and let Sieve drive the install via OAuth — see step 6).
5. From **Basic Information**, copy the Client ID and Client Secret into your environment.
6. In Sieve's admin UI, click **Add Connection** → **Slack** → **Install via OAuth**. Approve in Slack.
7. The redirect lands you back on Sieve with the connection in `status: active`.

### Option 2 — Direct bot-token entry

Best when your Slack app is already installed in your workspace and you have the bot token already (e.g., from another tool).

1. From your Slack app's **OAuth & Permissions** page, copy the bot token (`xoxb-…`).
2. In Sieve, **Add Connection** → **Slack** → **Use existing bot token**. Paste and submit.
3. Sieve calls `auth.test` against Slack; on success the connection lands `status: active`.

The pasted token is encrypted at rest (FR-003) — it is never written to a plaintext column or logged.

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

## Limitations (v1)

- **`search_messages` is disabled.** Slack's `search.messages` API requires a *user* token (`xoxp-…`), not a bot token. Sieve v1 supports bot tokens only (per the 2026-05-01 clarification: classic non-rotating scopes only). The operation is exposed for policy bindings but always returns `{"error": "operation_not_enabled", ...}`. User-token install support is on the roadmap.
- **No Slack Enterprise Grid org-level installs.** v1 supports per-workspace bot installs. If you operate across multiple workspaces, add a Sieve connection per workspace.
- **No inbound webhooks.** Slack Events API (real-time message ingestion) is out of scope for v1 — Sieve is outbound-only. Agents that need event-driven workflows poll the `read_channel_history` operation.
- **No granular-scope token rotation.** v1 uses classic non-rotating bot tokens. Granular scopes with refresh-token rotation are a future feature.

## Troubleshooting

**Q: I see the OAuth button is missing in the connector picker.**
A: `SLACK_CLIENT_ID` and/or `SLACK_CLIENT_SECRET` aren't set in Sieve's environment. Either set them and restart, or use the **Use existing bot token** path instead.

**Q: My connection went to `reauth_required` after I rotated the bot token in Slack.**
A: Expected — the old token is now revoked. Click **Re-install** on the row (OAuth) or paste the new token via the reauth form.

**Q: `auth.test` rejects my pasted token with `invalid_auth`.**
A: Confirm the token starts with `xoxb-` (bot token) — Sieve refuses `xoxp-` (user) and `xoxa-` (legacy app) tokens because the curated operations are scoped against bot capabilities. If you re-issued the token, copy the latest value from **OAuth & Permissions**.

**Q: `post_message` returns "channel not found" but the channel exists.**
A: The bot must be a member of private channels before it can post. Invite the bot user (the `bot_user_id` from `auth.test`) to the channel manually, or grant `channels:join` and call a separate join op (not yet curated).

## How the connector handles credentials

Per Sieve's [credential encryption design](./credential-encryption.md), the bot token (or OAuth-issued bearer) lives only inside the encrypted `config_ciphertext` blob on the `connections` row. The keyring KEK is derived from the operator's passphrase at startup; if the keyring is unloaded, every connector path returns HTTP 503 "service locked" rather than touching plaintext credentials.

The Slack connector does **not** participate in the refresh-token rotation hardening (FR-016) because classic bot tokens don't expire or rotate. Linear, Jira, and Asana — when they ship — will use that path.
