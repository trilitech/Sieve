# Slack Connector Contract

This document specifies the operations the Slack connector exposes to agents through the `connector.Connector` interface. The connector is registered with `Type() == "slack"`. When a token's role grants this connection, MCP tools are exposed with the prefix `slack_` (or unprefixed when the token has only one connection, per the existing rule in `internal/mcp/server.go`).

`Validate(ctx)` calls Slack `auth.test`. Returns `nil` on `ok: true`, otherwise a structured error.

## Operations

### `slack.list_channels`

List channels accessible to the bot.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `types` | string | no | Comma-separated channel types: `public_channel`, `private_channel`, `mpim`, `im`. Default: `public_channel,private_channel`. |
| `limit` | int | no | Max channels to return (1–1000). Default: 200. |
| `cursor` | string | no | Pagination cursor returned by a previous call. |

**Result**:

```json
{
  "channels": [
    {"id": "C012ABC", "name": "general", "is_private": false, "is_archived": false, "topic": "...", "purpose": "..."}
  ],
  "next_cursor": ""
}
```

**ReadOnly**: true.

---

### `slack.list_users`

List members of the workspace.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `limit` | int | no | Max users to return (1–1000). Default: 200. |
| `cursor` | string | no | Pagination cursor. |

**Result**:

```json
{
  "users": [
    {"id": "U012ABC", "name": "alice", "real_name": "Alice", "is_bot": false, "deleted": false}
  ],
  "next_cursor": ""
}
```

**ReadOnly**: true.

---

### `slack.read_user_profile`

Get profile info for a user.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `user` | string | yes | Slack user ID (e.g., `U012ABC`). |

**Result**: Slack user-profile object (`real_name`, `display_name`, `email`, `image_192`, etc.).

**ReadOnly**: true.

---

### `slack.read_channel_history`

Read messages from a channel.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `channel` | string | yes | Channel ID (e.g., `C012ABC`). |
| `limit` | int | no | Max messages (1–999). Default: 100. |
| `oldest` | string | no | Slack ts (e.g., `1722000000.000000`) — return messages after. |
| `latest` | string | no | Slack ts — return messages before. |
| `cursor` | string | no | Pagination cursor. |

**Result**:

```json
{
  "messages": [
    {"ts": "...", "user": "U...", "text": "...", "thread_ts": "..."}
  ],
  "next_cursor": ""
}
```

**ReadOnly**: true.

---

### `slack.read_thread`

Read replies in a thread.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `channel` | string | yes | Channel ID. |
| `thread_ts` | string | yes | Parent message ts. |
| `limit` | int | no | Default 100. |

**Result**: same shape as `read_channel_history`.

**ReadOnly**: true.

---

### `slack.search_messages`

Search messages across the workspace. Requires user-token install (see research.md R1a) — bot-token-only installs return:

```json
{"error": "operation_not_enabled", "message": "search:read scope requires user-token install"}
```

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `query` | string | yes | Slack search query (e.g., `from:@alice in:#general`). |
| `count` | int | no | Max results (1–100). Default: 20. |
| `page` | int | no | Page number (1-indexed). Default: 1. |

**Result**:

```json
{"matches": [...], "total": 42, "page": 1, "pages": 3}
```

**ReadOnly**: true.

---

### `slack.post_message`

Post a message to a channel or DM.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `channel` | string | yes | Channel ID, channel name (`#general`), or user ID for DM. |
| `text` | string | yes | Message text (Slack mrkdwn). |
| `thread_ts` | string | no | Reply in thread. |
| `unfurl_links` | bool | no | Default false. |
| `unfurl_media` | bool | no | Default false. |

**Result**:

```json
{"channel": "C012ABC", "ts": "1722000000.000000", "message": {...}}
```

**ReadOnly**: false.

**Side-effect note** (per spec edge case): policy decisions occur strictly before `Execute` dispatches to Slack. Once posted, the message cannot be retracted by Sieve.

---

## Error contract

All operations return errors in this shape:

```json
{
  "error": "<machine_code>",
  "message": "<human readable>",
  "retriable": <bool>
}
```

Standard codes:

| Code | When | Retriable |
|------|------|-----------|
| `invalid_params` | Param validation failed before dispatch. | false |
| `policy_denied` | Pre-execution policy denied the call. | false |
| `reauth_required` | Connection status is `reauth_required` (or just transitioned). | false |
| `disabled` | Connection status is `disabled`. | false |
| `rate_limited` | Slack returned 429. The connector includes `retry_after_seconds` in the message. | true |
| `upstream_error` | Slack returned a non-401/403 error. | depends |
| `operation_not_enabled` | Operation requires a scope/install kind not present (e.g., search). | false |
| `transient_error` | Network/5xx. | true |

The bearer credential and Slack response headers are never echoed in error messages.
