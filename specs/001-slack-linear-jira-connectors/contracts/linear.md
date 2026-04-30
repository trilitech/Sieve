# Linear Connector Contract

`Type() == "linear"`. MCP tools exposed with `linear_` prefix when the token has multiple connections. All operations execute against `https://api.linear.app/graphql` (overridable via `_base_url` in tests).

`Validate(ctx)` issues `query { viewer { id email } }`. Returns `nil` if `viewer` is non-null.

## Operations

### `linear.list_teams`

List teams in the connected organization.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `first` | int | no | Page size (1–100). Default: 50. |
| `cursor` | string | no | Pagination cursor. |

**Result**:

```json
{
  "teams": [{"id": "...", "key": "BOT", "name": "Bots"}],
  "next_cursor": ""
}
```

**ReadOnly**: true.

---

### `linear.list_users`

List users in the organization.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `first` | int | no | Default: 50. |
| `cursor` | string | no | |

**Result**:

```json
{"users": [{"id": "...", "email": "...", "name": "...", "active": true}], "next_cursor": ""}
```

**ReadOnly**: true.

---

### `linear.list_issues`

List issues, optionally filtered by team or assignee.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `team_key` | string | no | Restrict to a team (e.g., `BOT`). |
| `assignee_id` | string | no | Restrict to issues assigned to this user. |
| `state` | string | no | One of `triage`, `backlog`, `unstarted`, `started`, `completed`, `canceled`. |
| `first` | int | no | Default: 25. Max: 100. |
| `cursor` | string | no | |

**Result**:

```json
{
  "issues": [
    {"id": "...", "identifier": "BOT-42", "title": "...", "state": "started", "assignee": {...}, "team": {...}, "url": "..."}
  ],
  "next_cursor": ""
}
```

**ReadOnly**: true.

---

### `linear.get_issue`

Fetch one issue by identifier or UUID.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `identifier` | string | yes | Either `BOT-42` (human ID) or the UUID. |

**Result**: full issue object including `description`, `comments` (preview), `assignee`, `state`, `labels`.

**ReadOnly**: true.

---

### `linear.create_issue`

Create a new issue.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `team_key` | string | yes | Team to create the issue in (e.g., `BOT`). |
| `title` | string | yes | |
| `description` | string | no | Markdown body. |
| `assignee_id` | string | no | |
| `labels` | []string | no | Label IDs. |
| `priority` | int | no | 0 (none) – 4 (urgent). |

**Result**:

```json
{"id": "...", "identifier": "BOT-43", "url": "..."}
```

**ReadOnly**: false.

---

### `linear.update_issue`

Update fields on an existing issue.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `identifier` | string | yes | `BOT-42` or UUID. |
| `title` | string | no | |
| `description` | string | no | |
| `state_id` | string | no | Target workflow state. |
| `assignee_id` | string | no | |
| `priority` | int | no | |

At least one optional field must be present.

**Result**:

```json
{"id": "...", "identifier": "BOT-42", "updated_at": "..."}
```

**ReadOnly**: false.

---

### `linear.add_comment`

Add a comment to an issue.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `issue_identifier` | string | yes | `BOT-42` or UUID. |
| `body` | string | yes | Markdown body. |

**Result**:

```json
{"id": "<comment-id>", "created_at": "..."}
```

**ReadOnly**: false.

---

## Error contract

Same shape as Slack (see `slack.md` Error contract). Codes:

| Code | When | Retriable |
|------|------|-----------|
| `invalid_params` | Param validation failed. | false |
| `policy_denied` | Policy denied. | false |
| `reauth_required` | Connection status `reauth_required`. | false |
| `disabled` | Connection status `disabled`. | false |
| `rate_limited` | Linear returned 429 or `RATELIMITED` GraphQL error. | true |
| `not_found` | Issue/team/user not found. | false |
| `upstream_error` | Linear returned a non-auth error. | depends |
| `transient_error` | Network / 5xx. | true |

GraphQL errors with `extensions.code == "AUTHENTICATION_ERROR"` trigger `reauth_required` status transition (per research.md R10).
