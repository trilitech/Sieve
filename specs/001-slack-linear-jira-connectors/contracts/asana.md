# Asana Connector Contract

`Type() == "asana"`. MCP tools exposed with `asana_` prefix when the token has multiple connections. All operations execute against `https://app.asana.com/api/1.0/...` (overridable via `_base_url` for tests).

`Validate(ctx)` calls `GET /users/me`. Returns `nil` on 200 with a body containing `data.gid`.

**Refresh-token rotation**: For OAuth-mode connections, Asana rotates refresh tokens per the OAuth 2.0 spec. The connector reuses `connections.injectRefreshCallback` per FR-016. If the persist of a rotated refresh token fails, the connection transitions to `reauth_required` immediately.

**Pagination**: every `list_*` operation follows the normalized FR-014 shape (`{items, next_cursor}` with input `cursor` / `page_size`). The connector translates internally to Asana's native `offset` / `next_page.offset` and `limit` parameters.

**Rich text**: tasks and comments carry an HTML `notes` (or `html_text`) field upstream when the user formatted text in Asana. Per FR-015, the connector returns BOTH the native HTML field AND a plain-text companion (`notes_text` / `html_text_text`) rendered by `internal/connectors/asana/richtext.go`.

## Operations

### `asana.list_workspaces`

List workspaces the credentialed user belongs to.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `cursor` | string | no | FR-014 cursor. |
| `page_size` | int | no | Default 100, max 100. |

**Result**:

```json
{
  "items": [
    {"gid": "123456789", "name": "Acme Corp", "is_organization": true}
  ],
  "next_cursor": ""
}
```

**ReadOnly**: true.

---

### `asana.list_users`

List users in a workspace.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `workspace` | string | no | Workspace GID. Defaults to the connection's `default_workspace_gid`. |
| `cursor` | string | no | |
| `page_size` | int | no | |

**Result**:

```json
{
  "items": [
    {"gid": "111", "name": "Alice", "email": "alice@example.com"}
  ],
  "next_cursor": ""
}
```

**ReadOnly**: true.

---

### `asana.list_projects`

List projects in a workspace, optionally filtered by team.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `workspace` | string | no | Defaults to `default_workspace_gid`. |
| `team` | string | no | Team GID filter. |
| `archived` | bool | no | Default false. |
| `cursor` | string | no | |
| `page_size` | int | no | |

**Result**:

```json
{
  "items": [
    {"gid": "222", "name": "Q2 Roadmap", "archived": false, "current_status": {"text": "..."}}
  ],
  "next_cursor": ""
}
```

**ReadOnly**: true.

---

### `asana.list_tasks`

List tasks within a project.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `project` | string | yes | Project GID. |
| `completed_since` | string | no | RFC3339 timestamp; tasks completed before this are excluded. |
| `cursor` | string | no | |
| `page_size` | int | no | |

**Result** (rich-text companion fields per FR-015 when notes/html_notes present):

```json
{
  "items": [
    {
      "gid": "333",
      "name": "Ship the thing",
      "completed": false,
      "assignee": {"gid": "111", "name": "Alice"},
      "due_on": "2026-06-15",
      "notes": "<body>Some <b>HTML</b> content</body>",
      "notes_text": "Some HTML content"
    }
  ],
  "next_cursor": "20"
}
```

**ReadOnly**: true.

---

### `asana.get_task`

Fetch one task.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `task_gid` | string | yes | Task GID (e.g., `333`). |

**Result** (rich-text companion fields per FR-015):

```json
{
  "gid": "333",
  "name": "Ship the thing",
  "completed": false,
  "assignee": {"gid": "111", "name": "Alice"},
  "due_on": "2026-06-15",
  "notes": "<body>Some <b>HTML</b> content with a <a href='https://example.com'>link</a></body>",
  "notes_text": "Some HTML content with a link (https://example.com)",
  "tags": [{"gid": "444", "name": "priority-high"}],
  "memberships": [{"project": {"gid": "222"}, "section": {"gid": "555"}}]
}
```

**ReadOnly**: true.

---

### `asana.create_task`

Create a new task.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `project` | string | yes | Project GID. |
| `name` | string | yes | Task title. |
| `notes` | string | no | Plain-text description. Sent to Asana as `notes`. |
| `_html_notes` | string | no | Advanced: pass HTML body verbatim. Sent as `html_notes`. Mutually exclusive with `notes` — if both provided, `_html_notes` wins and `notes` is ignored. |
| `assignee_gid` | string | no | User GID to assign. |
| `due_on` | string | no | YYYY-MM-DD. |

**Result**:

```json
{
  "gid": "334",
  "name": "Ship the thing",
  "completed": false
}
```

**ReadOnly**: false.

---

### `asana.update_task`

Update an existing task. Only the supplied fields are changed.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `task_gid` | string | yes | |
| `name` | string | no | |
| `notes` | string | no | Plain-text replacement. |
| `_html_notes` | string | no | HTML replacement (advanced; mutually exclusive with `notes`). |
| `completed` | bool | no | |
| `assignee_gid` | string | no | Pass empty string to unassign. |
| `due_on` | string | no | |

**Result**: updated task object (same shape as `get_task`).

**ReadOnly**: false.

---

### `asana.add_comment`

Add a comment (story) to a task.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `task_gid` | string | yes | |
| `text` | string | yes | Plain-text comment body. |
| `_html_text` | string | no | Advanced HTML body, mutually exclusive with `text`. |

**Result**:

```json
{"gid": "555", "type": "comment", "created_at": "2026-05-01T12:00:00Z"}
```

**ReadOnly**: false.

## Terminal-auth signals

The connector treats the following responses as terminal-auth and transitions the connection's `status` to `reauth_required`:

- HTTP 401 with `{"errors": [{"message": "Not Authorized"}]}` (or any 401 with body containing `"Not Authorized"`).
- HTTP 403 with body containing `"deleted token"` or `"invalid_grant"`.
- OAuth refresh failure with `error_code` of `invalid_grant` from `https://app.asana.com/-/oauth_token`.

Anything else (5xx, 429, network) is transient and does NOT change connection status. Per R5/FR-016, a successful refresh that fails to persist (DB error) ALSO transitions the connection to `reauth_required`.

## Out of scope (v1)

These Asana surfaces are explicitly NOT covered:

- Webhooks (inbound).
- Attachments (upload/download). The connector does not surface `/tasks/{task_gid}/attachments`.
- Custom fields (read or write). Tasks are returned without their `custom_fields` array; agents that need custom-field interaction can use the HTTP proxy connector.
- Portfolios, goals, status updates, and time tracking.
- Asana Enterprise SAML/SCIM provisioning.
