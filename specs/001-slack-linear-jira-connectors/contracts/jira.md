# Jira Cloud Connector Contract

`Type() == "jira"`. MCP tools exposed with `jira_` prefix when the token has multiple connections. All operations execute against `https://api.atlassian.com/ex/jira/{cloudId}/rest/api/3/...` (OAuth path) or `<site_url>/rest/api/3/...` (basic-auth path). Both base URLs are overridable via `_base_url` in tests.

`Validate(ctx)` calls `GET /rest/api/3/myself`. Returns `nil` on 200 with a body containing `accountId`.

## Operations

### `jira.search_issues`

Search issues with JQL.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `jql` | string | yes | JQL query (e.g., `project = BOT AND status = "In Progress"`). |
| `fields` | []string | no | Field list to return. Default: `summary,status,assignee,priority`. |
| `start_at` | int | no | Pagination offset. Default: 0. |
| `max_results` | int | no | Page size (1–100). Default: 50. |

**Result**:

```json
{
  "issues": [
    {"key": "BOT-42", "id": "10042", "fields": {"summary": "...", "status": {"name": "In Progress"}, "assignee": {...}}}
  ],
  "start_at": 0,
  "max_results": 50,
  "total": 142
}
```

**ReadOnly**: true.

---

### `jira.get_issue`

Fetch one issue.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `issue_key` | string | yes | E.g., `BOT-42`. |
| `fields` | []string | no | Field list. Default: all. |

**Result**: full Jira issue object (`fields.summary`, `fields.description.content`, `fields.status`, `fields.assignee`, `fields.comment.comments`, etc.).

**ReadOnly**: true.

---

### `jira.create_issue`

Create a new issue.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `project_key` | string | yes | E.g., `BOT`. |
| `issue_type` | string | yes | E.g., `Task`, `Bug`, `Story`. |
| `summary` | string | yes | |
| `description` | string | no | ADF (Atlassian Document Format) markdown — connector handles plain-text-to-ADF conversion. |
| `assignee_account_id` | string | no | |
| `labels` | []string | no | |
| `priority` | string | no | E.g., `Medium`, `High`. |

**Result**:

```json
{"key": "BOT-43", "id": "10043", "self": "https://acme.atlassian.net/rest/api/3/issue/10043"}
```

**ReadOnly**: false.

---

### `jira.update_issue`

Update fields on an existing issue.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `issue_key` | string | yes | |
| `summary` | string | no | |
| `description` | string | no | |
| `assignee_account_id` | string | no | |
| `labels` | []string | no | Replaces existing labels. |
| `priority` | string | no | |

At least one optional field required.

**Result**: 204 No Content; connector returns `{"updated": true, "issue_key": "BOT-42"}`.

**ReadOnly**: false.

---

### `jira.transition_issue`

Move an issue through a workflow transition (e.g., To Do → In Progress).

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `issue_key` | string | yes | |
| `transition_id` | string | yes | Transition ID. The connector exposes `jira.list_transitions` (read-only) for discovery. |
| `comment` | string | no | Optional comment added with the transition. |

**Result**:

```json
{"transitioned": true, "issue_key": "BOT-42", "transition_id": "31"}
```

**ReadOnly**: false.

**Side-effect note**: transitions trigger upstream automation (notifications, webhook fires). Policy check happens before dispatch.

---

### `jira.add_comment`

Add a comment to an issue.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `issue_key` | string | yes | |
| `body` | string | yes | Plain text or ADF — connector converts plain text to ADF. |

**Result**:

```json
{"id": "10500", "created": "2026-05-01T..."}
```

**ReadOnly**: false.

---

### `jira.list_transitions` (helper, read-only)

Discover transition IDs for an issue's current state.

**Params**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `issue_key` | string | yes | |

**Result**:

```json
{"transitions": [{"id": "31", "name": "In Progress", "to": {"id": "10001", "name": "In Progress"}}]}
```

**ReadOnly**: true.

---

## Error contract

Same shape as Slack/Linear. Codes:

| Code | When | Retriable |
|------|------|-----------|
| `invalid_params` | Param validation failed. | false |
| `policy_denied` | Policy denied. | false |
| `reauth_required` | Connection status `reauth_required`. | false |
| `disabled` | Connection status `disabled`. | false |
| `rate_limited` | Jira returned 429. | true |
| `not_found` | Issue/project not found, or token lacks scope to see it. | false |
| `invalid_transition` | Transition ID not valid for the issue's current state. | false |
| `upstream_error` | Jira returned a non-auth error. | depends |
| `transient_error` | Network / 5xx. | true |

HTTP 401 with WWW-Authenticate referencing OAuth/Basic, or HTTP 403 with body containing token-revoked language, triggers `reauth_required` status transition (per research.md R10).
