# Agent Error Contract

This page documents every structured error envelope an agent client (REST or MCP) sees when calling the Sieve agent API on port 19817. Use it to write a single error handler for any agent SDK.

This contract was last revised in May 2026 (PR #10). Prior versions used different status codes and envelopes; if you have an agent wrapper authored against an older Sieve build, audit it against this page.

---

## At a glance

| Code (machine-readable) | HTTP status | When | Retry semantics |
|---|---|---|---|
| `reauth_required` | 403 | The connection's OAuth credentials are dead (refresh failed, token revoked). Both the pre-flight gate and the post-flight execution path return this. | **Permanent** until a human re-authenticates. Do not retry. Surface `reauth_url` to the operator. |
| `disabled` | 403 | An admin disabled the connection. | **Permanent** until an admin re-enables. Do not retry. |
| `operation_not_enabled` | 501 | The operation exists in the connector's catalog (policies can bind to its name) but is gated off in this Sieve version. Today's only producer is Slack's `search_messages`. | **Permanent for this Sieve version.** Don't retry; the gate goes away when Sieve adds the capability. |
| `service_locked` | 503 | The Sieve keyring is unloaded — the operator hasn't supplied the passphrase yet. | **Transient.** Retrying after the operator unlocks WILL succeed. |
| `rotation in progress` | 503 + `Retry-After` | A passphrase rotation is mid-flight. | **Transient.** Retry per the `Retry-After` header. |
| `too many auth attempts, retry later` | 429 | Per-IP token-bucket exhausted by failed bearer-token validations. | **Transient.** Retry per the `Retry-After` header. |
| `unknown parameter(s) …` | 400 | The request carried a parameter the operation does not declare. Parameters are a **closed set**: an operation accepts exactly what its catalog entry lists, and anything else is refused rather than accepted and discarded. The message names the offending keys and lists the accepted ones. | **Permanent** for that request. Fix the parameter name and retry; don't resend as-is. |

---

## REST envelopes

All bodies are JSON. Servers always set `Content-Type: application/json` and `Cache-Control: no-store, no-cache, max-age=0, must-revalidate, private`.

### 1. `reauth_required` (HTTP 403)

```json
{
  "error":         "reauth_required",
  "connection_id": "gmail-work",
  "reason":        "invalid_grant: refresh token revoked",
  "reauth_url":    "/connections/gmail-work/reauth",
  "message":       "This connection's credentials are no longer valid. A human must re-authenticate via the Sieve web UI."
}
```

Emitted from both detection paths byte-equally:

- Pre-flight: `connections.ErrReauthRequired` (the row's `status` column is `reauth_required`).
- Post-flight: `connector.ErrNeedsReauth` (the connector hit an upstream 401 during `Execute`).

Both paths route through the single `writeReauthError` helper.

### 2. `operation_not_enabled` (HTTP 501)

```json
{
  "error":         "operation_not_enabled",
  "connection_id": "acme-slack",
  "operation":     "search_messages",
  "message":       "slack search.messages requires user-token install; v1 supports bot tokens only"
}
```

Emitted when a connector returns `connector.ErrOperationNotEnabled` from `Execute`. The `message` is the connector-supplied detail (the sentinel prefix is stripped). The body's `error` field is the stable code SDKs should branch on; the `message` is human-readable and may change between releases.

### 3. `service_locked` (HTTP 503)

```json
{
  "error":   "service_locked",
  "message": "service locked: passphrase required"
}
```

Returned when `secrets.ErrKeyringNotLoaded` propagates to a request. The operator must supply the keyring passphrase (TTY prompt at startup, `SIEVE_PASSPHRASE_FILE`, or systemd FD 3). Agent retries after the operator unlocks will succeed.

### 4. `disabled` (HTTP 403)

```json
{
  "error":   "disabled",
  "message": "connection is disabled; an admin must re-enable it before agents can use it"
}
```

Returned for `connections.ErrConnectionDisabled` (an admin clicked the Disable button on the connection). Re-enable from the admin UI to recover.

---

## MCP envelopes

MCP does not use HTTP status codes for tool errors — it uses the tool-result `isError: true` flag plus a content block. The text begins with a stable machine-parseable prefix (`<code>:` followed by a space).

### `reauth_required`

```json
{
  "isError": true,
  "content": [
    { "type": "text",
      "text": "reauth_required: Connection \"gmail-work\" needs re-authentication. Reason: invalid_grant: refresh token revoked. A human must visit the Sieve admin UI and click Re-authenticate on this connection (URL: /connections/gmail-work/reauth)." }
  ]
}
```

### `operation_not_enabled`

```json
{
  "isError": true,
  "content": [
    { "type": "text",
      "text": "operation_not_enabled: slack search.messages requires user-token install; v1 supports bot tokens only" }
  ]
}
```

### `disabled`

```json
{
  "isError": true,
  "content": [
    { "type": "text", "text": "disabled: connection is disabled" }
  ]
}
```

### Keyring locked

When the keyring is unloaded, the MCP layer returns a JSON-RPC transport error (not a tool result) — a single `Error` object with code `-32000` and `message: "service locked: passphrase required"`. Agent retries after unlock will succeed.

---

## Parameters are a closed set

The generic ops route (`POST /api/v1/connections/{conn}/ops/{operation}`) used
to pass every key in the request body through to the connector, which ignored
the ones it didn't recognise. That made a whole class of silent failure
possible: set a field the operation knows nothing about and you get `200 OK`
describing a result that never included it.

Unknown parameters are now rejected with `400`, naming both the offending keys
and the accepted set:

```json
{ "error": "unknown parameter(s) \"body_html\" for operation \"create_draft\". Accepted: attachments, bcc, body, cc, in_reply_to, ..." }
```

The one exception is an operation whose accepted set genuinely cannot be
enumerated in advance — today only `mcp_proxy`, whose parameters are a
projection of an upstream tool's JSON Schema (which may allow additional
properties, and may be unreachable). Those operations opt out explicitly and
let the upstream tool do the rejecting.

Note the Gmail-compatible REST surface (`/gmail/v1/...`) has always enforced its
own allow-list and returns `unknown field "..."` in the same spirit.

---

## Suggested agent error handler

```pseudo
function handleSieveError(httpResp):
    if httpResp.status == 403 and httpResp.body.error == "reauth_required":
        notifyOperator("Re-authentication required: ${httpResp.body.reauth_url}")
        return TerminalError("reauth_required")
    if httpResp.status == 403 and httpResp.body.error == "disabled":
        notifyOperator("Connection disabled; ask an admin to re-enable")
        return TerminalError("disabled")
    if httpResp.status == 501 and httpResp.body.error == "operation_not_enabled":
        return TerminalError("operation_not_enabled: ${httpResp.body.message}")
    if httpResp.status == 503:
        return RetryableError(after = httpResp.headers["Retry-After"] or "30s")
    if httpResp.status == 429:
        return RetryableError(after = httpResp.headers["Retry-After"] or "60s")
    # ...
```

For MCP, branch on the text prefix:

```pseudo
function handleSieveMCPToolResult(result):
    if not result.isError: return result.content
    text = result.content[0].text
    if text.startsWith("reauth_required: "): return TerminalError("reauth_required", text)
    if text.startsWith("operation_not_enabled: "): return TerminalError("operation_not_enabled", text)
    if text.startsWith("disabled: "): return TerminalError("disabled", text)
    return UnknownError(text)
```

---

## What changed in the May 2026 revision

- The `reauth_required` envelope's HTTP status went from **503** to **403**. The error code went from `connection_reauth_required` to `reauth_required`. The envelope shape is otherwise unchanged.
- The `operation_not_enabled` shape is new — previously, gated operations returned HTTP 200 with `{"error": "operation_not_enabled"}` in the body (the "phantom success" bug the reviewer flagged).
- 503 is now reserved for genuinely transient conditions (`service_locked`, `rotation in progress`). Distinguishing transient from permanent at the status-code level lets retry-aware SDKs do the right thing without inspecting the body.
