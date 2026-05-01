# Phase 1 Data Model: Slack, Linear, Jira, and Asana Connectors

This document defines the persisted entities introduced or modified by this feature. All credential fields are stored inside the encrypted `config_ciphertext` blob on the `connections` row — never as plaintext columns.

> Updated 2026-05-01 to add `Asana Connection Config` per Q1 of Session 2026-05-01.

## Modified entity: `Connection`

Existing struct in `internal/connections/connections.go`. One additive field:

```go
type Connection struct {
    ID            string         `json:"id"`
    ConnectorType string         `json:"connector"`
    DisplayName   string         `json:"display_name"`
    Status        string         `json:"status"`              // NEW — see "Connection.Status" below
    Config        map[string]any `json:"-"`
    CreatedAt     time.Time      `json:"created_at"`
}
```

### Connection.Status

| Value | Meaning | Set by |
|-------|---------|--------|
| `active` | Connection is healthy. Default for new connections and for migrated existing connections. | Connection creation, successful re-auth |
| `reauth_required` | Last upstream call surfaced a terminal authentication error. Operations are blocked. | Connector classifier on terminal-auth error |
| `disabled` | Admin has explicitly disabled the connection. Operations are blocked. Does not auto-recover. | Admin UI button |

**Allowed transitions**: any → any (writes are validated at the call site, not encoded in the schema). In practice:

- `active` → `reauth_required` on terminal-auth error (connector-driven).
- `reauth_required` → `active` on successful re-auth (web handler-driven).
- `*` → `disabled` via admin action (UI-driven).
- `disabled` → `active` via admin action (UI-driven).

**Default**: `active`.

**Persistence**: new column `status TEXT NOT NULL DEFAULT 'active'` on the `connections` table. Idempotent ALTER TABLE migration in `internal/database/database.go`. Validation lives in Go (`validateStatus(s string) error`); no SQL CHECK constraint.

**Visibility**: returned by `Service.Get`, `Service.List`, `Service.GetWithConfig`. Does **not** require keyring decryption to read (status is non-secret) — `List` continues to work when keyring is unloaded.

## New entity: Slack Connection Config

Persisted inside the encrypted `config_ciphertext` blob. Schema:

```go
package slack

type Config struct {
    AuthKind   string  `json:"auth_kind"`              // "oauth" | "token"
    TeamID     string  `json:"team_id"`                // Slack workspace ID (e.g., "T012ABCDEF")
    TeamName   string  `json:"team_name,omitempty"`    // Display-only
    BotUserID  string  `json:"bot_user_id,omitempty"`  // Slack bot user (Uxxxxx)
    Scopes     []string `json:"scopes,omitempty"`      // Granted scope set

    // AuthKind == "oauth": populated by the OAuth callback.
    OAuthToken map[string]any `json:"oauth_token,omitempty"`     // {access_token, token_type, expiry?}
    ClientID     string `json:"client_id,omitempty"`             // For refresh (Slack bot tokens don't refresh, but kept for symmetry)
    ClientSecret string `json:"client_secret,omitempty"`

    // AuthKind == "token": pasted directly.
    BotToken string `json:"bot_token,omitempty"`                  // xoxb-... value, encrypted at rest
}
```

**Validation rules** (`Config.validate`):
- `AuthKind` must be one of `"oauth" | "token"`.
- If `AuthKind == "oauth"`: `OAuthToken.access_token` must be non-empty.
- If `AuthKind == "token"`: `BotToken` must start with `xoxb-`.
- `TeamID` must be non-empty after a successful OAuth or auth.test call.

## New entity: Linear Connection Config

```go
package linear

type Config struct {
    AuthKind         string   `json:"auth_kind"`              // "oauth" | "token"
    OrganizationID   string   `json:"organization_id"`        // Linear org UUID
    OrganizationName string   `json:"organization_name,omitempty"`
    Scopes           []string `json:"scopes,omitempty"`

    // AuthKind == "oauth": auth-code flow result.
    OAuthToken   map[string]any `json:"oauth_token,omitempty"` // {access_token, refresh_token, expiry, token_type}
    ClientID     string `json:"client_id,omitempty"`
    ClientSecret string `json:"client_secret,omitempty"`

    // AuthKind == "token": personal API key.
    APIKey string `json:"api_key,omitempty"`                    // lin_api_... value, encrypted at rest
}
```

**Validation rules**:
- `AuthKind` must be one of `"oauth" | "token"`.
- If `AuthKind == "oauth"`: `OAuthToken.access_token` non-empty.
- If `AuthKind == "token"`: `APIKey` must start with `lin_api_`.
- `OrganizationID` non-empty after Validate succeeds.

## New entity: Jira Cloud Connection Config

```go
package jira

type Config struct {
    AuthKind  string   `json:"auth_kind"`                       // "oauth" | "token"
    CloudID   string   `json:"cloud_id"`                        // Atlassian cloudId, used in API base URL
    SiteURL   string   `json:"site_url"`                        // e.g., https://acme.atlassian.net
    SiteName  string   `json:"site_name,omitempty"`
    Scopes    []string `json:"scopes,omitempty"`

    // AuthKind == "oauth": 3LO result.
    OAuthToken   map[string]any `json:"oauth_token,omitempty"` // {access_token, refresh_token, expiry}
    ClientID     string `json:"client_id,omitempty"`
    ClientSecret string `json:"client_secret,omitempty"`

    // AuthKind == "token": API token + email basic auth.
    Email    string `json:"email,omitempty"`
    APIToken string `json:"api_token,omitempty"`                 // Atlassian API token, encrypted at rest
}
```

**Validation rules**:
- `AuthKind` must be one of `"oauth" | "token"`.
- If `AuthKind == "oauth"`: `OAuthToken.access_token` non-empty AND `CloudID` non-empty.
- If `AuthKind == "token"`: `Email` matches `*@*` pattern AND `APIToken` non-empty AND `SiteURL` is `https://*.atlassian.net`.
- After Validate: `CloudID` non-empty in both modes (OAuth path resolves it via `accessible-resources`; token path resolves via `GET /rest/api/3/serverInfo`).

## New entity: Asana Connection Config

```go
package asana

type Config struct {
    AuthKind            string   `json:"auth_kind"`              // "oauth" | "token"
    DefaultWorkspaceGID string   `json:"default_workspace_gid"`  // Asana workspace GID, e.g. "123456789"
    UserGID             string   `json:"user_gid,omitempty"`     // The user the credential acts as
    UserName            string   `json:"user_name,omitempty"`    // Display-only
    Scopes              []string `json:"scopes,omitempty"`

    // AuthKind == "oauth": auth-code flow result.
    OAuthToken   map[string]any `json:"oauth_token,omitempty"`   // {access_token, refresh_token, expiry, token_type}
    ClientID     string `json:"client_id,omitempty"`
    ClientSecret string `json:"client_secret,omitempty"`

    // AuthKind == "token": Personal Access Token.
    PAT string `json:"pat,omitempty"`                            // 1/... value, encrypted at rest
}
```

**Validation rules**:
- `AuthKind` must be one of `"oauth" | "token"`.
- If `AuthKind == "oauth"`: `OAuthToken.access_token` non-empty AND (after Validate) `DefaultWorkspaceGID` non-empty AND `UserGID` non-empty.
- If `AuthKind == "token"`: `PAT` must start with `1/` and (after Validate) `DefaultWorkspaceGID` non-empty AND `UserGID` non-empty.

**Workspace resolution**: At connection creation time, the connector calls `GET /users/me?opt_fields=gid,name,workspaces.gid,workspaces.name`. The first workspace in the response (or, if the admin specified a `default_workspace_gid` at the form level, the matching one) is persisted as `DefaultWorkspaceGID`. Subsequent operations default to this workspace when the agent does not pass an explicit `workspace` parameter.

**Refresh-token rotation**: For `AuthKind == "oauth"`, Asana rotates refresh tokens per OAuth 2.0 spec. The connector reuses `connections.injectRefreshCallback` per FR-016. If the callback's persist fails, the connection transitions to `reauth_required` immediately.

## Relationships

- Each `Connection` references exactly one connector type via `ConnectorType` (existing FK semantics — string match into the registry).
- A `Role` (existing entity, `internal/roles`) references zero or more connections via `Bindings[].ConnectionID`. Slack/Linear/Jira connections plug into this unchanged.
- A `Token` (existing entity, `internal/tokens`) references one role. Unchanged.
- The `audit_log` table (existing) records every connector operation. Unchanged — its `connection_id`, `operation`, `policy_result` columns already cover the requirements in FR-006.

No new tables. No new foreign keys. No changes to `roles`, `tokens`, `policies`, `approval_queue`, or `audit_log` schemas.

## Field-level secret handling

The following fields on the `Config` structs above MUST never be logged, surfaced in error messages, or returned from any API endpoint:

- Slack: `BotToken`, `ClientSecret`, `OAuthToken.access_token`, `OAuthToken.refresh_token`
- Linear: `APIKey`, `ClientSecret`, `OAuthToken.access_token`, `OAuthToken.refresh_token`
- Jira: `APIToken`, `ClientSecret`, `OAuthToken.access_token`, `OAuthToken.refresh_token`
- Asana: `PAT`, `ClientSecret`, `OAuthToken.access_token`, `OAuthToken.refresh_token`

The `Connection.Config` field is already `json:"-"` (omitted from default serialization). Per-connector test cases must assert that error wrapping does not concatenate the credential into the error message (a known foot-gun when wrapping with `%w` plus a `%v` token).

## Operation parameter and result shapes

See [contracts/slack.md](./contracts/slack.md), [contracts/linear.md](./contracts/linear.md), [contracts/jira.md](./contracts/jira.md), and [contracts/asana.md](./contracts/asana.md) for the per-operation parameter and return-value contracts.

### Cross-cutting shape rules

These rules apply to every contract; the per-connector files spell out the upstream-specific instances.

**Pagination shape (FR-014)**: every `list_*` operation accepts:

```
cursor    string  optional   opaque value from previous response's next_cursor
page_size int     optional   default 100, hard cap 100
```

and returns:

```
{
  "items":       [ ... ],
  "next_cursor": ""   // empty string or null = end of dataset
}
```

The connector's `pagination.go` translates between this normalized shape and the upstream's native paging mechanism per the table in `research.md` § R13.

**Rich-text dual representation (FR-015)** — Jira and Asana only:

| Connector | Native field | Companion plain-text field | Rendering |
|-----------|--------------|----------------------------|-----------|
| Jira | `description` (ADF JSON tree) | `description_text` | ADF tree-walk, see `internal/connectors/jira/adf.go` |
| Jira | `comment.body` (ADF JSON) | `comment.body_text` | same |
| Asana | `notes` (HTML when html_notes is set, else plain) | `notes_text` | html-to-text helper, see `internal/connectors/asana/richtext.go` |

The plain-text rendering is best-effort; the native field is canonical. Policies authors choose whichever representation fits their matching needs (e.g., regex against `description_text`, structural match against `description.content`).
