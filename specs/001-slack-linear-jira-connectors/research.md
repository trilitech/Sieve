# Phase 0 Research: Slack, Linear, Jira, and Asana Connectors

This document resolves the open questions implied by the spec and the technical context. Each entry follows the format **Decision / Rationale / Alternatives**.

> Updated 2026-05-01 to incorporate the spec's Session 2026-05-01 clarifications:
> Asana added (R12), pagination normalization (R13), rich-text round-trip (R14),
> refresh-token rotation persistence semantics (R5 expanded). Slack scope strategy
> locked to classic non-rotating bot scopes (R1 unchanged in substance, but the
> "no rotation" decision is now load-bearing — see R5).

## R1. Slack authentication: OAuth install flow

**Decision**: Use Slack OAuth v2 with the `oauth.v2.access` token exchange endpoint. Sieve registers a Slack app once (operator-controlled, configured via `SLACK_CLIENT_ID` / `SLACK_CLIENT_SECRET` in `internal/config`), and per-connection install flow uses the existing `pendingOAuth` map keyed on a random state token (10-min TTL, same constant as Google OAuth in `internal/web/server.go`). The redirect URL is `http://<host>/oauth/callback?provider=slack` and routes through the existing `handleOAuthCallback` after dispatch on the `provider` query.

The minimum bot-token scope set, derived from the curated operations:

| Operation | Scope(s) |
|-----------|----------|
| list channels | `channels:read`, `groups:read` |
| list users | `users:read` |
| read user profile | `users:read`, `users.profile:read` |
| read channel history | `channels:history`, `groups:history` |
| read thread | covered by `channels:history` / `groups:history` |
| search messages | `search:read` (note: requires user token, not bot token — see R1a) |
| post message | `chat:write` |

**Rationale**: Matches the Slack-recommended "Install via OAuth" UX and reuses Sieve's existing OAuth infrastructure with zero new state-machine code. Persisting only after the token exchange succeeds matches FR-002 and the existing pendingOAuth invariant.

**Alternatives considered**:
- *Slack App tokens*: rejected — only useful for Socket Mode, which is event-driven and out of scope for v1.
- *Manifest-based install (paste-this-manifest)*: rejected — adds a setup step (admin must create the app first) that doesn't match the "click install, return with credentials" UX of the Google connector. Operators who do prefer manifest-driven install can use the direct-token entry path (R1b).

### R1a. Slack `search:read` scope ambiguity

**Decision**: For v1, document that `search:read` requires a user-token install when the operator wants the search-messages operation. Bot-token-only installs disable the search operation gracefully (returns "operation not enabled for this install — re-install with user-token scope") rather than failing opaquely. Adding user-token install support is deferred along with Enterprise Grid.

**Rationale**: Slack's `search.*` API methods only accept user tokens. The spec's curated set lists "search messages" but the spec also commits to bot-token-only OAuth in Assumptions. The user-facing impact is captured by an operation-level fallback rather than blocking the whole connector.

### R1b. Slack direct bot-token entry

**Decision**: A second admin path accepts a pasted bot token (typically `xoxb-...`) plus optional team metadata. On submit the connector calls Slack `auth.test`; on success the connection is persisted with `auth_kind: "token"`. No state machine is needed because the token is already issued; the admin manages the source-side Slack app independently.

**Rationale**: Matches the GitHub PAT entry path (`internal/web/github.go:handleGitHubPAT`) and supports operators with pre-existing internal Slack apps.

## R2. Linear authentication: OAuth 2.0 + personal API key

**Decision**: Two peer auth methods, both first-class:

- **OAuth 2.0**: standard auth-code flow against `https://linear.app/oauth/authorize` and `https://api.linear.app/oauth/token`. Scopes: `read,write,issues:create`. `actor=app` (acts as the OAuth app, not as the granting user) — but Linear's GraphQL API still accepts the resulting token. Refresh tokens are supported and persisted via the existing `injectRefreshCallback` hook.
- **Personal API key**: pasted by the admin (`lin_api_...` prefix). Validated by issuing the GraphQL query `query { viewer { id email } }`. On 200 with a non-null `viewer`, persist with `auth_kind: "token"`.

**Rationale**: The spec's Q1 clarification commits to both methods. Linear OAuth is the right choice for shared installations, while personal API keys are simpler and well-suited to Sieve's individual-account positioning (Q2). Refresh-token persistence reuses the Gmail/GitHub mechanism with no new code.

**Alternatives considered**:
- *OAuth-only*: rejected by Q1 (user explicitly wanted both, mirroring GitHub).
- *PKCE-only OAuth*: rejected — Linear supports PKCE but the standard auth-code flow is simpler and matches the existing Google connector pattern. PKCE adds value for public clients, but Sieve is a confidential client (the `client_secret` lives only in the operator's config).

## R3. Jira Cloud authentication: OAuth 2.0 (3LO) + API token

**Decision**: Two peer auth methods:

- **OAuth 2.0 (3LO)**: standard auth-code flow against `https://auth.atlassian.com/authorize` (audience=`api.atlassian.com`) and `https://auth.atlassian.com/oauth/token`. Scopes: `read:jira-user read:jira-work write:jira-work offline_access`. After token exchange, a follow-up call to `https://api.atlassian.com/oauth/token/accessible-resources` resolves the `cloudId` for the granted Atlassian site, which is stored in the config alongside the token. Subsequent API calls go to `https://api.atlassian.com/ex/jira/{cloudId}/rest/api/3/...`.
- **API token + email**: admin pastes their Atlassian email and an Atlassian API token (created at `https://id.atlassian.com/manage-profile/security/api-tokens`) plus the Jira site URL (e.g., `https://acme.atlassian.net`). The connector validates by calling `GET /rest/api/3/myself` with HTTP basic auth (`email:api_token`). The site URL doubles as the request base.

**Rationale**: Both methods are documented as Atlassian-supported. The OAuth (3LO) path requires the cloudId resolution step; basic-auth path skips it. Persisting only after a successful validation matches FR-002.

**Alternatives considered**:
- *Connect framework / OAuth 1.0a*: rejected — Connect is for Atlassian Marketplace apps, not point-to-point integrations. OAuth 1.0a is deprecated for Cloud.
- *Forge*: rejected — Forge is for Atlassian-hosted integrations, doesn't fit the Sieve credential-gateway model.
- *Jira Server / Data Center*: explicitly out of scope per spec.

## R4. Connection status field: schema, migration, and transition contract

**Decision**:

- **Schema change**: idempotent `ALTER TABLE connections ADD COLUMN status TEXT NOT NULL DEFAULT 'active'`, gated by a `columnExists("connections", "status")` check that mirrors the existing `hasOldConfig` pattern in `internal/database/database.go:161`. Existing rows take the default and become `active`. The migration is forward-only.
- **Allowed values**: `active`, `reauth_required`, `disabled`. CHECK constraint not added to the column (the existing schema uses no CHECK constraints; validation lives in Go).
- **Read path**: every SELECT against `connections` adds `status` to the column list. `Connection` struct gains `Status string` field. `List()` returns it; the admin UI renders it.
- **Write path**: a new method `connections.Service.SetStatus(id, status string) error` performs `UPDATE connections SET status = ? WHERE id = ?`. No KEK/encryption involvement (status is non-secret).
- **Transition trigger**: connectors classify upstream errors into `terminalAuth` (HTTP 401/403 with no retry hint, OAuth refresh failure, explicit revoked-token markers) vs. `transient` (5xx, network, 429). On `terminalAuth`, the connector calls `Service.SetStatus(id, "reauth_required")` once (idempotent — repeated calls are safe). On admin re-auth (fresh OAuth completion or token re-entry), `Service.SetStatus(id, "active")` is called from the web handler.
- **Disabled path**: `SetStatus(id, "disabled")` exposed via an admin-only UI button. Connectors check status before each `Execute` and short-circuit with a non-secret error if status != `active`. The check happens in `connections.GetConnector` (returns a sentinel error like `ErrConnectionDisabled` / `ErrReauthRequired`) so every call site benefits without per-connector code.

**Rationale**: An additive column with a non-null default is the cheapest viable schema change; the idempotent ALTER pattern is already used in this codebase. Putting the status check in `GetConnector` (rather than in each connector's `Execute`) means any future connector inherits the behavior without thinking about it. Validation in Go (rather than CHECK) matches existing project conventions.

**Alternatives considered**:
- *Separate `connection_status` table*: rejected — overkill for a 3-state enum, adds a join.
- *Status as a JSON field inside the encrypted config*: rejected — status is non-secret and needs to be visible in `List()` without keyring access (the admin UI must render it before the user types the passphrase).
- *FSM / state-transition table*: rejected — three states with two trigger paths don't justify the abstraction (CLAUDE.md "no premature abstraction").
- *Per-connection `last_error` text*: deferred — useful but not in scope for this clarification.

## R5. Token refresh persistence for Linear, Jira, and Asana

**Decision**: Reuse `connections.Service.injectRefreshCallback` exactly as Gmail does. Each connector's factory accepts the `_on_token_refresh` callback in config, wires it through a `persistingTokenSource` (the pattern at `internal/connectors/gmail/gmail.go:72-92`), and the callback writes the refreshed token back via `UpdateConfig`. **Persistence is mandatory before the refreshed access token is used for any subsequent upstream call**, because Atlassian, Linear, and Asana all rotate refresh tokens (the old refresh token is invalidated the moment the new one is issued — confirmed by Atlassian docs: *"Each time they are used, rotating refresh tokens issue a new limited life refresh token"*; Linear and Asana follow the same OAuth 2.0 rotation behavior). Slack does NOT rotate (classic bot scopes per Q2 2026-05-01).

**Failure semantics** (FR-016): If the persist itself fails (DB error, disk full, keyring unloaded mid-call), the connector MUST transition `status → reauth_required` immediately and surface a non-secret "reauth required" error to the agent. This is a one-line change to the existing callback at `internal/connections/connections.go` (`injectRefreshCallback` becomes status-aware on persist failure). Gmail benefits from the same change automatically.

A regression test in `internal/connections/refresh_test.go` simulates a `db.Exec` failure during `UpdateConfig` and asserts the row ends in `reauth_required`. Each per-connector test suite (Linear, Jira, Asana) has a complementary test that drives a token refresh through the connector's HTTP middleware with a stubbed-failure persistence layer.

**Rationale**: Same OAuth library, same callback shape, same persistence path. Once the upstream invalidates the old refresh token, the connection is functionally bricked unless the new one is durable. Surfacing `reauth_required` at the moment of the persist failure (instead of letting the next call attempt and fail with a stale refresh token) shortens the time-to-detection well within SC-007's 60-second target.

**Alternatives considered**:
- *Writing a custom refresh loop per connector*: rejected — redundant.
- *Two-phase commit (write new refresh token to DB BEFORE using it for the upstream call)*: rejected — doesn't help, since upstream invalidates the old refresh on issue of the new regardless of what we write locally first.
- *Leave status as `active` on persist failure and rely on the next call's auth-error path*: rejected — wastes one or more upstream calls and delays admin visibility.

## R6. Mock HTTP servers for tests

**Decision**: Add four small `httptest.Server`-based mocks under `internal/testing/`:

- `internal/testing/mockslack/server.go`
- `internal/testing/mocklinear/server.go`
- `internal/testing/mockjira/server.go`
- `internal/testing/mockasana/server.go`

Each mock implements only the endpoints exercised by the connector's curated operations + `Validate`. The connector factory accepts a base URL override (config key `_base_url` or similar, prefixed with underscore to match the existing `_on_token_refresh` convention) so tests can inject the mock's URL. In production this key is absent and the connector falls back to the official endpoint.

**Rationale**: Matches `internal/testing/mockconnector` precedent. Keeps test runs hermetic and fast; no network access required. Underscore-prefixed config keys are already idiomatic in this codebase for non-persisted runtime injections.

**Alternatives considered**:
- *VCR-style record/replay*: rejected — recording requires live credentials, replay drifts when the API changes; the cost-benefit is wrong for three small surface areas.
- *Real-service tests gated by env flag*: deferred — useful as a smoke check before release but not part of the standard `go test ./...` path.

## R7. e2e (Playwright) coverage

**Decision**: Extend `e2e/web-ui.spec.ts` with three new test cases per connector (Slack, Linear, Jira, Asana):

1. Add a connection via OAuth (mock OAuth provider in testserver, simulate the redirect with a synthesized state).
2. Add a connection via direct token entry, with the testserver returning a successful `Validate`.
3. Verify the connection's `status` column displays `active` after add, and transitions to `reauth_required` after the testserver's mock service starts returning 401.

`e2e/testserver/main.go` registers the four new mock services on internal ports and wires them into the connector factory base-URL overrides for the duration of the test run.

**Rationale**: Reproduces the user-visible flow end-to-end without burning real Slack/Linear/Jira accounts. The status-transition test directly verifies SC-007 and FR-009a.

## R8. Documentation pages

**Decision**: Four new pages — `docs/connectors-slack.md`, `docs/connectors-linear.md`, `docs/connectors-jira.md`, `docs/connectors-asana.md` — each containing:

1. External prerequisites (create a Slack app / Linear OAuth app / Jira OAuth app + scopes).
2. Setup walkthrough for the OAuth path.
3. Setup walkthrough for the direct-token path.
4. Curated operation list (matches `Operations()`).
5. Troubleshooting (reauth, scope mismatch, rate limits).

Format follows the existing per-connector docs style (no new toolchain).

**Rationale**: Discharges FR-012 directly. SC-001 (10-minute setup) is verified by following these pages.

## R9. Settings / config surface

**Decision**: Each connector's OAuth credentials (`{SERVICE}_CLIENT_ID`, `{SERVICE}_CLIENT_SECRET`) live in `internal/settings` alongside the existing Google/GitHub equivalents, loaded from the operator's config file. No env-var-only intake. If credentials are absent, the OAuth path is hidden in the UI and only direct-token entry is offered (matches the existing GitHub PAT-only path when the operator hasn't created a GitHub App).

**Rationale**: Single config surface, consistent operator UX. Letting the UI hide the OAuth button keeps the install flow honest about what's available.

## R10. Error classification matrix

**Decision**: Per service, define a small classifier function (`isTerminalAuthError(resp *http.Response, body []byte) bool`) used by the connector's HTTP middleware. The classification rules:

| Service | Terminal-auth signals |
|---------|----------------------|
| Slack | response body `{ok: false, error: "invalid_auth" | "token_revoked" | "account_inactive" | "not_authed"}` |
| Linear | HTTP 401, or GraphQL errors[0].extensions.code == `AUTHENTICATION_ERROR` |
| Jira | HTTP 401 with WWW-Authenticate referencing OAuth/Basic, or HTTP 403 with `{errorMessages: [...]}` body containing token-revoked language |
| Asana | HTTP 401 with body `{errors: [{message: "Not Authorized"}]}`, or HTTP 403 with body containing `"deleted token"` / `"invalid_grant"` |

Anything else (5xx, 429, network errors) is `transient` and does not change connection status. The classifier is deliberately conservative — false positives flip a connection to `reauth_required` unnecessarily, which is correctable but annoying; false negatives leave a stale credential in `active` until the next call.

**Rationale**: Each upstream service signals revocation differently, but the set of terminal codes is small and well-documented per service. Keeping this in a single per-connector function makes it easy to tighten later if we observe miscategorizations.

## R11. Out-of-scope reaffirmations

These are explicitly **not** addressed in v1 and have no Phase 0 design notes:

- Inbound webhook ingestion (Slack Events, Linear webhooks, Jira webhooks, Asana webhooks) — out of scope per Q3.
- Slack Enterprise Grid org-level installs — out of scope per spec Assumptions.
- Slack user-token flows (other than the documented limitation noted in R1a for `search:read`) — out of scope.
- Slack granular scopes with token rotation — out of scope per Q (2026-05-01); v1 uses classic non-rotating bot scopes only.
- Jira Server / Data Center — out of scope per spec Assumptions.
- Asana Enterprise SAML/SCIM provisioning, attachments upload/download — out of scope per spec Assumptions.
- Per-token rate-limit accounting on top of upstream signals — out of scope per spec Assumptions.
- Multi-tenant admin patterns (shared connections across users, team RBAC, billing) — out of scope per Q2 product positioning.

These appear in the spec; they're listed here for completeness so the planner does not accidentally re-introduce them.

## R12. Asana authentication: OAuth 2.0 + Personal Access Token

**Decision**: Two peer auth methods, both first-class:

- **OAuth 2.0**: standard auth-code flow against `https://app.asana.com/-/oauth_authorize` and `https://app.asana.com/-/oauth_token`. Scopes: default Asana OAuth grants full access to the authorizing user's data — Asana does not expose granular OAuth scopes for third-party apps in the same manner as Linear/Jira (the per-resource access control is enforced server-side by the user's existing Asana role/permissions). Refresh tokens are rotated per OAuth 2.0 spec; reuse `injectRefreshCallback` per R5.
- **Personal Access Token (PAT)**: pasted by the admin (`1/...` prefix). Validated by issuing `GET https://app.asana.com/api/1.0/users/me`. On 200 with a non-null `data.gid`, persist with `auth_kind: "token"`. PATs do not expire on a fixed schedule but can be revoked at the source.

OAuth-based connections also resolve and persist the `default_workspace_gid` at connection time (from the `users/me` response after token exchange) so that subsequent ops can default to the right workspace when the agent doesn't supply one explicitly.

**Rationale**: The spec's Q1 clarification commits to both methods. PAT is the lowest-friction onboarding for individual-account users (Sieve's positioning per Q2). OAuth is required for admins acting on behalf of multiple Asana users in the future, even if v1 sticks to one-account-per-connection.

**Alternatives considered**:
- *OAuth-only*: rejected by Q1.
- *App-OAuth-first with PAT as a fallback*: rejected — the spec calls them peer methods, not fallback paths.

**API base URL**: `https://app.asana.com/api/1.0` for both auth methods. Overridable via `_base_url` for tests.

**Curated operations**: list_workspaces, list_users, list_projects, list_tasks (project-scoped), get_task, create_task, update_task, add_comment. See `contracts/asana.md` for parameter and result shapes.

**Rich-text fields**: Asana stores task notes in two fields — `notes` (plain text) and `html_notes` (HTML). When the admin's task contains rich text, the `html_notes` field is canonical. The connector exposes both `notes` (raw HTML when html_notes is set, else the plain `notes` value) and `notes_text` (rendered plain text from html_notes via a small html-to-text helper). See R14 for the rendering rule.

## R13. Pagination normalization across connectors (FR-014)

**Decision**: Every curated `list_*` operation accepts the input parameters:

- `cursor` (string, optional) — opaque value; on first call, omitted; on subsequent calls, the value of the previous response's `next_cursor`.
- `page_size` (int, optional) — default 100, hard cap 100. Values >100 are silently capped.

And returns the response shape:

```json
{ "items": [ ... ], "next_cursor": "" }
```

Where `next_cursor == ""` (or null) signals the end of the dataset.

**Per-connector translation** (lives in `internal/connectors/<name>/pagination.go`):

| Service | Normalized cursor → upstream | Upstream end-of-pages → `next_cursor: ""` |
|---------|------------------------------|--------------------------------------------|
| Slack | upstream uses `cursor` (string) and `response_metadata.next_cursor` — pass-through verbatim | `response_metadata.next_cursor == ""` or absent |
| Linear | upstream uses Relay `after` (string) and `pageInfo.endCursor` — pass `cursor` as `after` | `pageInfo.hasNextPage == false` |
| Jira | upstream uses `startAt` (int) + `maxResults` (int); compute `next_cursor` = `strconv.Itoa(startAt + len(issues))` if `startAt + len < total` else `""`; on input parse cursor as int with fallback to 0 | `startAt + len(issues) >= total` |
| Asana | upstream uses `offset` (string) + `limit` (int); pass `cursor` as `offset`; `next_page.offset` from response becomes `next_cursor` | `next_page == null` |

The connector MUST NOT auto-paginate — exactly one upstream page per call so the policy pipeline can gate per page.

**Rationale**: Cursor pass-through is the standard agent-tool pattern; agents and policies see one page at a time, which keeps payloads bounded and allows per-page response filtering (Principle V — Simplicity; no new abstraction). Normalizing the param names (`cursor`/`page_size`) means agents writing policies don't need four service-specific paging vocabularies. The translation tables are small and live in one file per connector.

**Alternatives considered**:
- *Auto-paginate up to N items*: rejected (Q3 2026-05-01, Option A) — risk of unbounded memory and audit-log volume.
- *First-page-only*: rejected — silent data loss.
- *Pass through native paging vocabulary per service*: rejected — burdens agents with per-service paging knowledge for marginal flexibility gain.

## R14. Rich-text round-trip for Jira and Asana (FR-015)

**Decision**: Operations on Jira and Asana that read or write long-form rich-text fields use a dual-representation contract.

**Jira (ADF — Atlassian Document Format):**
- *Reads* (`get_issue`, `search_issues` with `fields` including description/comments): the connector returns the issue object with `description` (raw ADF JSON tree from upstream) AND a synthesized `description_text` (best-effort plain-text rendering). Same dual shape for `comment.body` (ADF) and `comment.body_text` (plain text).
- *Writes* (`create_issue`, `update_issue`, `add_comment`): agents pass plain text in the existing `description` / `body` parameter; the connector wraps it in a minimal ADF doc node tree before calling Jira (the existing `textToADF` helper).
- *ADF-tree-walk-to-text*: a 30-line recursive helper in `internal/connectors/jira/adf.go`. Walk the `content` array, concatenate `text` nodes, insert `\n\n` between paragraph breaks, render `mention` nodes as `@<displayName>`, render `inlineCard` as the bare URL, render `codeBlock` as fenced text. Intentionally lossy on tables, panels, status lozenges (those keep the structural form in the native `description` field for agents that want them).

**Asana (HTML in `html_notes`):**
- *Reads*: `get_task` and `list_tasks` (when `opt_fields` requests `html_notes` or by default) return the task with `notes` (raw HTML when `html_notes` is set, else plain `notes`) AND a synthesized `notes_text` (best-effort plain-text rendering of `html_notes`). Same shape for `comment.html_text` ↔ `comment.html_text_text`.
- *Writes* (`create_task`, `update_task`, `add_comment`): agents pass plain text in `notes`; the connector sends it as the upstream `notes` field. If the agent explicitly wants HTML formatting, they use the underscore-prefixed `_html_notes` parameter, which the connector forwards as `html_notes`. (Documented in `contracts/asana.md` as an advanced option.)
- *HTML-to-text helper*: small wrapper in `internal/connectors/asana/richtext.go` over `golang.org/x/net/html` (already an indirect dep of `net/http`); strips tags, renders `<a>` as `text (href)`, collapses whitespace, preserves paragraph breaks.

**Rationale**: Plain-text-only would lose mentions/attachments/code/tables (information policies care about). Native-only would force every agent that just wants "what does this issue say" to walk a JSON tree. Dual representation is two extra fields on the response shape and ~50 lines of helper code total; it follows constitutional Principle V ("three similar lines beat a premature abstraction").

**Test coverage** lives in `internal/connectors/jira/adf_test.go` and `internal/connectors/asana/richtext_test.go` with table-driven cases for: empty doc, paragraphs, bullets, mentions, code blocks, links, malformed input.

**Alternatives considered**:
- *Plain text only* (lossy on reads): rejected per FR-015.
- *Native rich-text only*: rejected — pushes the parsing burden onto every agent.
- *Connector-configurable per-connection toggle*: rejected — doubles the contract surface for marginal benefit.
