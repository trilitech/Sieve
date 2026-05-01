---

description: "Task list for the Slack / Linear / Jira Cloud / Asana connectors feature"
---

# Tasks: Slack, Linear, Jira, and Asana Connectors

**Input**: Design documents from `/specs/001-slack-linear-jira-connectors/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Included. Sieve is a security-sensitive credential gateway and every existing connector ships with unit + integration tests; new connectors must match. Per-connector test tasks live inside each story phase.

**Organization**: Tasks are grouped by user story (US1 Slack P1, US2 Linear P2, US3 Jira Cloud P3, US4 Asana P4) so each story can be implemented, tested, and shipped independently.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: User story label (US1, US2, US3, US4) — Setup / Foundational / Polish phases have no story label
- Include exact file paths in descriptions

## Path Conventions

Single-Go-service layout already in place. New code lives under `internal/connectors/<name>/`, `internal/web/`, `internal/testing/`, and `docs/`. See `plan.md` § Project Structure for the full tree.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Create directory skeletons and verify the baseline. Project is already initialized; this phase is intentionally minimal.

- [ ] T001 Create empty package directories `internal/connectors/slack/`, `internal/connectors/linear/`, `internal/connectors/jira/`, `internal/connectors/asana/`, `internal/testing/mockslack/`, `internal/testing/mocklinear/`, `internal/testing/mockjira/`, `internal/testing/mockasana/`, and placeholder doc files `docs/connectors-slack.md`, `docs/connectors-linear.md`, `docs/connectors-jira.md`, `docs/connectors-asana.md`
- [ ] T002 [P] Verify the baseline is green by running `go test ./...` and `npx playwright test` from the repo root and recording the pre-feature pass count for regression comparison

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Add the cross-cutting `Connection.Status` field and the migration that applies to **all** connector types, plus the refresh-token rotation persistence rule (FR-016) that the OAuth-rotating connectors (US2 Linear, US3 Jira, US4 Asana) depend on. Every user story below transitions a connection's status on terminal-auth errors and reads it via `GetConnector`, so this phase MUST complete before any of US1/US2/US3/US4.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete and Foundational tests pass.

### Status field

- [X] T003 Add idempotent migration `ALTER TABLE connections ADD COLUMN status TEXT NOT NULL DEFAULT 'active'` (gated by `columnExists("connections", "status")`) to `migrate()` in `internal/database/database.go`
- [X] T004 Add `Status string` field to the `Connection` struct in `internal/connections/connections.go`, update every SELECT and INSERT in that file (`Add`, `Get`, `GetWithConfig`, `List`, `InitAll`) to include the column, and add a package-level `validateStatus(s string) error` helper accepting only `active`, `reauth_required`, `disabled`
- [X] T005 Add `Service.SetStatus(id, status string) error` method in `internal/connections/connections.go` performing `UPDATE connections SET status = ? WHERE id = ?` after validation; does not require keyring
- [X] T006 Define `ErrReauthRequired` and `ErrConnectionDisabled` sentinels in `internal/connections/connections.go` and short-circuit them at the top of `Service.GetConnector` based on the loaded row's status (block any non-`active` status before instantiating the live connector)
- [X] T007 [P] Add `TestMigrate_StatusColumn_FreshDB` and `TestMigrate_StatusColumn_PreExistingRowsDefaultActive` in `internal/database/database_test.go`
- [X] T008 [P] Add `TestService_SetStatus_HappyPath`, `TestService_SetStatus_RejectsUnknownValue`, and `TestService_GetConnector_BlocksOnReauthRequired`, `TestService_GetConnector_BlocksOnDisabled` in `internal/connections/connections_test.go`

### Refresh-token rotation persistence (FR-016)

- [X] T009 Modify `injectRefreshCallback` in `internal/connections/connections.go` so that when the persist of a rotated refresh token fails (any error from `UpdateConfig`), the connection's `status` is transitioned to `reauth_required` via `SetStatus(id, "reauth_required")` BEFORE the error is returned to the caller. The status transition MUST be best-effort (if `SetStatus` itself fails, log and return the original persist error — do not mask it)
- [X] T010 [P] Add `TestInjectRefreshCallback_PersistFailure_TransitionsToReauthRequired` and `TestInjectRefreshCallback_PersistSuccess_LeavesStatusActive` in `internal/connections/refresh_test.go` (NEW file). The persist-failure test injects a stub `UpdateConfig` that returns an error and asserts the row's `status` lands in `reauth_required`

### Status surfacing on API/Web/MCP

- [X] T011 Surface `status` in JSON responses for the connections list endpoint in `internal/api/router.go` (verify the existing handler serializes `Connection` with the new field — adjust any explicit field allow-list)
- [X] T012 Surface `status` in admin UI handlers in `internal/web/server.go` (`handleConnections` JSON + connection-detail handlers); add a status-badge render in `internal/web/templates/connections.html` (or whichever template currently renders the connections list)
- [X] T013 Add admin endpoints `POST /connections/{id}/disable` and `POST /connections/{id}/enable` in `internal/web/server.go`, both gated by the existing `rejectIfAgentToken` middleware; calls `Service.SetStatus`
- [X] T014 [P] Add `TestServer_DisableConnection_RejectsAgentToken` and `TestServer_DisableEnable_HappyPath` in `internal/web/server_test.go`
- [X] T015 Map `ErrReauthRequired` → HTTP 403 `{"error": "reauth_required", "message": "..."}` and `ErrConnectionDisabled` → HTTP 403 `{"error": "disabled", "message": "..."}` in `internal/api/router.go` and `internal/mcp/server.go` so all four new connectors inherit the behavior automatically without per-connector code
- [X] T016 [P] Add `TestRouter_ReauthRequired_Returns403` and `TestRouter_Disabled_Returns403` in `internal/api/router_test.go` using a test connector that always returns the sentinel
- [X] T017 [P] Add `TestMCP_ReauthRequired_Surface` covering the same in `internal/mcp/server_test.go`

**Checkpoint**: Foundation ready. `go test ./internal/database ./internal/connections ./internal/api ./internal/mcp ./internal/web` is green. SC-008 (existing connections migrate to `active`) is verified by T007. FR-016 regression coverage is verified by T010. User story implementation can begin.

---

## Phase 3: User Story 1 — Slack workspace as a managed connector (Priority: P1) 🎯 MVP

**Goal**: An admin can connect a Slack workspace via OAuth or by pasting a bot token. An agent token bound to that connection can call the curated Slack operations subject to policy, with audit logging, normalized cursor pagination (FR-014), and reauth-required status transition on revocation. Slack uses classic non-rotating bot scopes per Q2 2026-05-01 — no refresh-token code path.

**Independent Test**: Add a Slack connection to a test workspace through the admin UI, issue a sub-token with a "post to #bot-test only" rules policy, verify post to `#bot-test` succeeds, verify post to `#general` is denied, paginate `slack.list_channels` past 100 channels using `next_cursor`, revoke the upstream install and verify the next call returns `reauth_required` and the admin UI shows that status. No Linear, Jira, or Asana work is required.

### Tests for User Story 1

> Write these tests FIRST, ensure they FAIL before implementation.

- [ ] T018 [P] [US1] Contract tests for the 7 Slack operations in `internal/connectors/slack/ops_test.go`, asserting the param/result shapes from `contracts/slack.md` against `internal/testing/mockslack`, including the normalized `{items, next_cursor}` shape on `list_channels` and `list_users`
- [ ] T019 [P] [US1] Pagination translation table-test in `internal/connectors/slack/pagination_test.go` covering: empty `cursor` → no upstream cursor; opaque `cursor` → upstream `cursor` verbatim; upstream `response_metadata.next_cursor == ""` → normalized `next_cursor == ""`; upstream `next_cursor == "dXNlcjpVMDYxTkZUVDI="` → normalized `next_cursor` verbatim
- [ ] T020 [P] [US1] Validate test in `internal/connectors/slack/validate_test.go` covering happy path (`auth.test` returns `ok: true`) and terminal-auth response (`ok: false, error: "invalid_auth"`)
- [ ] T021 [P] [US1] Terminal-auth classifier table-test in `internal/connectors/slack/auth_test.go` covering `invalid_auth`, `token_revoked`, `account_inactive`, `not_authed` → true; `rate_limited`, 5xx, network → false
- [ ] T022 [P] [US1] Web handler tests in `internal/web/slack_test.go` covering OAuth start (state generation + redirect), OAuth callback success, OAuth callback with expired state, direct bot-token entry validation
- [ ] T023 [P] [US1] e2e Playwright group "Slack connector" in `e2e/web-ui.spec.ts` covering: add via OAuth → status active; add via bot token → status active; revoked-token call → status reauth_required and UI badge updates within 60s; cursor pagination works through 2+ pages of mocked channels

### Implementation for User Story 1

- [ ] T024 [P] [US1] Add `SLACK_CLIENT_ID` / `SLACK_CLIENT_SECRET` settings keys to `internal/settings/settings.go` (or wherever existing OAuth client settings live; mirror the GitHub/Google pattern)
- [ ] T025 [P] [US1] Implement mock Slack server in `internal/testing/mockslack/server.go` exposing `httptest.NewServer` with handlers for `auth.test`, `conversations.list`, `conversations.history`, `conversations.replies`, `search.messages`, `chat.postMessage`, `users.list`, `users.profile.get`; supports a `forceError(code)` toggle for terminal-auth simulation; `conversations.list` and `users.list` honour `cursor` / page-size for pagination tests
- [ ] T026 [P] [US1] Define `Config` struct + `parseConfig` + `validate()` in `internal/connectors/slack/config.go` per `data-model.md` § Slack Connection Config (auth_kind discriminator, OAuth + token branches)
- [ ] T027 [P] [US1] Implement `isTerminalAuthError` classifier in `internal/connectors/slack/auth.go` per `research.md` R10
- [ ] T028 [P] [US1] Implement pagination translation in `internal/connectors/slack/pagination.go` per `research.md` R13 (Slack table row): pass `cursor` through verbatim as Slack `cursor`; pass `page_size` as Slack `limit`; map `response_metadata.next_cursor` to normalized `next_cursor`
- [ ] T029 [US1] Implement HTTP client wrapper in `internal/connectors/slack/client.go` (resolves auth headers from `Config.AuthKind`, accepts `_base_url` override for tests, applies `isTerminalAuthError` and calls `connections.Service.SetStatus(id, "reauth_required")` on hit) — depends on T026, T027
- [ ] T030 [US1] Implement `Operations()` table and `Execute(ctx, op, params)` dispatch in `internal/connectors/slack/ops.go` per `contracts/slack.md` (7 operations: list_channels, list_users, read_user_profile, read_channel_history, read_thread, search_messages, post_message); `list_*` ops use the FR-014 normalized shape via `pagination.go`; `search_messages` returns the `operation_not_enabled` shape per research R1a when scope absent — depends on T028, T029
- [ ] T031 [US1] Implement `Validate(ctx)` calling Slack `auth.test` in `internal/connectors/slack/validate.go` — depends on T029
- [ ] T032 [US1] Implement `Connector` struct + `Meta` + `Factory` in `internal/connectors/slack/slack.go`; registers Type `"slack"`, Category `"Communication"`, SetupFields covering both auth paths. No `_on_token_refresh` wiring (Slack classic bot scopes don't rotate per Q2 2026-05-01) — depends on T026, T029, T030, T031
- [ ] T033 [US1] Register the Slack connector in `cmd/sieve/main.go` and `e2e/testserver/main.go` connector registry initialization — depends on T032
- [ ] T034 [US1] Implement `handleSlackOAuthStart` and direct-token entry handler `handleSlackToken` in `internal/web/slack.go` (mirrors `internal/web/github.go` shape; uses `pendingOAuth` map keyed by random state with the existing 10-minute TTL) — depends on T024, T032
- [ ] T035 [US1] Extend `handleOAuthCallback` in `internal/web/server.go` to dispatch on `provider=slack` query param, calling Slack's `oauth.v2.access` endpoint and persisting the resulting Config via `connections.Service.UpdateConfig` then `SetStatus(id, "active")` — depends on T034
- [ ] T036 [US1] Add reauth/refresh handler `handleSlackReauth` in `internal/web/slack.go` that re-runs the OAuth start (or accepts a fresh token) and on success calls `Service.SetStatus(id, "active")` — depends on T034
- [ ] T037 [US1] Register the Slack web handlers in `Server.Routes()` in `internal/web/server.go`, all gated by `rejectIfAgentToken` — depends on T034, T035, T036
- [ ] T038 [P] [US1] Author `docs/connectors-slack.md` per `quickstart.md` and `research.md` R1 (prereqs, OAuth path, token path, scope table, troubleshooting, normalized cursor pagination notes)

**Checkpoint**: Slack connector functional independently. MVP complete: a user can install the binary, set up Slack via OAuth or token, attach to a role, and an agent can list/post/search subject to policy with normalized pagination. SC-001 (10-min setup), SC-005 (zero plaintext credentials), and SC-007 (60s reauth detection) are verified by the quickstart walkthrough and the e2e test.

---

## Phase 4: User Story 2 — Linear organization as a managed connector (Priority: P2)

**Goal**: An admin can connect a Linear organization via OAuth 2.0 or by pasting a personal API key. Agents can list/get/create/update issues with response-filter policies redacting confidential fields. Linear OAuth uses rotating refresh tokens per FR-016.

**Independent Test**: Connect a test Linear org, attach a script policy that redacts `customer:\w+` to `[REDACTED]` from issue descriptions, query an issue containing `customer:acme`, verify the agent receives the redacted version while the audit log shows the original was filtered. Independent from Slack, Jira, and Asana.

### Tests for User Story 2

- [ ] T039 [P] [US2] Contract tests for the 7 Linear operations in `internal/connectors/linear/ops_test.go` against `internal/testing/mocklinear`, including normalized `{items, next_cursor}` on `list_issues`, `list_users`, `list_teams`
- [ ] T040 [P] [US2] Pagination translation table-test in `internal/connectors/linear/pagination_test.go`: empty `cursor` → no upstream `after`; cursor passed through as Relay `after`; `pageInfo.hasNextPage == false` → `next_cursor == ""`; `endCursor` value pass-through
- [ ] T041 [P] [US2] Validate test in `internal/connectors/linear/validate_test.go` covering happy path (`viewer { id email }` returns non-null) and terminal-auth (`AUTHENTICATION_ERROR` extension code)
- [ ] T042 [P] [US2] Terminal-auth classifier table-test in `internal/connectors/linear/auth_test.go` (HTTP 401, GraphQL `extensions.code == "AUTHENTICATION_ERROR"`)
- [ ] T043 [P] [US2] Refresh-token persist-failure test in `internal/connectors/linear/refresh_test.go`: drives a token refresh through the connector with a stubbed-failure persistence layer and asserts the connection lands in `reauth_required` with a non-secret error returned to the caller (per FR-016)
- [ ] T044 [P] [US2] Web handler tests in `internal/web/linear_test.go` covering OAuth start, OAuth callback, API-key entry validation
- [ ] T045 [P] [US2] e2e Playwright group "Linear connector" in `e2e/web-ui.spec.ts`: add via OAuth, add via API key, response-filter policy redaction (acceptance scenario US2.2), status reauth transition on revoked credential, cursor pagination through `list_issues`

### Implementation for User Story 2

- [ ] T046 [P] [US2] Add `LINEAR_CLIENT_ID` / `LINEAR_CLIENT_SECRET` settings keys to `internal/settings/settings.go`
- [ ] T047 [P] [US2] Implement mock Linear GraphQL server in `internal/testing/mocklinear/server.go` (single `/graphql` endpoint dispatching on operation name: `viewer`, `teams`, `users`, `issues`, `issue`, `issueCreate`, `issueUpdate`, `commentCreate`); supports `forceError("AUTHENTICATION_ERROR")` toggle and Relay-style `pageInfo` for paginated queries
- [ ] T048 [P] [US2] Define `Config` struct + `parseConfig` + `validate()` in `internal/connectors/linear/config.go` per `data-model.md` § Linear Connection Config
- [ ] T049 [P] [US2] Implement `isTerminalAuthError` classifier in `internal/connectors/linear/auth.go`
- [ ] T050 [P] [US2] Implement pagination translation in `internal/connectors/linear/pagination.go` per `research.md` R13 (Linear table row): cursor → Relay `after`; `pageInfo.endCursor` → `next_cursor`; `hasNextPage == false` → `next_cursor == ""`
- [ ] T051 [US2] Implement GraphQL client wrapper in `internal/connectors/linear/client.go` (auth header per `AuthKind`: `Authorization: Bearer <oauth>` or `Authorization: <api_key>` (no Bearer prefix per Linear docs); `_base_url` override; `isTerminalAuthError` → `SetStatus("reauth_required")`; for OAuth mode, wires `injectRefreshCallback` so rotated refresh tokens are persisted per FR-016) — depends on T048, T049, T050
- [ ] T052 [US2] Implement `Operations()` + `Execute` dispatch in `internal/connectors/linear/ops.go` per `contracts/linear.md` (7 operations); `list_*` ops use the normalized FR-014 shape via `pagination.go` — depends on T051
- [ ] T053 [US2] Implement `Validate(ctx)` issuing `query { viewer { id email } }` in `internal/connectors/linear/validate.go` — depends on T051
- [ ] T054 [US2] Implement `Connector` + `Meta` + `Factory` in `internal/connectors/linear/linear.go` wiring `_on_token_refresh` (Linear OAuth has rotating refresh tokens per FR-016) — depends on T048, T051, T052, T053
- [ ] T055 [US2] Register the Linear connector in `cmd/sieve/main.go` and `e2e/testserver/main.go` — depends on T054
- [ ] T056 [US2] Implement `handleLinearOAuthStart` and `handleLinearAPIKey` in `internal/web/linear.go` — depends on T046, T054
- [ ] T057 [US2] Extend `handleOAuthCallback` in `internal/web/server.go` to dispatch on `provider=linear`, exchanging the auth code at `https://api.linear.app/oauth/token` and persisting the result — depends on T056
- [ ] T058 [US2] Add reauth handler `handleLinearReauth` in `internal/web/linear.go` — depends on T056
- [ ] T059 [US2] Register the Linear web handlers in `Server.Routes()` in `internal/web/server.go`, all gated by `rejectIfAgentToken` — depends on T056, T057, T058
- [ ] T060 [P] [US2] Author `docs/connectors-linear.md` per `quickstart.md` and `research.md` R2

**Checkpoint**: Linear connector functional independently. Acceptance scenario US2.2 (response-filter redaction) demonstrably works. Refresh-rotation persistence verified.

---

## Phase 5: User Story 3 — Jira Cloud site as a managed connector (Priority: P3)

**Goal**: An admin can connect an Atlassian Cloud Jira site via OAuth 2.0 (3LO) or by pasting an Atlassian API token + email. Agents can search/get/create/update/transition/comment on issues subject to policy. Jira OAuth uses rotating refresh tokens (90-day TTL) per FR-016. Read operations return ADF native + plain-text companion fields per FR-015.

**Independent Test**: Connect a test Jira Cloud site, scope a role to project `BOT`, run a JQL search across all projects through the agent, verify only `BOT` issues are returned and the audit log records the policy-driven scoping. Verify `get_issue` returns both `description` (ADF) and `description_text` (plain text). Verify a refresh-token rotation persists correctly across sequential calls.

### Tests for User Story 3

- [ ] T061 [P] [US3] Contract tests for the 7 Jira operations in `internal/connectors/jira/ops_test.go` against `internal/testing/mockjira` (search w/ JQL, get, create, update, transition, add_comment, list_transitions); `search_issues` and `get_issue` results carry both `description`/`comment.body` (ADF) AND `description_text`/`comment.body_text` (plain) per FR-015
- [ ] T062 [P] [US3] Pagination translation table-test in `internal/connectors/jira/pagination_test.go`: empty `cursor` → upstream `startAt = 0`; numeric `cursor` → `startAt`; `startAt + len(issues) < total` → `next_cursor` is `strconv.Itoa(startAt + len)`; `startAt + len >= total` → `next_cursor == ""`; non-numeric `cursor` → falls back to `startAt = 0` with a clear error
- [ ] T063 [P] [US3] ADF helper test in `internal/connectors/jira/adf_test.go`: `textToADF` produces a minimal `{type:"doc", version:1, content:[{type:"paragraph", content:[{type:"text", text:"..."}]}]}` for plain text. `adfToText` (NEW) renders empty doc → `""`, paragraphs → joined with `\n\n`, mentions → `@displayName`, code blocks → fenced text, inline cards → bare URL; lossy on tables/panels (asserts the lossy fields are absent in the text output)
- [ ] T064 [P] [US3] Validate test in `internal/connectors/jira/validate_test.go` covering both auth modes (`/rest/api/3/myself` returns `accountId`)
- [ ] T065 [P] [US3] Terminal-auth classifier test in `internal/connectors/jira/auth_test.go` (HTTP 401 with WWW-Authenticate, HTTP 403 with token-revoked body)
- [ ] T066 [P] [US3] cloudId resolution test in `internal/connectors/jira/cloudid_test.go` covering OAuth path (`accessible-resources` returns single resource, returns multiple, returns empty) and basic-auth path (`serverInfo` returns cloudId)
- [ ] T067 [P] [US3] Refresh-token persist-failure test in `internal/connectors/jira/refresh_test.go` (per FR-016, mirrors T043)
- [ ] T068 [P] [US3] Web handler tests in `internal/web/jira_test.go` covering OAuth start, OAuth callback with cloudId resolution, API-token entry validation
- [ ] T069 [P] [US3] e2e Playwright group "Jira connector" in `e2e/web-ui.spec.ts`: add via OAuth (mock 3LO including accessible-resources), add via API token, project-scoped JQL policy (acceptance scenario US3.2), status reauth transition, FR-014 cursor pagination, FR-015 ADF + description_text round-trip on `get_issue`

### Implementation for User Story 3

- [ ] T070 [P] [US3] Add `JIRA_CLIENT_ID` / `JIRA_CLIENT_SECRET` settings keys to `internal/settings/settings.go`
- [ ] T071 [P] [US3] Implement mock Jira server in `internal/testing/mockjira/server.go` covering `/oauth/token/accessible-resources`, `/ex/jira/{cloudId}/rest/api/3/myself`, `/rest/api/3/serverInfo` (basic-auth path), `/rest/api/3/search`, `/rest/api/3/issue/{key}`, `/rest/api/3/issue` (POST), `/rest/api/3/issue/{key}/transitions`, `/rest/api/3/issue/{key}/comment`; supports `forceError(401)` and `forceError(403)`; search and issue responses include ADF-shaped descriptions and comment bodies for FR-015 testing; supports `startAt`/`maxResults` paging
- [ ] T072 [P] [US3] Define `Config` struct + `parseConfig` + `validate()` in `internal/connectors/jira/config.go` per `data-model.md` § Jira Cloud Connection Config (must validate `SiteURL` matches `https://*.atlassian.net` for token mode)
- [ ] T073 [P] [US3] Implement `isTerminalAuthError` classifier in `internal/connectors/jira/auth.go`
- [ ] T074 [P] [US3] Implement ADF helpers in `internal/connectors/jira/adf.go`: `textToADF(s string) map[string]any` (write direction — wraps plain text in a minimal ADF doc); `adfToText(node map[string]any) string` (read direction — recursive tree-walk per FR-015 / R14: paragraphs → `\n\n`, mentions → `@displayName`, code blocks → fenced, inline cards → URL, lossy on tables/panels/status)
- [ ] T075 [P] [US3] Implement pagination translation in `internal/connectors/jira/pagination.go` per `research.md` R13 (Jira table row): parse `cursor` as int with fallback to 0 (translates to upstream `startAt`); compute `next_cursor` = `strconv.Itoa(startAt + len)` if `startAt + len < total`, else `""`
- [ ] T076 [US3] Implement HTTP client wrapper in `internal/connectors/jira/client.go` (auth header per `AuthKind`: `Authorization: Bearer <oauth>` for OAuth or `Authorization: Basic <base64(email:api_token)>` for token; base URL = `https://api.atlassian.com/ex/jira/{CloudID}` for OAuth or `<SiteURL>` for token; `_base_url` override; `isTerminalAuthError` → `SetStatus("reauth_required")`; OAuth mode wires `injectRefreshCallback` per FR-016) — depends on T072, T073
- [ ] T077 [US3] Implement cloudId resolver in `internal/connectors/jira/cloudid.go` (OAuth: GET `https://api.atlassian.com/oauth/token/accessible-resources`; token: GET `<SiteURL>/rest/api/3/serverInfo`) — depends on T076
- [ ] T078 [US3] Implement `Operations()` + `Execute` dispatch in `internal/connectors/jira/ops.go` per `contracts/jira.md` (7 operations); `search_issues` uses normalized FR-014 shape via `pagination.go`; `get_issue` and `search_issues` results call `adfToText` to populate `description_text` / `comment.body_text` per FR-015 — depends on T074, T075, T076
- [ ] T079 [US3] Implement `Validate(ctx)` calling `GET /rest/api/3/myself` and asserting `accountId` non-empty in `internal/connectors/jira/validate.go` — depends on T076, T077
- [ ] T080 [US3] Implement `Connector` + `Meta` + `Factory` in `internal/connectors/jira/jira.go` wiring `_on_token_refresh` (Jira OAuth has rotating refresh tokens per FR-016) — depends on T072, T076, T077, T078, T079
- [ ] T081 [US3] Register the Jira connector in `cmd/sieve/main.go` and `e2e/testserver/main.go` — depends on T080
- [ ] T082 [US3] Implement `handleJiraOAuthStart` and `handleJiraAPIToken` in `internal/web/jira.go` (token path collects email + API token + site URL in one form) — depends on T070, T080
- [ ] T083 [US3] Extend `handleOAuthCallback` in `internal/web/server.go` to dispatch on `provider=jira`, exchanging auth code at `https://auth.atlassian.com/oauth/token`, then calling the cloudId resolver before persisting — depends on T077, T082
- [ ] T084 [US3] Add reauth handler `handleJiraReauth` in `internal/web/jira.go` — depends on T082
- [ ] T085 [US3] Register the Jira web handlers in `Server.Routes()` in `internal/web/server.go`, all gated by `rejectIfAgentToken` — depends on T082, T083, T084
- [ ] T086 [P] [US3] Author `docs/connectors-jira.md` per `quickstart.md` and `research.md` R3 + R14 (ADF round-trip explanation, when to use `description` vs `description_text`)

**Checkpoint**: Jira Cloud connector functional independently. Acceptance scenarios US3.1–US3.3 pass. FR-014 pagination, FR-015 ADF round-trip, FR-016 refresh persistence all verified.

---

## Phase 6: User Story 4 — Asana workspace as a managed connector (Priority: P4)

**Goal**: An admin can connect an Asana workspace via OAuth 2.0 or by pasting a Personal Access Token. Agents can list/get/create/update tasks and add comments subject to policy, with normalized cursor pagination (FR-014), HTML+plain-text companion fields on rich-text reads (FR-015), and rotating-refresh-token persistence (FR-016).

**Independent Test**: Connect a test Asana workspace, scope a role to a single project GID, confirm `asana.list_tasks` for that project succeeds and for a different project is denied. Verify `get_task` returns both `notes` (HTML or plain) and `notes_text` (plain). Independent from Slack, Linear, and Jira.

### Tests for User Story 4

- [ ] T087 [P] [US4] Contract tests for the 8 Asana operations in `internal/connectors/asana/ops_test.go` against `internal/testing/mockasana` (list_workspaces, list_users, list_projects, list_tasks, get_task, create_task, update_task, add_comment); `list_*` ops carry the FR-014 normalized shape; `get_task` and `list_tasks` carry `notes` AND `notes_text` per FR-015
- [ ] T088 [P] [US4] Pagination translation table-test in `internal/connectors/asana/pagination_test.go`: cursor passed through as Asana `offset`; `next_page.offset` → `next_cursor`; `next_page == null` → `next_cursor == ""`; respects `page_size` cap of 100 (translated to upstream `limit`)
- [ ] T089 [P] [US4] Rich-text helper test in `internal/connectors/asana/richtext_test.go`: `htmlToText` covers empty body → `""`; `<p>foo</p>` → `"foo"`; `<a href="https://example.com">x</a>` → `"x (https://example.com)"`; `<b>` and `<i>` flatten; `&amp;` decodes; malformed HTML (unclosed tags) renders best-effort without panic
- [ ] T090 [P] [US4] Validate test in `internal/connectors/asana/validate_test.go` covering happy path (`/users/me` returns `data.gid`) and terminal-auth (HTTP 401 with `Not Authorized` body)
- [ ] T091 [P] [US4] Terminal-auth classifier table-test in `internal/connectors/asana/auth_test.go` (HTTP 401 + `Not Authorized`, HTTP 403 + `deleted token`, HTTP 403 + `invalid_grant`)
- [ ] T092 [P] [US4] Refresh-token persist-failure test in `internal/connectors/asana/refresh_test.go` (per FR-016, mirrors T043/T067)
- [ ] T093 [P] [US4] Workspace resolution test in `internal/connectors/asana/workspace_test.go`: `/users/me?opt_fields=...` returning a single workspace lands in `default_workspace_gid`; multiple workspaces with explicit admin selection persists the chosen one; multiple workspaces without selection falls back to the first
- [ ] T094 [P] [US4] Web handler tests in `internal/web/asana_test.go` covering OAuth start, OAuth callback (workspace resolution), PAT entry validation
- [ ] T095 [P] [US4] e2e Playwright group "Asana connector" in `e2e/web-ui.spec.ts`: add via OAuth (mock OAuth + workspace resolution), add via PAT, project-scoped policy (acceptance scenario US4.3), status reauth transition on revoked PAT, FR-014 cursor pagination through `list_tasks`, FR-015 `notes` + `notes_text` round-trip on `get_task`

### Implementation for User Story 4

- [ ] T096 [P] [US4] Add `ASANA_CLIENT_ID` / `ASANA_CLIENT_SECRET` settings keys to `internal/settings/settings.go`
- [ ] T097 [P] [US4] Implement mock Asana server in `internal/testing/mockasana/server.go` covering `/users/me`, `/workspaces`, `/users`, `/projects`, `/projects/{gid}/tasks`, `/tasks/{gid}`, `/tasks` (POST), `/tasks/{gid}/stories` (POST for comments), `/-/oauth_token` (refresh); supports `forceError(401)` and `forceError(403)`; tasks responses include `html_notes` for FR-015 testing; honours `offset`/`limit` and emits `next_page.offset`
- [ ] T098 [P] [US4] Define `Config` struct + `parseConfig` + `validate()` in `internal/connectors/asana/config.go` per `data-model.md` § Asana Connection Config (auth_kind discriminator, OAuth + PAT branches, `default_workspace_gid` field)
- [ ] T099 [P] [US4] Implement `isTerminalAuthError` classifier in `internal/connectors/asana/auth.go` per R10 (Asana row)
- [ ] T100 [P] [US4] Implement html-to-text helper in `internal/connectors/asana/richtext.go` using `golang.org/x/net/html` to parse, walk text nodes, render `<a href="...">text</a>` as `"text (href)"`, collapse whitespace, preserve paragraph breaks
- [ ] T101 [P] [US4] Implement pagination translation in `internal/connectors/asana/pagination.go` per `research.md` R13 (Asana table row): cursor → upstream `offset`; `next_page.offset` → `next_cursor`; `next_page == null` → `next_cursor == ""`
- [ ] T102 [P] [US4] Implement workspace resolver in `internal/connectors/asana/workspace.go` (`resolveDefaultWorkspace(ctx, client, explicitGID string) (gid, name string, err error)`)
- [ ] T103 [US4] Implement HTTP client wrapper in `internal/connectors/asana/client.go` (auth header per `AuthKind`: `Authorization: Bearer <oauth>` for OAuth or `Authorization: Bearer <pat>` for PAT — Asana uses Bearer for both; `_base_url` override; `isTerminalAuthError` → `SetStatus("reauth_required")`; OAuth mode wires `injectRefreshCallback` per FR-016) — depends on T098, T099, T101
- [ ] T104 [US4] Implement `Operations()` + `Execute` dispatch in `internal/connectors/asana/ops.go` per `contracts/asana.md` (8 operations); `list_*` ops use the normalized FR-014 shape via `pagination.go`; `get_task` and `list_tasks` call `htmlToText` on `html_notes` to populate `notes_text` per FR-015; `_html_notes` advanced parameter supported on `create_task` / `update_task` / `add_comment` per the contract — depends on T100, T101, T103
- [ ] T105 [US4] Implement `Validate(ctx)` calling `GET /users/me` and asserting `data.gid` non-empty in `internal/connectors/asana/validate.go` — depends on T103
- [ ] T106 [US4] Implement `Connector` + `Meta` + `Factory` in `internal/connectors/asana/asana.go` wiring `_on_token_refresh` (Asana OAuth has rotating refresh tokens per FR-016) and the workspace resolver — depends on T098, T102, T103, T104, T105
- [ ] T107 [US4] Register the Asana connector in `cmd/sieve/main.go` and `e2e/testserver/main.go` — depends on T106
- [ ] T108 [US4] Implement `handleAsanaOAuthStart` and `handleAsanaPAT` in `internal/web/asana.go` — depends on T096, T106
- [ ] T109 [US4] Extend `handleOAuthCallback` in `internal/web/server.go` to dispatch on `provider=asana`, exchanging auth code at `https://app.asana.com/-/oauth_token`, then calling the workspace resolver before persisting — depends on T102, T108
- [ ] T110 [US4] Add reauth handler `handleAsanaReauth` in `internal/web/asana.go` — depends on T108
- [ ] T111 [US4] Register the Asana web handlers in `Server.Routes()` in `internal/web/server.go`, all gated by `rejectIfAgentToken` — depends on T108, T109, T110
- [ ] T112 [P] [US4] Author `docs/connectors-asana.md` per `quickstart.md` and `research.md` R12 + R14 (prereqs, OAuth path, PAT path, curated operations, html_notes round-trip explanation, troubleshooting)

**Checkpoint**: All four connectors functional independently. SC-009 (Asana ships as independent slice) verified — Asana ships without modifying Slack/Linear/Jira code paths.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Validation against measurable success criteria, documentation polish, regression-suite hygiene.

- [ ] T113 [P] Walk through `quickstart.md` end-to-end against the real Slack/Linear/Jira/Asana sandbox accounts (or document with screenshots if real accounts aren't available) to verify SC-001 (10-min setup) for each connector
- [ ] T114 [P] Verify SC-002 (95% workflow coverage) by listing the operations agents most commonly request through the existing HTTP proxy connector against the curated set across all four connectors; document any gap in `research.md` § R11 as a known limitation, not a blocker
- [ ] T115 [P] Verify SC-005 (zero plaintext credentials) by querying `sqlite3 ./data/sieve.db "SELECT id, connector_type FROM connections;"` after each new connector type is created in the test env, confirming the `config_ciphertext` column holds bytes that don't deserialize as JSON without the keyring
- [ ] T116 [P] Update `README.md` to list Slack, Linear, Jira Cloud, and Asana in the connector catalog (move from any "coming soon" markings if present); update the "What Sieve is" intro line that lists supported services
- [ ] T117 [P] Update CLAUDE.md "Conventions worth knowing" with: Slack `search:read` requires user-token install (not currently supported); Slack uses classic non-rotating bot scopes only (per Q2 2026-05-01); Linear OAuth uses `actor=app`; Jira cloudId is resolved at OAuth callback and stored in the encrypted config; Asana resolves `default_workspace_gid` at connection time; the new `connections.status` field is non-secret and returned without keyring decryption; pagination across new connectors uses the normalized `{items, next_cursor}` shape; rich-text round-trip via `*_text` companion fields on Jira/Asana
- [ ] T118 Run `go vet ./... && go test ./... -race` and resolve any warnings or flakiness introduced by the feature
- [ ] T119 Run `npx playwright test e2e/web-ui.spec.ts` three times in a row and confirm zero flakes across the new Slack/Linear/Jira/Asana test groups; if any flake, fix the test (do not retry-loop in CI)
- [ ] T120 [P] Add a one-line entry to `docs/connectors-overview.md` (or equivalent index doc) listing each new connector with a link to its dedicated page

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately.
- **Foundational (Phase 2)**: Depends on Setup completion. **Blocks all user stories** because every connector calls `connections.Service.SetStatus`, reads through `GetConnector`'s status short-circuit, and (for US2/US3/US4) relies on the FR-016 `injectRefreshCallback` modification.
- **User Story 1 / 2 / 3 / 4 (Phases 3–6)**: All depend on Foundational. Once Foundational is done, the four stories are mutually independent and can proceed in parallel by separate developers.
- **Polish (Phase 7)**: Depends on whichever user stories are in scope for the release.

### User Story Dependencies

- **US1 (Slack)**: Depends only on Foundational. No dependency on US2, US3, or US4.
- **US2 (Linear)**: Depends only on Foundational. No dependency on US1, US3, or US4.
- **US3 (Jira Cloud)**: Depends only on Foundational. No dependency on US1, US2, or US4.
- **US4 (Asana)**: Depends only on Foundational. No dependency on US1, US2, or US3.

### Within Each User Story

- Tests (T018–T023 for US1; T039–T045 for US2; T061–T069 for US3; T087–T095 for US4) are written first against the mock servers and assert the contracts; they fail until implementation lands.
- Within implementation: settings + mock + config + auth classifier + pagination.go (+ adf.go / richtext.go where applicable) are independent ([P] across them); client depends on config + classifier + pagination; ops + validate depend on client; the connector main file depends on config + client + ops + validate; web handlers depend on settings + the connector main file; route registration is the final wiring step.
- Docs ([T038] / [T060] / [T086] / [T112]) are independent and can be authored in parallel with the code.

### Parallel Opportunities

- All Foundational tests T007, T008, T010, T014, T016, T017 run in parallel after their respective implementation tasks complete.
- Within a user story, all `[P]` tasks against different files run in parallel (settings, mock server, config, classifier, pagination, rich-text helper, docs).
- Across user stories, after Foundational completes, four developers can take US1, US2, US3, US4 in parallel — there is no shared file conflict between the four connector packages, the four web-handler files, or the four doc pages.
- Polish phase tasks T113–T117 and T120 are all independent and run in parallel.

---

## Parallel Example: User Story 4 (Asana)

```bash
# After Foundational is done, launch all Asana [P] implementation files in parallel:
Task: "Add ASANA_CLIENT_ID/SECRET to internal/settings/settings.go"                  # T096
Task: "Implement mock Asana server in internal/testing/mockasana/server.go"          # T097
Task: "Define Config + validate in internal/connectors/asana/config.go"              # T098
Task: "Implement isTerminalAuthError in internal/connectors/asana/auth.go"           # T099
Task: "Implement htmlToText in internal/connectors/asana/richtext.go"                # T100
Task: "Implement pagination translation in internal/connectors/asana/pagination.go"  # T101
Task: "Implement workspace resolver in internal/connectors/asana/workspace.go"       # T102
Task: "Author docs/connectors-asana.md"                                              # T112

# Then sequentially (each depends on prior):
Task: "Implement HTTP client in internal/connectors/asana/client.go"                  # T103 (depends on T098, T099, T101)
Task: "Implement Operations + Execute in internal/connectors/asana/ops.go"            # T104 (depends on T100, T101, T103)
Task: "Implement Validate in internal/connectors/asana/validate.go"                   # T105 (depends on T103)
Task: "Implement Connector + Factory in internal/connectors/asana/asana.go"           # T106 (depends on T098, T102-T105)
```

The same shape applies to US1, US2, and US3 with the file paths substituted.

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1: Setup (T001, T002).
2. Phase 2: Foundational (T003–T017) — **critical**, blocks everything.
3. Phase 3: Slack (T018–T038).
4. **STOP and VALIDATE**: Run `go test ./...` + `npx playwright test -g Slack`. Walk `quickstart.md` § Slack against a real workspace.
5. Ship the MVP with Slack only. Status migration applies to all existing connectors (Gmail, GitHub, MCP proxy, HTTP proxy) at this point too — verify SC-008. Refresh-rotation hardening (FR-016) lands with Foundational and benefits Gmail too.

### Incremental Delivery

1. Setup + Foundational → status field shipped to existing users; refresh-rotation persistence hardened for Gmail.
2. Add Slack (US1) → ship MVP.
3. Add Linear (US2) → ship.
4. Add Jira Cloud (US3) → ship.
5. Add Asana (US4) → ship.
6. Polish (Phase 7) → final release polish.

Each story adds value without breaking the others. The status field migration and refresh-rotation hardening happen once at the start and are forward-compatible with all subsequent stories.

### Parallel Team Strategy

With four engineers post-Foundational:

- Eng A: US1 Slack (Phase 3).
- Eng B: US2 Linear (Phase 4).
- Eng C: US3 Jira Cloud (Phase 5).
- Eng D: US4 Asana (Phase 6).

The four connector packages, web handler files, mock servers, and doc pages do not collide; Phase 2 is the single integration point and must merge first.

---

## Notes

- `[P]` tasks = different files, no dependencies on incomplete tasks.
- `[Story]` label maps each user-story task to its priority (US1=Slack/P1, US2=Linear/P2, US3=Jira/P3, US4=Asana/P4).
- Each user story is independently completable and testable; cutting any one from a release does not affect the others.
- Tests are written first against mock HTTP servers, asserting the operation contracts in `contracts/`. They fail until the corresponding implementation lands.
- Stop at any checkpoint to validate the story independently against `quickstart.md`.
- Avoid: vague tasks, same-file conflicts (each task names exactly one file or a tightly-grouped set), cross-story dependencies that would break independence.

### Commit hygiene (Constitution Principle III)

Each commit MUST be a self-contained, revertable unit that compiles and passes `go test ./...` on its own.

- **Tests land with the behavior they cover.** The Slack contract tests (T018) and the implementation that satisfies them (T030) ship in the same commit (or with the failing test in an immediately-preceding commit on the same branch). The same rule applies to Linear (T039 ↔ T052), Jira (T061 ↔ T078), and Asana (T087 ↔ T104).
- **Commit boundaries follow logical units, not task IDs.** Suggested grouping:
  1. *Schema slice (Foundational only):* T003 + T004 + T005 + T006 + T007 + T008 — one commit. Adds the `status` column, the model field, the SetStatus method, the GetConnector short-circuit, and their tests. After this commit, `go test ./internal/database ./internal/connections` is green and pre-existing connections are intact (SC-008).
  2. *Refresh-rotation hardening (Foundational only):* T009 + T010 — one commit. Modifies `injectRefreshCallback` for FR-016 status-on-failure transition, with the regression test. Benefits Gmail immediately.
  3. *API/MCP/Web surfacing of status (Foundational only):* T011 + T012 + T013 + T014 + T015 + T016 + T017 — one commit. Adds the JSON serialization, the badge rendering for **all** connector types, the disable/enable endpoints, and the sentinel-to-403 mapping with their tests.
  4. *Per-connector slice* (Slack / Linear / Jira / Asana each shipping the same shape):
     - Commit A: settings + mock server + config + auth classifier + pagination.go (+ adf.go / richtext.go where applicable) + their unit tests. All `[P]` tasks within the slice.
     - Commit B: client + ops + validate + their contract tests.
     - Commit C: connector main file + registration + web handlers + routes + their handler tests.
     - Commit D: e2e Playwright tests + docs.
- **Rules per commit (constitutional, non-negotiable):**
  - MUST compile and pass `go test ./...` standalone — no broken intermediates on the shared branch.
  - MUST do one thing — schema OR refresh-rotation OR a connector slice OR docs, not a mix.
  - MUST include the tests covering its behavior; coverage MUST not regress.
  - Commit message explains *why* (the spec FR, the constraint, the incident this prevents) — the diff already shows *what*.
  - No `--no-verify`, no force-pushes to the shared branch, no amends to published commits.
