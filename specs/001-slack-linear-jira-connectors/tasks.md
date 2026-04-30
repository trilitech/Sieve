---

description: "Task list for the Slack / Linear / Jira Cloud connectors feature"
---

# Tasks: Slack, Linear, and Jira Connectors

**Input**: Design documents from `/specs/001-slack-linear-jira-connectors/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Included. Sieve is a security-sensitive credential gateway and every existing connector ships with unit + integration tests; new connectors must match. Per-connector test tasks live inside each story phase.

**Organization**: Tasks are grouped by user story (US1 Slack P1, US2 Linear P2, US3 Jira Cloud P3) so each story can be implemented, tested, and shipped independently.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: User story label (US1, US2, US3) — Setup / Foundational / Polish phases have no story label
- Include exact file paths in descriptions

## Path Conventions

Single-Go-service layout already in place. New code lives under `internal/connectors/<name>/`, `internal/web/`, `internal/testing/`, and `docs/`. See `plan.md` § Project Structure for the full tree.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Create directory skeletons and verify the baseline. Project is already initialized; this phase is intentionally minimal.

- [ ] T001 Create empty package directories `internal/connectors/slack/`, `internal/connectors/linear/`, `internal/connectors/jira/`, `internal/testing/mockslack/`, `internal/testing/mocklinear/`, `internal/testing/mockjira/`, and placeholder doc files `docs/connectors-slack.md`, `docs/connectors-linear.md`, `docs/connectors-jira.md`
- [ ] T002 [P] Verify the baseline is green by running `go test ./...` and `npx playwright test` from the repo root and recording the pre-feature pass count for regression comparison

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Add the cross-cutting `Connection.Status` field and the migration that applies to **all** connector types. Every user story below transitions a connection's status on terminal-auth errors and reads it via `GetConnector`, so this phase MUST complete before any of US1/US2/US3.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete and Foundational tests pass.

- [ ] T003 Add idempotent migration `ALTER TABLE connections ADD COLUMN status TEXT NOT NULL DEFAULT 'active'` (gated by `columnExists("connections", "status")`) to `migrate()` in `internal/database/database.go`
- [ ] T004 Add `Status string` field to the `Connection` struct in `internal/connections/connections.go`, update every SELECT and INSERT in that file (`Add`, `Get`, `GetWithConfig`, `List`, `InitAll`) to include the column, and add a package-level `validateStatus(s string) error` helper accepting only `active`, `reauth_required`, `disabled`
- [ ] T005 Add `Service.SetStatus(id, status string) error` method in `internal/connections/connections.go` performing `UPDATE connections SET status = ? WHERE id = ?` after validation; does not require keyring
- [ ] T006 Define `ErrReauthRequired` and `ErrConnectionDisabled` sentinels in `internal/connections/connections.go` and short-circuit them at the top of `Service.GetConnector` based on the loaded row's status (block any non-`active` status before instantiating the live connector)
- [ ] T007 [P] Add `TestMigrate_StatusColumn_FreshDB` and `TestMigrate_StatusColumn_PreExistingRowsDefaultActive` in `internal/database/database_test.go`
- [ ] T008 [P] Add `TestService_SetStatus_HappyPath`, `TestService_SetStatus_RejectsUnknownValue`, and `TestService_GetConnector_BlocksOnReauthRequired`, `TestService_GetConnector_BlocksOnDisabled` in `internal/connections/connections_test.go`
- [ ] T009 Surface `status` in JSON responses for the connections list endpoint in `internal/api/router.go` (verify the existing handler serializes `Connection` with the new field — adjust any explicit field allow-list)
- [ ] T010 Surface `status` in admin UI handlers in `internal/web/server.go` (`handleConnections` JSON + connection-detail handlers); add a status-badge render in `internal/web/templates/connections.html` (or whichever template currently renders the connections list)
- [ ] T011 Add admin endpoints `POST /connections/{id}/disable` and `POST /connections/{id}/enable` in `internal/web/server.go`, both gated by the existing `rejectIfAgentToken` middleware; calls `Service.SetStatus`
- [ ] T012 [P] Add `TestServer_DisableConnection_RejectsAgentToken` and `TestServer_DisableEnable_HappyPath` in `internal/web/server_test.go`
- [ ] T013 Map `ErrReauthRequired` → HTTP 403 `{"error": "reauth_required", "message": "..."}` and `ErrConnectionDisabled` → HTTP 403 `{"error": "disabled", "message": "..."}` in `internal/api/router.go` and `internal/mcp/server.go` so all three new connectors inherit the behavior automatically without per-connector code
- [ ] T014 [P] Add `TestRouter_ReauthRequired_Returns403` and `TestRouter_Disabled_Returns403` in `internal/api/router_test.go` using a test connector that always returns the sentinel
- [ ] T015 [P] Add `TestMCP_ReauthRequired_Surface` covering the same in `internal/mcp/server_test.go`

**Checkpoint**: Foundation ready. `go test ./internal/database ./internal/connections ./internal/api ./internal/mcp ./internal/web` is green. User story implementation can begin.

---

## Phase 3: User Story 1 — Slack workspace as a managed connector (Priority: P1) 🎯 MVP

**Goal**: An admin can connect a Slack workspace via OAuth or by pasting a bot token. An agent token bound to that connection can call the curated Slack operations subject to policy, with audit logging and reauth-required status transition on revocation.

**Independent Test**: Add a Slack connection to a test workspace through the admin UI, issue a sub-token with a "post to #bot-test only" rules policy, verify post to `#bot-test` succeeds, verify post to `#general` is denied, revoke the upstream install and verify the next call returns `reauth_required` and the admin UI shows that status. No Linear or Jira work is required.

### Tests for User Story 1

> Write these tests FIRST, ensure they FAIL before implementation.

- [ ] T016 [P] [US1] Contract tests for the 7 Slack operations in `internal/connectors/slack/ops_test.go`, asserting the param/result shapes from `contracts/slack.md` against `internal/testing/mockslack`
- [ ] T017 [P] [US1] Validate test in `internal/connectors/slack/validate_test.go` covering happy path (`auth.test` returns `ok: true`) and terminal-auth response (`ok: false, error: "invalid_auth"`)
- [ ] T018 [P] [US1] Terminal-auth classifier table-test in `internal/connectors/slack/auth_test.go` covering `invalid_auth`, `token_revoked`, `account_inactive`, `not_authed` → true; `rate_limited`, 5xx, network → false
- [ ] T019 [P] [US1] Web handler tests in `internal/web/slack_test.go` covering OAuth start (state generation + redirect), OAuth callback success, OAuth callback with expired state, direct bot-token entry validation
- [ ] T020 [P] [US1] e2e Playwright group "Slack connector" in `e2e/web-ui.spec.ts` covering: add via OAuth → status active; add via bot token → status active; revoked-token call → status reauth_required and UI badge updates within 60s

### Implementation for User Story 1

- [ ] T021 [P] [US1] Add `SLACK_CLIENT_ID` / `SLACK_CLIENT_SECRET` settings keys to `internal/settings/settings.go` (or wherever existing OAuth client settings live; mirror the GitHub/Google pattern)
- [ ] T022 [P] [US1] Implement mock Slack server in `internal/testing/mockslack/server.go` exposing `httptest.NewServer` with handlers for `auth.test`, `conversations.list`, `conversations.history`, `conversations.replies`, `search.messages`, `chat.postMessage`, `users.list`, `users.profile.get`; supports a `forceError(code)` toggle for terminal-auth simulation
- [ ] T023 [P] [US1] Define `Config` struct + `parseConfig` + `validate()` in `internal/connectors/slack/config.go` per `data-model.md` § Slack Connection Config (auth_kind discriminator, OAuth + token branches)
- [ ] T024 [P] [US1] Implement `isTerminalAuthError` classifier in `internal/connectors/slack/auth.go` per `research.md` R10
- [ ] T025 [US1] Implement HTTP client wrapper in `internal/connectors/slack/client.go` (resolves auth headers from `Config.AuthKind`, accepts `_base_url` override for tests, applies `isTerminalAuthError` and calls `connections.Service.SetStatus(id, "reauth_required")` on hit) — depends on T023, T024
- [ ] T026 [US1] Implement `Operations()` table and `Execute(ctx, op, params)` dispatch in `internal/connectors/slack/ops.go` per `contracts/slack.md` (7 operations: list_channels, list_users, read_user_profile, read_channel_history, read_thread, search_messages, post_message); `search_messages` returns the `operation_not_enabled` shape per research R1a when scope absent — depends on T025
- [ ] T027 [US1] Implement `Validate(ctx)` calling Slack `auth.test` in `internal/connectors/slack/validate.go` — depends on T025
- [ ] T028 [US1] Implement `Connector` struct + `Meta` + `Factory` in `internal/connectors/slack/slack.go`, wiring `_on_token_refresh` symmetry from Gmail (Slack bot tokens don't refresh, but kept for future user-token support); registers Type `"slack"`, Category `"Communication"`, SetupFields covering both auth paths — depends on T023, T025, T026, T027
- [ ] T029 [US1] Register the Slack connector in `cmd/sieve/main.go` and `e2e/testserver/main.go` connector registry initialization — depends on T028
- [ ] T030 [US1] Implement `handleSlackOAuthStart` and direct-token entry handler `handleSlackToken` in `internal/web/slack.go` (mirrors `internal/web/github.go` shape; uses `pendingOAuth` map keyed by random state with the existing 10-minute TTL) — depends on T021, T028
- [ ] T031 [US1] Extend `handleOAuthCallback` in `internal/web/server.go` to dispatch on `provider=slack` query param, calling Slack's `oauth.v2.access` endpoint and persisting the resulting Config via `connections.Service.UpdateConfig` then `SetStatus(id, "active")` — depends on T030
- [ ] T032 [US1] Add reauth/refresh handler `handleSlackReauth` in `internal/web/slack.go` that re-runs the OAuth start (or accepts a fresh token) and on success calls `Service.SetStatus(id, "active")` — depends on T030
- [ ] T033 [US1] Register the Slack web handlers in `Server.Routes()` in `internal/web/server.go`, all gated by `rejectIfAgentToken` — depends on T030, T031, T032
- [ ] T034 [P] [US1] Author `docs/connectors-slack.md` per `quickstart.md` and `research.md` R1 (prereqs, OAuth path, token path, scope table, troubleshooting)

**Checkpoint**: Slack connector functional independently. MVP complete: a user can install the binary, set up Slack via OAuth or token, attach to a role, and an agent can list/post/search subject to policy. SC-001 (10-min setup), SC-005 (zero plaintext credentials), and SC-007 (60s reauth detection) are verified by the quickstart walkthrough and the e2e test.

---

## Phase 4: User Story 2 — Linear organization as a managed connector (Priority: P2)

**Goal**: An admin can connect a Linear organization via OAuth 2.0 or by pasting a personal API key. Agents can list/get/create/update issues with response-filter policies redacting confidential fields.

**Independent Test**: Connect a test Linear org, attach a script policy that redacts `customer:\w+` to `[REDACTED]` from issue descriptions, query an issue containing `customer:acme`, verify the agent receives `[REDACTED]` while the audit log records the original was filtered. Independent from Slack and Jira.

### Tests for User Story 2

- [ ] T035 [P] [US2] Contract tests for the 7 Linear operations in `internal/connectors/linear/ops_test.go` against `internal/testing/mocklinear`
- [ ] T036 [P] [US2] Validate test in `internal/connectors/linear/validate_test.go` covering happy path (`viewer { id email }` returns non-null) and terminal-auth (`AUTHENTICATION_ERROR` extension code)
- [ ] T037 [P] [US2] Terminal-auth classifier table-test in `internal/connectors/linear/auth_test.go` (HTTP 401, GraphQL `extensions.code == "AUTHENTICATION_ERROR"`)
- [ ] T038 [P] [US2] Web handler tests in `internal/web/linear_test.go` covering OAuth start, OAuth callback, API-key entry validation
- [ ] T039 [P] [US2] e2e Playwright group "Linear connector" in `e2e/web-ui.spec.ts`: add via OAuth, add via API key, response-filter policy redaction (acceptance scenario US2.2), status reauth transition on revoked credential

### Implementation for User Story 2

- [ ] T040 [P] [US2] Add `LINEAR_CLIENT_ID` / `LINEAR_CLIENT_SECRET` settings keys to `internal/settings/settings.go`
- [ ] T041 [P] [US2] Implement mock Linear GraphQL server in `internal/testing/mocklinear/server.go` (single `/graphql` endpoint dispatching on operation name: `viewer`, `teams`, `users`, `issues`, `issue`, `issueCreate`, `issueUpdate`, `commentCreate`); supports `forceError("AUTHENTICATION_ERROR")` toggle
- [ ] T042 [P] [US2] Define `Config` struct + `parseConfig` + `validate()` in `internal/connectors/linear/config.go` per `data-model.md` § Linear Connection Config
- [ ] T043 [P] [US2] Implement `isTerminalAuthError` classifier in `internal/connectors/linear/auth.go`
- [ ] T044 [US2] Implement GraphQL client wrapper in `internal/connectors/linear/client.go` (auth header per `AuthKind`: `Authorization: Bearer <oauth>` or `Authorization: <api_key>`; `_base_url` override; `isTerminalAuthError` → `SetStatus("reauth_required")`) — depends on T042, T043
- [ ] T045 [US2] Implement `Operations()` + `Execute` dispatch in `internal/connectors/linear/ops.go` per `contracts/linear.md` (7 operations) — depends on T044
- [ ] T046 [US2] Implement `Validate(ctx)` issuing `query { viewer { id email } }` in `internal/connectors/linear/validate.go` — depends on T044
- [ ] T047 [US2] Implement `Connector` + `Meta` + `Factory` in `internal/connectors/linear/linear.go` wiring `_on_token_refresh` (Linear OAuth has refresh tokens) — depends on T042, T044, T045, T046
- [ ] T048 [US2] Register the Linear connector in `cmd/sieve/main.go` and `e2e/testserver/main.go` — depends on T047
- [ ] T049 [US2] Implement `handleLinearOAuthStart` and `handleLinearAPIKey` in `internal/web/linear.go` — depends on T040, T047
- [ ] T050 [US2] Extend `handleOAuthCallback` in `internal/web/server.go` to dispatch on `provider=linear`, exchanging the auth code at `https://api.linear.app/oauth/token` and persisting the result — depends on T049
- [ ] T051 [US2] Add reauth handler `handleLinearReauth` in `internal/web/linear.go` — depends on T049
- [ ] T052 [US2] Register the Linear web handlers in `Server.Routes()` in `internal/web/server.go`, all gated by `rejectIfAgentToken` — depends on T049, T050, T051
- [ ] T053 [P] [US2] Author `docs/connectors-linear.md` per `quickstart.md` and `research.md` R2

**Checkpoint**: Linear connector functional independently. Acceptance scenario US2.2 (response-filter redaction) demonstrably works.

---

## Phase 5: User Story 3 — Jira Cloud site as a managed connector (Priority: P3)

**Goal**: An admin can connect an Atlassian Cloud Jira site via OAuth 2.0 (3LO) or by pasting an Atlassian API token + email. Agents can search/get/create/update/transition/comment on issues subject to policy.

**Independent Test**: Connect a test Jira Cloud site, scope a role to project `BOT`, run a JQL search across all projects through the agent, verify only `BOT` issues are returned and the audit log records the policy-driven scoping.

### Tests for User Story 3

- [ ] T054 [P] [US3] Contract tests for the 7 Jira operations in `internal/connectors/jira/ops_test.go` against `internal/testing/mockjira` (search w/ JQL, get, create, update, transition, add_comment, list_transitions)
- [ ] T055 [P] [US3] Validate test in `internal/connectors/jira/validate_test.go` covering both auth modes (`/rest/api/3/myself` returns `accountId`)
- [ ] T056 [P] [US3] Terminal-auth classifier test in `internal/connectors/jira/auth_test.go` (HTTP 401 with WWW-Authenticate, HTTP 403 with token-revoked body)
- [ ] T057 [P] [US3] cloudId resolution test in `internal/connectors/jira/cloudid_test.go` covering OAuth path (`accessible-resources` returns single resource, returns multiple, returns empty) and basic-auth path (`serverInfo` returns cloudId)
- [ ] T058 [P] [US3] Web handler tests in `internal/web/jira_test.go` covering OAuth start, OAuth callback with cloudId resolution, API-token entry validation
- [ ] T059 [P] [US3] e2e Playwright group "Jira connector" in `e2e/web-ui.spec.ts`: add via OAuth (mock 3LO including accessible-resources), add via API token, project-scoped JQL policy (acceptance scenario US3.2), status reauth transition

### Implementation for User Story 3

- [ ] T060 [P] [US3] Add `JIRA_CLIENT_ID` / `JIRA_CLIENT_SECRET` settings keys to `internal/settings/settings.go`
- [ ] T061 [P] [US3] Implement mock Jira server in `internal/testing/mockjira/server.go` covering `/oauth/token/accessible-resources`, `/ex/jira/{cloudId}/rest/api/3/myself`, `/rest/api/3/serverInfo` (basic-auth path), `/rest/api/3/search`, `/rest/api/3/issue/{key}`, `/rest/api/3/issue` (POST), `/rest/api/3/issue/{key}/transitions`, `/rest/api/3/issue/{key}/comment`; supports `forceError(401)` and `forceError(403)`
- [ ] T062 [P] [US3] Define `Config` struct + `parseConfig` + `validate()` in `internal/connectors/jira/config.go` per `data-model.md` § Jira Cloud Connection Config (must validate `SiteURL` matches `https://*.atlassian.net` for token mode)
- [ ] T063 [P] [US3] Implement `isTerminalAuthError` classifier in `internal/connectors/jira/auth.go`
- [ ] T064 [P] [US3] Implement plain-text-to-ADF helper `textToADF(s string) map[string]any` in `internal/connectors/jira/adf.go` (used by create_issue, update_issue, add_comment) plus its unit tests `adf_test.go`
- [ ] T065 [US3] Implement HTTP client wrapper in `internal/connectors/jira/client.go` (auth header per `AuthKind`: `Authorization: Bearer <oauth>` for OAuth or `Authorization: Basic <base64(email:api_token)>` for token; base URL = `https://api.atlassian.com/ex/jira/{CloudID}` for OAuth or `<SiteURL>` for token; `_base_url` override; `isTerminalAuthError` → `SetStatus("reauth_required")`) — depends on T062, T063
- [ ] T066 [US3] Implement cloudId resolver in `internal/connectors/jira/cloudid.go` (OAuth: GET `https://api.atlassian.com/oauth/token/accessible-resources`; token: GET `<SiteURL>/rest/api/3/serverInfo`) — depends on T065
- [ ] T067 [US3] Implement `Operations()` + `Execute` dispatch in `internal/connectors/jira/ops.go` per `contracts/jira.md` (7 operations) — depends on T064, T065
- [ ] T068 [US3] Implement `Validate(ctx)` calling `GET /rest/api/3/myself` and asserting `accountId` non-empty in `internal/connectors/jira/validate.go` — depends on T065, T066
- [ ] T069 [US3] Implement `Connector` + `Meta` + `Factory` in `internal/connectors/jira/jira.go` wiring `_on_token_refresh` (Jira OAuth has refresh tokens) — depends on T062, T065, T066, T067, T068
- [ ] T070 [US3] Register the Jira connector in `cmd/sieve/main.go` and `e2e/testserver/main.go` — depends on T069
- [ ] T071 [US3] Implement `handleJiraOAuthStart` and `handleJiraAPIToken` in `internal/web/jira.go` (token path collects email + API token + site URL in one form) — depends on T060, T069
- [ ] T072 [US3] Extend `handleOAuthCallback` in `internal/web/server.go` to dispatch on `provider=jira`, exchanging auth code at `https://auth.atlassian.com/oauth/token`, then calling the cloudId resolver before persisting — depends on T066, T071
- [ ] T073 [US3] Add reauth handler `handleJiraReauth` in `internal/web/jira.go` — depends on T071
- [ ] T074 [US3] Register the Jira web handlers in `Server.Routes()` in `internal/web/server.go`, all gated by `rejectIfAgentToken` — depends on T071, T072, T073
- [ ] T075 [P] [US3] Author `docs/connectors-jira.md` per `quickstart.md` and `research.md` R3

**Checkpoint**: All three connectors functional independently. Acceptance scenarios across US1/US2/US3 pass.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Validation against measurable success criteria, documentation polish, regression-suite hygiene.

- [ ] T076 [P] Walk through `quickstart.md` end-to-end against the real Slack/Linear/Jira sandbox accounts (or document with screenshots if real accounts aren't available) to verify SC-001 (10-min setup) for each connector
- [ ] T077 [P] Verify SC-002 (95% workflow coverage) by listing the operations agents most commonly request through the existing HTTP proxy connector against the curated set; document any gap in `research.md` § R11 as a known limitation, not a blocker
- [ ] T078 [P] Verify SC-005 (zero plaintext credentials) by querying `sqlite3 ./data/sieve.db "SELECT id, connector_type FROM connections;"` after each new connector type is created in the test env, confirming the `config_ciphertext` column holds bytes that don't deserialize as JSON without the keyring
- [ ] T079 [P] Update `README.md` to list Slack, Linear, and Jira Cloud in the connector catalog (move from any "coming soon" markings if present); update the "What Sieve is" intro line that lists supported services
- [ ] T080 [P] Update CLAUDE.md "Conventions worth knowing" with: Slack `search:read` requires user-token install (not currently supported); Linear OAuth uses `actor=app`; Jira cloudId is resolved at OAuth callback and stored in the encrypted config; the new `connections.status` field is non-secret and returned without keyring decryption
- [ ] T081 Run `go vet ./... && go test ./... -race` and resolve any warnings or flakiness introduced by the feature
- [ ] T082 Run `npx playwright test e2e/web-ui.spec.ts` three times in a row and confirm zero flakes across the new Slack/Linear/Jira test groups; if any flake, fix the test (do not retry-loop in CI)
- [ ] T083 [P] Add a one-line entry to `docs/connectors-overview.md` (or equivalent index doc) listing each new connector with a link to its dedicated page

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately.
- **Foundational (Phase 2)**: Depends on Setup completion. **Blocks all user stories** because every connector calls `connections.Service.SetStatus` and reads through `GetConnector`'s status short-circuit.
- **User Story 1 / 2 / 3 (Phases 3–5)**: All depend on Foundational. Once Foundational is done, the three stories are mutually independent and can proceed in parallel by separate developers.
- **Polish (Phase 6)**: Depends on whichever user stories are in scope for the release.

### User Story Dependencies

- **US1 (Slack)**: Depends only on Foundational. No dependency on US2 or US3.
- **US2 (Linear)**: Depends only on Foundational. No dependency on US1 or US3.
- **US3 (Jira Cloud)**: Depends only on Foundational. No dependency on US1 or US2.

### Within Each User Story

- Tests (T016–T020 for US1, T035–T039 for US2, T054–T059 for US3) are written first against the mock servers and assert the contracts; they fail until implementation lands.
- Within implementation: settings + mock + config + auth classifier are independent ([P] across them); client depends on config + classifier; ops + validate depend on client; the connector main file depends on config + client + ops + validate; web handlers depend on settings + the connector main file; route registration is the final wiring step.
- Docs ([T034] / [T053] / [T075]) are independent and can be authored in parallel with the code.

### Parallel Opportunities

- All Foundational tests T007, T008, T012, T014, T015 run in parallel after their respective implementation tasks complete.
- Within a user story, all `[P]` tasks against different files run in parallel (settings, mock server, config, classifier, docs).
- Across user stories, after Foundational completes, three developers can take US1, US2, US3 in parallel — there is no shared file conflict between the three connector packages, the three web-handler files, or the three doc pages.
- Polish phase tasks T076–T080 and T083 are all independent and run in parallel.

---

## Parallel Example: User Story 1 (Slack)

```bash
# After Foundational is done, launch all Slack [P] implementation files in parallel:
Task: "Add SLACK_CLIENT_ID/SECRET to internal/settings/settings.go"             # T021
Task: "Implement mock Slack server in internal/testing/mockslack/server.go"      # T022
Task: "Define Config + validate in internal/connectors/slack/config.go"          # T023
Task: "Implement isTerminalAuthError in internal/connectors/slack/auth.go"       # T024
Task: "Author docs/connectors-slack.md"                                          # T034

# Then sequentially (each depends on prior):
Task: "Implement HTTP client in internal/connectors/slack/client.go"              # T025 (depends on T023, T024)
Task: "Implement Operations + Execute in internal/connectors/slack/ops.go"        # T026 (depends on T025)
Task: "Implement Validate in internal/connectors/slack/validate.go"               # T027 (depends on T025)
Task: "Implement Connector + Factory in internal/connectors/slack/slack.go"       # T028 (depends on T023, T025, T026, T027)
```

The same shape applies to US2 and US3 with the file paths substituted.

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1: Setup (T001, T002).
2. Phase 2: Foundational (T003–T015) — **critical**, blocks everything.
3. Phase 3: Slack (T016–T034).
4. **STOP and VALIDATE**: Run `go test ./...` + `npx playwright test -g Slack`. Walk `quickstart.md` § Slack against a real workspace.
5. Ship the MVP with Slack only. Status migration applies to all existing connectors (Gmail, GitHub, MCP proxy, HTTP proxy) at this point too — verify SC-008.

### Incremental Delivery

1. Setup + Foundational → status field shipped to existing users.
2. Add Slack (US1) → ship MVP.
3. Add Linear (US2) → ship.
4. Add Jira Cloud (US3) → ship.
5. Polish (Phase 6) → final release polish.

Each story adds value without breaking the others. The status field migration happens once at the start and is forward-compatible with all subsequent stories.

### Parallel Team Strategy

With three engineers post-Foundational:

- Eng A: US1 Slack (Phase 3).
- Eng B: US2 Linear (Phase 4).
- Eng C: US3 Jira Cloud (Phase 5).

The three connector packages, web handler files, mock servers, and doc pages do not collide; Phase 2 is the single integration point and must merge first.

---

## Notes

- `[P]` tasks = different files, no dependencies on incomplete tasks.
- `[Story]` label maps each user-story task to its priority (US1=Slack/P1, US2=Linear/P2, US3=Jira/P3).
- Each user story is independently completable and testable; cutting US2 or US3 from a release does not affect the others.
- Tests are written first against mock HTTP servers, asserting the operation contracts in `contracts/`. They fail until the corresponding implementation lands.
- Commit after each task or logical group (settings + mock + config as one commit, then client + ops + validate, then connector main file + registration, then web handlers + routes, then docs).
- Stop at any checkpoint to validate the story independently against `quickstart.md`.
- Avoid: vague tasks, same-file conflicts (each task names exactly one file or a tightly-grouped set), cross-story dependencies that would break independence.
