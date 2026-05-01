# Implementation Plan: Slack, Linear, Jira, and Asana Connectors

**Branch**: `001-slack-linear-jira-connectors` | **Date**: 2026-05-01 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-slack-linear-jira-connectors/spec.md`

## Summary

Add four new managed connectors — Slack workspace (P1), Linear organization (P2), Jira Cloud site (P3), and Asana workspace (P4) — under the existing `connector.Connector` interface so they share Sieve's policy pipeline, envelope-encryption credential storage, audit logging, and MCP exposure. Each connector accepts both OAuth flow credentials and direct API/personal tokens (mirroring the existing GitHub connector's multi-method credential model). Four priorities ship as independent slices: P1 Slack, P2 Linear, P3 Jira Cloud, P4 Asana.

In addition to the four connectors, this feature introduces:

1. A first-class `status` field on the `connections` table (`active`, `reauth_required`, `disabled`) applied to **every** connector type, not just the new ones. Existing connections migrate to `active` on first start. Connectors transition to `reauth_required` when an upstream call returns a terminal authentication error, and admins clear that state by completing a fresh OAuth flow or re-entering a valid token. The schema change is forward-only and additive.
2. A normalized pagination shape (`{ items, next_cursor }` with input `cursor` / `page_size`) across every curated `list_*` operation, per FR-014. The connector translates this into each upstream service's native paging mechanism (Slack `cursor`, Linear Relay `after`, Jira `startAt`, Asana `offset`).
3. A rich-text round-trip rule for Jira and Asana, per FR-015: every operation returning long-form rich-text fields (Jira `description`/`comment.body`, Asana `notes`) carries both the native rich-text representation AND a plain-text-rendered `*_text` companion field. Slack and Linear are unaffected (Slack messages and Linear descriptions are already plain text or simple Markdown).
4. A refresh-token rotation persistence rule, per FR-016: every OAuth-based connector whose upstream rotates refresh tokens (Linear, Jira, Asana) reuses Gmail's `injectRefreshCallback` to persist the new refresh token after every refresh; if the persist fails, the connection transitions to `reauth_required` immediately. Slack uses classic non-rotating bot scopes (per Q2 clarification 2026-05-01) and is unaffected.

The implementation reuses every existing pattern: the `pendingOAuth` map and 10-minute-TTL state machine in `internal/web/server.go`, the `injectRefreshCallback` token-rotation hook in `internal/connections/connections.go`, the per-connector form-field metadata in `internal/connector/connector.go:Field`, and the connector-prefixed MCP tool naming rule in `internal/mcp/server.go`. Inbound webhooks are explicitly out of scope.

## Technical Context

**Language/Version**: Go 1.22+ (matches `go.mod`)
**Primary Dependencies**: `golang.org/x/oauth2` (existing; reused for Slack/Linear/Jira OAuth flows), `database/sql` + `mattn/go-sqlite3` (existing), `net/http` standard library (existing). No new top-level dependencies are required for v1; service-specific calls are made via `http.Client` against documented REST/GraphQL endpoints rather than third-party SDKs to keep the dependency surface small and match the existing GitHub connector.
**Storage**: Single SQLite file at `./data/sieve.db` (existing). One additive schema change: `status TEXT NOT NULL DEFAULT 'active'` column on the `connections` table.
**Testing**: `go test ./...` for unit + integration; Playwright for end-to-end via `e2e/web-ui.spec.ts` against `e2e/testserver`. New per-connector tests live alongside the connector code (`internal/connectors/<name>/*_test.go`); new e2e flows extend `e2e/web-ui.spec.ts`. The `internal/testing/mockconnector` and `internal/testing/testenv` patterns are extended with per-service mock HTTP servers for Slack, Linear, Jira, and Asana. A regression test for FR-016 simulates a refresh-token persist failure (DB write error) and asserts the connection lands in `reauth_required`.
**Target Platform**: Linux server (Docker compose / systemd-managed), single-binary; macOS for local development. No new platform constraints.
**Project Type**: Single Go service with two HTTP servers (agent-facing API+MCP on 19817, admin UI on 19816). Existing layout preserved.
**Performance Goals**: Match existing connector latency. The added overhead per connector call is bounded by one extra database round-trip if status needs to be updated (i.e., only on terminal-auth-error path), and zero added overhead on the happy path. SC-003 (audit visible within 5s) and SC-007 (status transition visible within 60s) are the only feature-specific perf targets.
**Constraints**: Keyring must be loaded for any credential read/write (existing invariant — surfaces as HTTP 503). Two-port topology preserved: agent endpoints stay on 19817, admin endpoints stay on 19816. `rejectIfAgentToken` continues to gate every admin endpoint added by this feature. No env-var-based credential intake. No plaintext credential fields on `connections`.
**Scale/Scope**: Individual-account product — one Sieve install per user, expected to hold a small number of connections (tens at most). No multi-tenant requirements. No high-throughput target — operations are user/agent-paced, not machine-paced.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

The project constitution at `.specify/memory/constitution.md` is the unfilled template — no concrete principles, sections, or governance rules have been ratified. The constitution check is therefore vacuously satisfied: there are no gates to violate.

This plan introduces no patterns, dependencies, or architectural choices that would require justification under common constitutional principles (test-first, library-first, simplicity, observability) had they been ratified:

- **Test-first**: Each connector ships with unit tests for ops + auth and integration tests against mock HTTP servers; the e2e suite covers the OAuth/token-entry happy paths.
- **Simplicity**: No new top-level dependencies, no new architectural layer, no new persistence engine, no new RPC mechanism. The status column is a single additive field.
- **Observability**: Audit logging continues to capture every operation invocation (existing FR-006 mechanism, unchanged).
- **Two-port topology**: Preserved exactly. No agent endpoints added to web server; no admin endpoints added to API router.

**Result**: PASS (vacuous). Re-check after Phase 1 design: still PASS — the design adds no implementation patterns that would trigger a constitutional concern under standard principles.

## Project Structure

### Documentation (this feature)

```text
specs/001-slack-linear-jira-connectors/
├── plan.md              # This file (/speckit-plan command output)
├── spec.md              # Feature specification (/speckit-specify + /speckit-clarify output)
├── research.md          # Phase 0 output — decisions and rationale per unknown
├── data-model.md        # Phase 1 output — persisted entities and shapes
├── quickstart.md        # Phase 1 output — local dev/test walkthrough per connector
├── contracts/           # Phase 1 output — per-connector operation contracts
│   ├── slack.md
│   ├── linear.md
│   ├── jira.md
│   └── asana.md
├── checklists/
│   └── requirements.md  # Spec quality checklist
└── tasks.md             # Phase 2 output (generated by /speckit-tasks — NOT created here)
```

### Source Code (repository root)

```text
internal/
├── connector/                          # (existing) Connector interface, Registry, Field metadata
├── connections/
│   └── connections.go                  # ADD: Connection.Status field, GetStatus/SetStatus methods, list
│                                       #      filtering; touch InitAll/GetWithConfig SQL to read status
├── connectors/
│   ├── github/                         # (existing — reference precedent for multi-credential)
│   ├── gmail/                          # (existing — reference precedent for OAuth flow)
│   ├── httpproxy/                      # (existing)
│   ├── mcpproxy/                       # (existing)
│   ├── slack/                          # NEW (P1)
│   │   ├── slack.go                    # Meta + Factory + GoogleConnector-equivalent
│   │   ├── auth.go                     # OAuth-token vs direct-bot-token resolution
│   │   ├── client.go                   # HTTP client wrapping Slack Web API
│   │   ├── ops.go                      # Operations() and Execute() dispatch table
│   │   ├── config.go                   # Config struct + parseConfig + validate()
│   │   ├── validate.go                 # Validate() — auth.test against Slack
│   │   ├── pagination.go               # Normalized cursor ↔ Slack cursor (FR-014)
│   │   └── *_test.go
│   ├── linear/                         # NEW (P2) — same shape as slack/
│   │   ├── linear.go ... validate.go
│   │   ├── pagination.go               # Normalized cursor ↔ Relay after/pageInfo
│   │   └── *_test.go
│   ├── jira/                           # NEW (P3) — same shape as slack/
│   │   ├── jira.go ... validate.go
│   │   ├── adf.go                      # textToADF + ADF-tree-to-text (FR-015)
│   │   ├── pagination.go               # Normalized cursor ↔ startAt/maxResults
│   │   └── *_test.go
│   └── asana/                          # NEW (P4)
│       ├── asana.go                    # Meta + Factory
│       ├── auth.go                     # OAuth vs PAT resolution
│       ├── client.go                   # HTTP client wrapping Asana REST API
│       ├── ops.go                      # Operations() and Execute() dispatch
│       ├── config.go                   # Config struct + parseConfig + validate()
│       ├── validate.go                 # Validate() — GET /users/me
│       ├── pagination.go               # Normalized cursor ↔ offset/next_page
│       ├── richtext.go                 # html_notes ↔ notes_text (FR-015)
│       └── *_test.go
├── database/
│   └── database.go                     # MODIFY: add ALTER TABLE migration to add `status` column;
│                                       # default 'active'; idempotent via columnExists()
├── web/
│   ├── server.go                       # MODIFY: register Slack/Linear/Jira/Asana OAuth flow handlers
│                                       # using the existing pendingOAuth pattern; reuse handleOAuthCallback
│   ├── slack.go                        # NEW: handlers for Slack OAuth start, direct-token entry,
│                                       #      and reauth refresh (mirrors web/github.go shape)
│   ├── linear.go                       # NEW: same shape
│   ├── jira.go                         # NEW: same shape
│   └── asana.go                        # NEW: same shape
├── api/
│   └── router.go                       # NO CHANGE for v1: agent calls flow through the generic
│                                       # /api/v1 connector endpoints — connector-prefixed naming
│                                       # in MCP suffices; no Slack-/Linear-/Jira-specific REST surfaces
└── mcp/
    └── server.go                       # NO CHANGE: existing tool-registration loop already iterates
                                        # Operations() and applies the connector_type prefix rule.

docs/
├── connectors-slack.md                 # NEW: setup + scopes + token entry walkthrough
├── connectors-linear.md                # NEW
├── connectors-jira.md                  # NEW
└── connectors-asana.md                 # NEW

internal/testing/
├── mockslack/                          # NEW: per-service httptest.Server
├── mocklinear/                         # NEW
├── mockjira/                           # NEW
└── mockasana/                          # NEW

e2e/
├── testserver/                         # MODIFY: register Slack/Linear/Jira/Asana mock connectors
└── web-ui.spec.ts                      # MODIFY: add per-connector OAuth/token entry test cases
```

**Structure Decision**: Use the existing single-Go-service layout. New connectors live under `internal/connectors/<name>/` following the file decomposition already established by the GitHub connector (`auth.go`, `client.go`, `config.go`, `ops.go`, `validate.go`). Per-connector web handlers live under `internal/web/<name>.go`. Per-service mock HTTP servers live under `internal/testing/mock<name>/`. No new top-level directories. The implementation pattern is "copy the GitHub connector skeleton, swap upstream service" with three cross-cutting helper files added per connector as needed: `pagination.go` (normalized cursor translation, FR-014), `adf.go` / `richtext.go` (rich-text round-trip, FR-015 — Jira and Asana only), and reuse of `connections.injectRefreshCallback` for refresh-token rotation persistence (FR-016 — Linear, Jira, Asana). The new `status` field on `connections` is additive and fully backwards-compatible at the schema level.

## Phase 0: Outline & Research

See [research.md](./research.md) for the resolved decisions. Phase 0 produces no `NEEDS CLARIFICATION` markers — all unknowns about service authentication shapes, scope sets, the status migration mechanism, pagination normalization, rich-text round-trip, and refresh-token rotation persistence are decided in `research.md`. Decisions cover:

1. Slack: OAuth v2 install flow specifics (scopes, redirect URL, install URL, response token shape) + direct bot-token validation via `auth.test`. Classic non-rotating bot scopes only (per Q2 clarification 2026-05-01).
2. Linear: OAuth 2.0 flow specifics (scopes, redirect URL, token endpoint) + personal API key validation via the `viewer` GraphQL query. Refresh tokens rotate; reuse `injectRefreshCallback`.
3. Jira Cloud: OAuth 2.0 (3LO) flow specifics (scopes, accessible-resources lookup for cloudId) + Atlassian API token + email basic-auth validation via `myself` REST endpoint. Refresh tokens rotate (90-day TTL); reuse `injectRefreshCallback`.
4. Asana (R12, NEW): OAuth 2.0 flow specifics + Personal Access Token validation via `GET /users/me`. Workspace GID resolved at connection time. Refresh tokens rotate per OAuth 2.0 spec.
5. Status field: column shape, default value, migration mechanism (idempotent ALTER TABLE), the contract for connectors mutating status, and the classification rule for "terminal auth error" per service.
6. Pagination normalization (R13, NEW): `{ items, next_cursor }` response shape across every `list_*` op; per-connector translation tables to upstream native paging.
7. Rich-text round-trip (R14, NEW): Jira ADF tree-walk, Asana html-to-text rules; output in `*_text` companion fields alongside the native representation.
8. Refresh-token rotation persistence (R5 updated): reuse Gmail `injectRefreshCallback`; on persist failure, transition `status → reauth_required` immediately.
9. Test strategy: mock HTTP servers per service in `internal/testing/{mockslack,mocklinear,mockjira,mockasana}/`, e2e Playwright extensions, and the testserver wiring.

## Phase 1: Design & Contracts

See [data-model.md](./data-model.md) for entity shapes (Slack/Linear/Jira/Asana `Config` structs, the new `Connection.Status` field, validation rules) and [contracts/](./contracts/) for the per-connector operation contracts (`slack.md`, `linear.md`, `jira.md`, `asana.md`). [quickstart.md](./quickstart.md) walks through local setup and verification for each connector.

The design follows five principles, each grounded in existing code:

1. **Multi-method credential model** (per Q1 clarification): each connector's `Config` struct holds a discriminator field (e.g., `auth_kind: "oauth" | "token"`) plus method-specific fields. The factory dispatches on `auth_kind` to construct the right `http.Client`. This mirrors `internal/connectors/github/config.go` (`KindFPAT` vs `KindAppInstallation`).
2. **One account per connection** (per Q2 clarification): no per-request credential routing. The connection's single bound credential is used for every call. Multi-workspace/org/site/workspace setups create multiple connections, each with a distinct alias.
3. **Connection status, not connection state machine** (per Q4 clarification): the column is a static enum with three values; transitions are simple writes. There is no FSM, no state-transition table, no event log. The connector calls `connections.Service.SetStatus(id, "reauth_required")` on a terminal-auth error; the admin clearing reauth (via fresh OAuth or token re-entry) calls `SetStatus(id, "active")`.
4. **Normalized pagination shape** (FR-014): every `list_*` operation accepts `{cursor?, page_size?}` and returns `{items, next_cursor}`. Each connector owns a small translation table (`pagination.go`) mapping the normalized cursor to/from the upstream's native shape (Slack `cursor`, Linear Relay `after`, Jira `startAt+maxResults`, Asana `offset`).
5. **Rich-text dual representation** (FR-015): Jira and Asana operations returning long-form rich text emit BOTH the native field (`description`/`comment.body` as ADF JSON; Asana `notes` as HTML) AND a plain-text companion (`*_text` suffix). The plain-text rendering is best-effort and lives in `adf.go`/`richtext.go`.
6. **Refresh-token rotation persistence** (FR-016): for Linear/Jira/Asana, reuse Gmail's `injectRefreshCallback`. On persist failure, transition `status → reauth_required` immediately. Slack uses classic non-rotating tokens and is unaffected.

Re-evaluation after Phase 1 design: **PASS**. No new patterns warrant constitutional review. The Phase 1 artifacts add four connector packages and one schema column; the pagination/richtext/rotation rules are additive helpers that fit within the existing connector layering. The fourth connector (Asana) is a direct copy of the Linear/Jira shape with REST-style endpoints — no new abstractions.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

No violations. Section intentionally empty.
