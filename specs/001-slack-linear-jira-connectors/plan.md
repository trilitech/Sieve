# Implementation Plan: Slack, Linear, and Jira Connectors

**Branch**: `001-slack-linear-jira-connectors` | **Date**: 2026-05-01 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-slack-linear-jira-connectors/spec.md`

## Summary

Add three new managed connectors — Slack workspace, Linear organization, Jira Cloud site — under the existing `connector.Connector` interface so they share Sieve's policy pipeline, envelope-encryption credential storage, audit logging, and MCP exposure. Each connector accepts both OAuth flow credentials and direct API/personal tokens (mirroring the existing GitHub connector's multi-method credential model). Three priorities ship as independent slices: P1 Slack, P2 Linear, P3 Jira Cloud.

In addition to the three connectors, this feature introduces a first-class `status` field on the `connections` table (`active`, `reauth_required`, `disabled`) applied to **every** connector type, not just the new ones. Existing connections migrate to `active` on first start. Connectors transition to `reauth_required` when an upstream call returns a terminal authentication error, and admins clear that state by completing a fresh OAuth flow or re-entering a valid token. The schema change is forward-only and additive.

The implementation reuses every existing pattern: the `pendingOAuth` map and 10-minute-TTL state machine in `internal/web/server.go`, the `injectRefreshCallback` token-rotation hook in `internal/connections/connections.go`, the per-connector form-field metadata in `internal/connector/connector.go:Field`, and the connector-prefixed MCP tool naming rule in `internal/mcp/server.go`. Inbound webhooks are explicitly out of scope.

## Technical Context

**Language/Version**: Go 1.22+ (matches `go.mod`)
**Primary Dependencies**: `golang.org/x/oauth2` (existing; reused for Slack/Linear/Jira OAuth flows), `database/sql` + `mattn/go-sqlite3` (existing), `net/http` standard library (existing). No new top-level dependencies are required for v1; service-specific calls are made via `http.Client` against documented REST/GraphQL endpoints rather than third-party SDKs to keep the dependency surface small and match the existing GitHub connector.
**Storage**: Single SQLite file at `./data/sieve.db` (existing). One additive schema change: `status TEXT NOT NULL DEFAULT 'active'` column on the `connections` table.
**Testing**: `go test ./...` for unit + integration; Playwright for end-to-end via `e2e/web-ui.spec.ts` against `e2e/testserver`. New per-connector tests live alongside the connector code (`internal/connectors/<name>/*_test.go`); new e2e flows extend `e2e/web-ui.spec.ts`. The `internal/testing/mockconnector` and `internal/testing/testenv` patterns are extended with per-service mock HTTP servers for Slack/Linear/Jira.
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
│   └── jira.md
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
│   │   └── *_test.go
│   ├── linear/                         # NEW (P2) — same shape as slack/
│   │   ├── linear.go ... validate.go
│   │   └── *_test.go
│   └── jira/                           # NEW (P3) — same shape as slack/
│       ├── jira.go ... validate.go
│       └── *_test.go
├── database/
│   └── database.go                     # MODIFY: add ALTER TABLE migration to add `status` column;
│                                       # default 'active'; idempotent via columnExists()
├── web/
│   ├── server.go                       # MODIFY: register Slack/Linear/Jira OAuth flow handlers using
│                                       # the existing pendingOAuth pattern; reuse handleOAuthCallback
│   ├── slack.go                        # NEW: handlers for Slack OAuth start, direct-token entry,
│                                       #      and reauth refresh (mirrors web/github.go shape)
│   ├── linear.go                       # NEW: same shape
│   └── jira.go                         # NEW: same shape
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
└── connectors-jira.md                  # NEW

e2e/
├── testserver/                         # MODIFY: register Slack/Linear/Jira mock connectors
└── web-ui.spec.ts                      # MODIFY: add per-connector OAuth/token entry test cases
```

**Structure Decision**: Use the existing single-Go-service layout. New connectors live under `internal/connectors/<name>/` following the file decomposition already established by the GitHub connector (`auth.go`, `client.go`, `config.go`, `ops.go`, `validate.go`). Per-connector web handlers live under `internal/web/<name>.go`. No new top-level directories. The implementation pattern is "copy the GitHub connector skeleton, swap upstream service" with the added requirement that the generic OAuth-flow path also remains an option (per Q1 clarification). The new `status` field on `connections` is additive and fully backwards-compatible at the schema level.

## Phase 0: Outline & Research

See [research.md](./research.md) for the resolved decisions. Phase 0 produces no `NEEDS CLARIFICATION` markers — all unknowns about service authentication shapes, scope sets, and the status migration mechanism are decided in `research.md`. Decisions cover:

1. Slack: OAuth v2 install flow specifics (scopes, redirect URL, install URL, response token shape) + direct bot-token validation via `auth.test`.
2. Linear: OAuth 2.0 flow specifics (scopes, redirect URL, token endpoint) + personal API key validation via the `viewer` GraphQL query.
3. Jira Cloud: OAuth 2.0 (3LO) flow specifics (scopes, accessible-resources lookup for cloudId) + Atlassian API token + email basic-auth validation via `myself` REST endpoint.
4. Status field: column shape, default value, migration mechanism (idempotent ALTER TABLE), the contract for connectors mutating status, and the classification rule for "terminal auth error" per service.
5. Test strategy: mock HTTP servers per service in `internal/testing/`, e2e Playwright extensions, and the testserver wiring.

## Phase 1: Design & Contracts

See [data-model.md](./data-model.md) for entity shapes (Slack/Linear/Jira `Config` structs, the new `Connection.Status` field, validation rules) and [contracts/](./contracts/) for the per-connector operation contracts (`slack.md`, `linear.md`, `jira.md`). [quickstart.md](./quickstart.md) walks through local setup and verification for each connector.

The design follows three principles, each grounded in existing code:

1. **Multi-method credential model** (per Q1 clarification): each connector's `Config` struct holds a discriminator field (e.g., `auth_kind: "oauth" | "token"`) plus method-specific fields. The factory dispatches on `auth_kind` to construct the right `http.Client`. This mirrors `internal/connectors/github/config.go` (`KindFPAT` vs `KindAppInstallation`).
2. **One account per connection** (per Q2 clarification): no per-request credential routing. The connection's single bound credential is used for every call. Multi-workspace/org/site setups create multiple connections, each with a distinct alias.
3. **Connection status, not connection state machine** (per Q4 clarification): the column is a static enum with three values; transitions are simple writes. There is no FSM, no state-transition table, no event log. The connector calls `connections.Service.SetStatus(id, "reauth_required")` on a terminal-auth error; the admin clearing reauth (via fresh OAuth or token re-entry) calls `SetStatus(id, "active")`.

Re-evaluation after Phase 1 design: **PASS**. No new patterns warrant constitutional review. The Phase 1 artifacts add three connector packages and one schema column; both are direct extensions of patterns the codebase already employs.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

No violations. Section intentionally empty.
