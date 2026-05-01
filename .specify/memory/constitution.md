<!--
SYNC IMPACT REPORT
==================
Version change: (uninitialized template) → 1.0.0
Bump rationale: MAJOR — initial ratification. The previous file contained only
template placeholders; this is the first concrete governance document, so the
version starts at 1.0.0.

Modified principles: N/A (initial ratification)
Added principles:
  - I. Security-First (Credentials Never Leak)
  - II. Test-Driven Development (NON-NEGOTIABLE)
  - III. Clean, Independent Commits
  - IV. UI Parity With Behavior Changes
  - V. Simplicity & Layered Architecture

Added sections:
  - Security & Encryption Constraints
  - Development Workflow & Quality Gates
  - Governance

Removed sections: none

Templates requiring updates:
  - ✅ .specify/templates/plan-template.md — Constitution Check section
    references "Gates determined based on constitution file"; no edit
    required, gates will be filled per-feature against this document.
  - ✅ .specify/templates/spec-template.md — no constitution-specific
    references; structure compatible.
  - ✅ .specify/templates/tasks-template.md — already enforces "Tests MUST
    fail before implementation" and "Commit after each task or logical
    group", which align with Principles II and III.
  - ✅ .claude/skills/speckit-constitution/SKILL.md (this command file) —
    no outdated references found.
  - ⚠ README.md / SPEC.md — no constitutional references to reconcile yet;
    revisit if future amendments add public-facing rules.

Deferred items / TODOs: none.
-->

# Sieve Constitution

## Core Principles

### I. Security-First (Credentials Never Leak)

Sieve is a credential gateway; protecting real credentials is the product, not
a feature. Every change MUST preserve these invariants:

- Plaintext credentials MUST NEVER be persisted. All connection configs flow
  through `internal/secrets` envelope encryption (per-record DEK, AES-256-GCM,
  KEK-wrapped). New credential fields MUST route through `connections.Config`.
- The agent-facing port (19817) and the human-facing port (19816) MUST remain
  separate. Agent endpoints MUST NOT be reachable on the web UI port, and
  web/admin endpoints MUST NOT be reachable on the API port. `rejectIfAgentToken`
  protections on the web server MUST be preserved.
- Passphrase intake MUST come from TTY, `SIEVE_PASSPHRASE_FILE`, or FD 3 only.
  Environment-variable-based passphrase intake is forbidden (env leaks via
  `/proc/<pid>/environ`, `ps`, and crash dumps).
- Every agent request MUST pass through the policy pipeline; bypassing
  `authMiddleware`, the policy `Evaluator`, or response filters is a
  constitutional violation, not a refactor.

**Rationale**: A credential gateway that leaks credentials is worse than no
gateway at all — it provides false assurance. These invariants are load-bearing
and have been violated in dependent systems before; they are not negotiable.

### II. Test-Driven Development (NON-NEGOTIABLE)

Tests are written before or alongside the code they cover, and every change
MUST land with sufficient automated coverage to prevent regression.

- New behavior MUST have a failing test demonstrating the gap before the
  implementation lands. Bug fixes MUST include a regression test that fails
  without the fix and passes with it.
- Coverage MUST be maintained or improved by every change; a change that
  reduces meaningful coverage MUST justify the reduction in the PR description
  and link to a follow-up.
- Integration tests covering connector, policy, and storage interactions MUST
  use real implementations (real SQLite via `internal/testing/testenv`, real
  encryption keyring, mock connectors only for external HTTP boundaries).
  Mocking the database, the keyring, or the policy evaluator is forbidden
  except in tightly-scoped unit tests of those components themselves.
- E2E flows touching the web UI MUST be exercised by the Playwright suite
  (`e2e/web-ui.spec.ts`) before merge.
- A change is not "done" until `go test ./...` and the relevant Playwright
  specs pass locally.

**Rationale**: Sieve sits on the trust boundary between agents and real
credentials. A bug here is a security incident, not an inconvenience. TDD
forces the hazard to be expressed as a test first, which is what makes future
refactors safe.

### III. Clean, Independent Commits

Each commit MUST be a self-contained, reviewable, revertable unit of change.

- A commit MUST compile, pass `go test ./...`, and leave the repo in a working
  state. No "WIP", "fix later", or broken-intermediate commits on shared
  branches.
- A commit MUST do one thing: a feature, a refactor, a fix, a docs update,
  or a test addition — not a mix. Unrelated drive-by edits MUST be split into
  separate commits.
- Tests MUST land in the same commit as the behavior change they cover (or in
  an immediately preceding commit on the same branch when introducing a failing
  test before the fix). Coverage and code MUST not drift across PRs.
- Commit messages MUST explain the *why* (constraint, incident, requirement),
  not just the *what* (which the diff already shows).
- `--no-verify`, force-pushes to shared branches, and amending published
  commits are forbidden without explicit reviewer approval.

**Rationale**: Clean commits make `git bisect` work, make reverts surgical
instead of catastrophic, and make code review a bounded task. They are the
mechanism by which a small team maintains a high-trust codebase over time.

### IV. UI Parity With Behavior Changes

The admin UI (`internal/web`, port 19816) is the primary surface humans use to
operate Sieve. Behavior changes that affect what humans configure or observe
MUST update the UI in the same change set.

- Adding, renaming, or removing a connector type, policy type, role binding
  field, token attribute, or settings field MUST also update the corresponding
  forms, tables, validation, and labels in `internal/web` and any embedded
  templates/JS.
- UI/storage serialization mappings (e.g., `require_approval` ↔
  `approval_required`) MUST be preserved bidirectionally; unit or integration
  tests MUST cover both directions.
- A PR that changes API/MCP behavior but explicitly chooses NOT to update the
  UI MUST justify the deferral in the PR description and file a follow-up
  issue. "I forgot the UI" is a blocker, not a nit.
- For UI-visible changes, manual verification in a browser (golden path + at
  least one error path) is required before claiming the task complete.
  Automated checks alone do not certify UI correctness.

**Rationale**: Sieve's value depends on humans being able to see and control
what agents are doing. A backend feature with no UI is an incomplete feature,
and silent UI drift produces operator surprises that erode trust in the tool.

### V. Simplicity & Layered Architecture

The codebase is small on purpose. New abstractions MUST earn their place.

- Respect the existing layering: `connector` → `policy` → `policies/roles/tokens`
  → `api/router` and `mcp/server`. Cross-layer shortcuts (e.g., a connector
  reading the database directly, or the web server calling a connector
  bypassing policy) are forbidden.
- Do not add error handling, fallbacks, or validation for scenarios that
  cannot happen. Validate at system boundaries (HTTP handlers, connector
  inputs, policy script I/O); trust internal invariants elsewhere.
- Do not introduce frameworks, dependency-injection containers, or
  configuration layers for hypothetical future requirements. Three similar
  lines beat a premature abstraction.
- Do not add backwards-compatibility shims for code paths under our own
  control. Change the call sites instead.

**Rationale**: Every line of code is a place a security bug can hide. A small
codebase that one person can audit in an afternoon is itself a security
property of the system.

## Security & Encryption Constraints

These constraints flow from Principle I and apply to every change:

- The `connections` schema MUST NOT acquire plaintext credential columns. New
  credential types route through `connections.Config` and the envelope
  encryption path.
- The keyring is a required dependency of `connections.NewService`. Code
  paths that touch connection configs while the keyring is unloaded MUST
  return `secrets.ErrKeyringNotLoaded`, which API/web handlers map to
  HTTP 503.
- Audit logging (`internal/audit`) MUST capture every policy decision and
  approval event; silencing or batching audit writes MUST be reviewed as a
  security-relevant change.
- When in doubt about whether an action is destructive (rotating keys,
  dropping a `connections` table on schema migration, revoking tokens), the
  default is to confirm with the operator before acting.

## Development Workflow & Quality Gates

- All PRs MUST pass `go test ./...` in CI before merge.
- PRs touching the web UI MUST pass the Playwright suite.
- PRs MUST be reviewed by at least one human reviewer; AI-only review is not
  sufficient for changes affecting Principles I, II, or IV.
- The Constitution Check in `.specify/templates/plan-template.md` MUST be
  filled out for every feature plan. Violations MUST be enumerated under
  Complexity Tracking with a justification or rejected.
- Generated artifacts (`specs/*/plan.md`, `tasks.md`, `data-model.md`) MUST be
  kept consistent with the principles above; `/speckit-analyze` is the
  authoritative cross-artifact consistency check.

## Governance

This constitution supersedes ad-hoc conventions and prior README guidance.
Where this document and a code comment, doc, or PR description disagree,
this document wins until it is amended.

**Amendment procedure**:

1. Open a PR that updates `.specify/memory/constitution.md` and propagates
   the change to dependent templates and docs (see Sync Impact Report
   header in this file for the propagation checklist).
2. Justify the version bump in the PR description per the rules below.
3. Obtain review from at least one maintainer.
4. On merge, the new version takes effect immediately.

**Versioning policy** (semantic):

- **MAJOR**: Backward-incompatible governance changes (principle removed,
  redefined to forbid previously-allowed behavior, or workflow gate removed).
- **MINOR**: New principle or section added, or material expansion of
  existing guidance.
- **PATCH**: Clarifications, wording fixes, typo corrections, formatting —
  no semantic change to what the project requires.

**Compliance review**:

- Every feature plan MUST pass the Constitution Check gate before Phase 0
  research and again after Phase 1 design.
- Reviewers MUST flag PRs that violate any principle; flagged violations
  block merge until either fixed or recorded under Complexity Tracking with
  reviewer-approved justification.
- Use `CLAUDE.md` and `AGENTS.md` for runtime/agent-facing guidance; those
  files MUST NOT contradict this constitution and SHOULD be updated when this
  document changes.

**Version**: 1.0.0 | **Ratified**: 2026-05-01 | **Last Amended**: 2026-05-01
