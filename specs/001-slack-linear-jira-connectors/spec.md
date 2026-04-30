# Feature Specification: Slack, Linear, and Jira Connectors

**Feature Branch**: `001-slack-linear-jira-connectors`
**Created**: 2026-04-30
**Status**: Draft
**Input**: User description: "adding remaining features like slack linear jira"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Slack workspace as a managed connector (Priority: P1)

A Sieve admin wants their AI agents to read from and post to a company Slack workspace under policy control, without giving the agent the workspace's real bot token. The admin opens the Sieve admin UI, picks "Slack" from the list of connectors, completes the Slack OAuth install, and gets back a connection they can attach to a role. An agent token bound to that role can then call Slack operations (list channels, search messages, post a message, read a thread) and every call is gated by the role's policies and recorded in the audit log.

**Why this priority**: Slack is the most common workplace target for AI-agent automation among Sieve's current users (notifications, daily summaries, ticket triage). It is also the most-requested integration that is not yet a first-class connector and is therefore the highest-value standalone slice.

**Independent Test**: Can be fully validated by adding a Slack connection in a test workspace, issuing a sub-token scoped to that connection with a "post to #bot-test only" policy, and confirming an agent can post to `#bot-test` but is denied for any other channel. No Linear or Jira work is required.

**Acceptance Scenarios**:

1. **Given** an admin with no existing Slack connection, **When** they complete the Slack OAuth install through the admin UI, **Then** a new connection appears in the connections list with status "connected" and the bot token is stored encrypted, never in plaintext.
2. **Given** an agent token whose role binds the Slack connection with a policy that allows posting only to `#bot-test`, **When** the agent calls the post-message operation targeting `#bot-test`, **Then** the message is delivered and an audit entry is recorded with decision "allow".
3. **Given** the same token from scenario 2, **When** the agent attempts to post to `#general`, **Then** the call is denied before it reaches Slack and an audit entry is recorded with decision "deny".
4. **Given** the Slack admin revokes the bot install upstream, **When** the agent next calls a Slack operation, **Then** Sieve surfaces a "reauth required" state on the connection in the admin UI and returns a clear non-secret error to the agent.

---

### User Story 2 - Linear organization as a managed connector (Priority: P2)

A Sieve admin wants AI agents to read and update Linear issues through Sieve so that policies can scrub confidential fields from responses (e.g., remove customer names from issue descriptions before the agent sees them). The admin adds a Linear connection via OAuth, attaches it to a role with a response-filter policy, and the agent can search and update issues with confidential strings redacted.

**Why this priority**: Linear is the issue tracker for many of Sieve's engineering-focused users, and response filtering on issue text is the most concrete use case for Sieve's post-execution filter pipeline. Lower than Slack only because the affected user set is narrower.

**Independent Test**: Can be fully validated by connecting a test Linear workspace, attaching a policy that redacts strings matching a configured regex from issue descriptions, querying an issue containing such a string, and confirming the agent receives the redacted version while the audit log shows the original was filtered.

**Acceptance Scenarios**:

1. **Given** an admin completes Linear OAuth, **When** they attach the connection to a role, **Then** the role can be granted to tokens and agents on those tokens see Linear operations exposed.
2. **Given** an agent token with a response-filter policy that redacts `[REDACTED]` for any string matching `customer:\w+`, **When** the agent reads an issue containing `customer:acme`, **Then** the description returned to the agent contains `[REDACTED]` in place of `customer:acme`.
3. **Given** an agent token without create-issue permission, **When** the agent attempts to create a Linear issue, **Then** the call is denied and no issue is created in Linear.

---

### User Story 3 - Jira Cloud site as a managed connector (Priority: P3)

A Sieve admin at an enterprise running Atlassian Cloud wants agents to query and transition Jira issues through Sieve. They add a Jira Cloud connection via OAuth, scope a role to a specific project, and agents can search issues with JQL, read them, comment, and transition them — all subject to per-operation policies.

**Why this priority**: Jira coverage matters for enterprise Sieve adopters and rounds out the "issue tracker" surface alongside Linear. Ranked P3 because the user base requesting it is smaller than Slack or Linear and the operation set overlaps Linear functionally.

**Independent Test**: Can be fully validated by connecting a test Jira Cloud site, scoping a role to a single project key, and confirming an agent can search and read issues only within that project but is denied for others.

**Acceptance Scenarios**:

1. **Given** an admin completes Jira Cloud OAuth, **When** they attach the connection to a role and grant it to a token, **Then** the agent can list and search issues within the granted scope.
2. **Given** a policy that restricts the agent to the `BOT` project, **When** the agent issues a JQL search across all projects, **Then** the response includes only `BOT` issues and the audit log records the policy that scoped the query.
3. **Given** an agent calls the transition-issue operation with an invalid transition for the issue's current state, **When** the call reaches Jira and is rejected, **Then** Sieve surfaces the upstream error to the agent and records the failure in the audit log without leaking the bearer credential.

---

### Edge Cases

- **Multiple workspaces of the same type**: An admin must be able to add a second Slack workspace (or Linear org, or Jira site) and address each one by a distinct alias on the agent-facing surface.
- **Upstream revocation**: When credentials are revoked at the source (admin uninstalls the Slack app, rotates the Linear API key, deactivates the Jira OAuth grant), the next operation must surface a "reauth required" state and not return stale or leaked secrets.
- **Rate limiting**: When an upstream service returns a 429 or equivalent, Sieve must propagate a retry-friendly error to the agent without exposing the upstream credential or response headers verbatim.
- **OAuth flow abandoned**: If the admin closes the OAuth window before completing the install, the pending OAuth state expires within its TTL and no half-configured connection is persisted.
- **Side-effect operations after policy denial**: For destructive or externally-visible operations (post message, transition issue, add comment), the policy decision must occur strictly *before* the call is dispatched upstream — there is no way to "filter back" a sent message.
- **Unsupported deployment**: If an admin attempts to connect a Jira Server / Data Center instance (non-Cloud), the system must clearly state the deployment is not supported in this version rather than failing opaquely.
- **Operation outside curated set**: If an agent attempts an operation not exposed by the curated connector, the system returns a clear "operation not supported by this connector" error and points the admin toward the generic HTTP proxy connector as a fallback path.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Admins MUST be able to add Slack, Linear, and Jira Cloud as new connections through the existing admin UI without writing code or editing config files.
- **FR-002**: The system MUST acquire credentials for each new connector through the same OAuth-with-state pattern used by existing connectors, persisting the connection only after the flow completes successfully.
- **FR-003**: The system MUST store all credentials for the new connectors using the existing envelope-encryption mechanism, with no plaintext credential ever persisted to disk.
- **FR-004**: Each new connector MUST expose a curated set of operations covering the most common AI-agent workflows for that service (see Key Entities) and label each operation with stable, predictable names so policies can target them.
- **FR-005**: Every operation invocation on a new connector MUST flow through the policy pipeline (pre-execution decision and post-execution response filters) on every call, with no bypass paths.
- **FR-006**: The system MUST record an audit entry for every operation invocation, including connector type, connection alias, operation name, agent token identifier, policy decision, and timestamp.
- **FR-007**: Each new connector's operations MUST be exposed as MCP tools to agents whose role grants access to the connection, following the existing connector-prefixed naming rule when the token has multiple connections.
- **FR-008**: Admins MUST be able to add more than one connection of the same type (e.g., two Slack workspaces) and have agents address each by alias.
- **FR-009**: When upstream credentials are revoked or expire, the system MUST detect the failure on the next operation and present a clear "reauth required" state for that connection in the admin UI.
- **FR-010**: When an upstream service responds with a rate-limit error, the system MUST surface a retry-friendly error to the agent without leaking the upstream bearer credential or sensitive response headers.
- **FR-011**: Admins MUST be able to scope a token's role to permit only specific operations or specific resources (channel, project, team) on each new connector, using the existing policy mechanisms (rules, script, llm, chain, composite, builtin).
- **FR-012**: User-facing setup documentation MUST cover each connector's external prerequisites (Slack app, Linear OAuth app, Jira OAuth app) at the same depth and format as the existing connector documentation pages.
- **FR-013**: All admin-facing endpoints for managing the new connectors MUST reject any request that carries an agent bearer token, preserving the human-vs-agent boundary already enforced for existing connectors.

### Key Entities

- **Slack Connection**: Represents a single installed Slack workspace. Identified by workspace ID and admin-chosen alias. Holds bot token, granted scopes, and bot user identity. Curated operations: list channels, list users, search messages, read channel history, read thread, read user profile, post message.
- **Linear Connection**: Represents a single Linear organization. Identified by organization ID and admin-chosen alias. Holds OAuth credentials (or API key for single-user setups), granted scopes. Curated operations: list teams, list users, list issues, get issue, create issue, update issue, add comment.
- **Jira Cloud Connection**: Represents a single Atlassian Cloud site. Identified by Cloud ID and admin-chosen alias. Holds OAuth credentials and granted scopes. Curated operations: search issues with JQL, get issue, create issue, update issue, transition issue, add comment.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A new admin can complete the first connection of each connector type, end-to-end, in under 10 minutes by following the documentation alone.
- **SC-002**: For the curated operation set of each connector, agents can perform at least 95% of common workflows without falling back to the generic HTTP proxy connector.
- **SC-003**: Every operation invocation produces an audit record visible in the admin UI within 5 seconds of the call completing.
- **SC-004**: 100% of operation invocations on the new connectors are evaluated by the policy pipeline before reaching the upstream service, verifiable from the audit log having a policy-decision entry for each invocation.
- **SC-005**: 0 plaintext credentials for the new connectors exist in the database, verifiable by inspecting the connections table and confirming only ciphertext columns hold credential material.
- **SC-006**: Adding a second instance of the same connector type (e.g., a second Slack workspace) requires no code changes — only an admin action through the UI.
- **SC-007**: When upstream credentials are revoked, the connection's "reauth required" state is visible to admins within 60 seconds of the next agent operation that hits the revocation.

## Assumptions

- Slack support targets the Slack OAuth 2.0 bot-token install flow; user tokens and Slack Enterprise Grid org-level installs are out of scope for v1.
- Linear support uses OAuth 2.0 as the primary auth method, with personal API key accepted as a fallback for single-user installations that do not warrant a full OAuth app.
- Jira support targets Atlassian Cloud only; Jira Server and Jira Data Center are explicitly out of scope for v1.
- The existing OAuth state machine (random state token, ten-minute TTL, no persistence until success) is sufficient for these three connectors and does not need architectural changes.
- The curated operation set per connector is intentionally minimal at launch; agents needing an operation not in the curated set can fall back to the generic HTTP proxy connector. The curated set is expected to expand based on observed usage.
- Rate-limit handling defers to the upstream service's documented headers (Retry-After, X-RateLimit-Remaining); Sieve does not maintain its own per-token rate-limit accounting for these connectors in v1.
- Setup documentation will be added alongside the existing per-connector pages and will not change navigation structure or the documentation toolchain.
- The existing role-binding model (one binding per connection, list of policy IDs, empty list = deny all) is sufficient for expressing per-operation and per-resource scoping for the new connectors.
