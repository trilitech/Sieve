# Understanding Sieve's Data Model

Sieve has five core objects: **connections**, **policies**, **rules**, **roles**, and **tokens**. They form a layered system where each layer has a specific job. This document explains what each one is, how they relate, and why the layers exist.

## Overview

```
Token (what the agent holds)
  |
  v
Role (bundles connections with policies)
  |
  +-- Connection A  +  [Policy 1, Policy 2]
  |
  +-- Connection B  +  [Policy 3]
  |
  +-- Connection C  +  [Policy 1, Policy 3]
```

A **token** references exactly one **role**. A role defines one or more **connections**, each paired with zero or more **policies**. Each policy contains an ordered list of **rules**. When an agent makes a request, Sieve resolves this chain to decide what is allowed.

## Connections

A connection is a set of real credentials for one external service. Sieve holds the credentials; agents never see them.

Each connection has:
- **An alias** (e.g., `work`, `anthropic`, `aws-prod`) -- used to identify it in roles and in API paths.
- **A display name** (e.g., "Work Gmail", "Claude API") -- shown in the UI.
- **A connector type** that determines how Sieve talks to the service.

### Connection types

**Google Account** -- OAuth credentials for a Google account. One connection gives access to six services: Gmail, Drive, Calendar, Contacts (People API), Sheets, and Docs. That is 35+ individual operations (list_emails, drive.upload_file, calendar.create_event, etc.). Policies control which of these operations the agent can actually use.

**HTTP Proxy** -- A generic credential-substitution proxy for any HTTP API. You provide the target base URL, the auth header name (e.g., `x-api-key`, `Authorization`), and the real auth value (your API key). When an agent sends a request through Sieve, Sieve strips the agent's token and injects the real credential. This is the connector behind LLM provider cards (Anthropic, OpenAI, Gemini, Bedrock), cloud provider cards (AWS, Hyperstack), and the generic HTTP Proxy card.

**MCP Proxy** -- Points to an upstream MCP server. Sieve connects to it, discovers its tools via `tools/list`, and re-exposes those tools to agents through Sieve's own MCP interface. Every tool call passes through Sieve's policy pipeline before being forwarded upstream. This lets you wrap any existing MCP server with fine-grained access control.

### Multi-account support

You can create multiple connections of the same type. For example, two Google connections (`work` and `personal`) or two Anthropic connections (`anthropic-prod` and `anthropic-dev`). Agents disambiguate via the connection alias -- in Gmail API paths (`/gmail/v1/users/work/messages`) or in MCP tool prefixes (`work_list_emails`, `personal_list_emails`).

## Policies

A policy is a **named, reusable set of rules** with a default action. It defines what is allowed, denied, or requires approval -- independent of any specific connection.

Each policy has:
- **A name** (e.g., `read-only`, `drafter`, `redact-pii`, `sonnet-only`).
- **An ordered list of rules** (evaluated top-to-bottom, first match wins).
- **A default action** (`allow` or `deny`) that applies when no rule matches.

### Policies are not tied to connections

This is a key design decision. A `read-only` policy that allows `list_emails` and `read_email` while denying everything else can be reused across multiple Gmail connections. A `sonnet-only` policy that restricts LLM calls to `claude-sonnet-*` models can be applied to any Anthropic connection. You define the policy once and reference it wherever you need it.

### Built-in presets

Sieve includes several preset policies:
- **read-only** -- list + read emails, deny everything else.
- **drafter** -- read + draft, sends require approval.
- **full-assist** -- everything allowed, sends require approval.
- **triage** -- read + label + archive, no compose/send.

You can also create custom policies through the web UI or have agents propose them via MCP.

## Rules

A rule is a single entry within a policy. Each rule has **match conditions** and an **action**.

### Match conditions

Match conditions are ANDed within a rule: all specified conditions must be true for the rule to fire. Omitting a condition means "match any" for that field.

Common match fields available to all rules:
- **operations** -- Array of operation names (e.g., `["list_emails", "read_email"]`). Empty or omitted means "match all operations."

Service-specific match fields depend on the connection type. For example:
- **Gmail**: `from`, `to` (glob patterns like `*@company.com`), `subject_contains`, `content_contains`, `labels`.
- **LLM**: `model` (glob patterns like `claude-sonnet-*`), `max_tokens`, `max_cost`, `extended_thinking`.
- **HTTP Proxy**: `path` (glob pattern for request path), `body_contains`.
- **EC2**: `instance_type`, `region`, `max_count`, `ami`, `cidr`.
- **S3**: `bucket`, `key_prefix`, `region`.

See the full schema by calling `get_policy_schema` via MCP, or consult [policy-rules-reference.md](policy-rules-reference.md).

### Rule evaluation

Rules are evaluated **top-to-bottom, first match wins**. Once a rule matches, its action is applied and no further rules are checked. If no rule matches, the policy's default action applies.

Example:

```
Rule 1: IF operations = [send_email, reply]          -> approval_required
Rule 2: IF operations = [list_emails, read_email]     -> allow
Rule 3: IF content_contains "CONFIDENTIAL"            -> deny (post-phase)
Default: deny
```

In this policy, sending email requires approval, reading is allowed, anything containing "CONFIDENTIAL" in the response is blocked, and everything else is denied.

### The four action types

**allow** -- Permit the operation. The request is forwarded to the real service with the real credentials.

**deny** -- Block the operation. The agent receives an error with an optional reason. The request never reaches the real service.

**approval_required** -- Queue the operation for human review. The agent receives an approval ID and can poll for the result. A human reviews the request in the Sieve admin UI and clicks Approve or Reject. If approved, Sieve executes the operation.

**filter** -- Like allow, but applies content filters to the response before returning it to the agent. Two filter mechanisms are available:
- `filter_exclude` -- Remove response items containing a specified string (case-insensitive).
- `redact_patterns` -- Array of regex patterns; matches are replaced with `[REDACTED]` in the response.

This is the mechanism behind policies like "redact phone numbers" or "exclude emails from @personal.com."

### Two-phase evaluation

Sieve evaluates policies in two phases:
1. **Pre-execution** -- Before the operation runs. Decides allow, deny, or approval_required.
2. **Post-execution** -- After the operation returns data. Applies response filters (redaction, exclusion) and can deny based on response content (e.g., blocking responses that contain "CONFIDENTIAL").

## Roles

A role is the **bridge between connections and policies**. It says: "for connection X, apply policies A and B; for connection Y, apply policy C."

Each role has:
- **A name** (e.g., `developer`, `support-agent`, `intern`).
- **A list of bindings**, where each binding pairs one connection with one or more policies.

```
Role: "developer"
  Binding 1: connection "work"      -> policies ["drafter", "redact-pii"]
  Binding 2: connection "anthropic"  -> policies ["sonnet-only"]
  Binding 3: connection "aws-prod"   -> policies ["ec2-readonly"]
```

### What a role controls

- **Which connections the agent can see.** If a connection is not in the role, the agent cannot discover or use it. It will not appear in `tools/list` or `list_connections`.
- **Which policies apply to each connection.** Multiple policies on the same connection are evaluated in order. A connection with no policies in a role means deny-all (no rules to allow anything).
- **Which operations and data the agent can access.** The combination of connection + policies determines exactly what the agent can do.

### Shared roles

One role can be referenced by many tokens. When you update a role's bindings, every token referencing that role picks up the change immediately. This makes it easy to manage permissions across many agents at once -- change the role, and all agents using it are updated.

Manage roles via the CLI (`sieve role create`, `sieve role list`, `sieve role delete`) or the web UI at `http://localhost:19816/roles`.

## Tokens

A token is **what the agent actually holds**. It is a bearer credential that references exactly one role.

Each token has:
- **A name** (e.g., `project-x-agent`, `ci-pipeline`).
- **A plaintext string** (`sieve_tok_...`) shown once at creation. This is the only time the full token is visible.
- **A role reference** that determines what the token can access.
- **An optional expiry** (e.g., 24 hours, 7 days). Expired tokens are rejected.
- **A revocable status.** Tokens can be revoked in one click without touching the underlying credentials.

### How agents use tokens

As a Bearer token in HTTP headers:

```
Authorization: Bearer sieve_tok_xxxxx
```

This works for both the MCP endpoint (`POST /mcp`) and the HTTP proxy (`GET/POST /proxy/{connection}/...`).

### Token lifecycle

1. **Create** -- Admin creates a token via UI or CLI, assigning it a role and optional expiry. The plaintext token is shown once.
2. **Use** -- Agent includes the token in every request. Sieve validates it, resolves the role, evaluates policies.
3. **Expire** -- If an expiry was set, the token stops working after that time.
4. **Revoke** -- Admin can revoke a token at any time. Revocation is instant; the agent's next request will fail.

Multiple tokens can share the same role. This means you can give 10 agents the same permissions by creating 10 tokens pointing to one role, rather than configuring each one individually.

## Why the layers exist

### Why not just "token -> connection + policy"?

Because you want to reuse permission bundles. If 10 agents are doing the same job (e.g., triaging support emails), they should share one role, not each have manually-configured identical permission sets. When the job's requirements change, you update the role once.

### Why are policies separate from roles?

Because you want to compose them. A role might say:
- Connection `work` gets the `read-only` policy and the `redact-pii` policy.
- Connection `anthropic` gets the `sonnet-only` policy.

The `redact-pii` policy is useful across many contexts -- Gmail, Drive, any API that returns data. Keeping it as a standalone object means you define it once and attach it wherever needed. If you bundled policies directly into roles, you would duplicate the redaction rules in every role that needs them.

### Why are roles separate from tokens?

Because tokens are disposable credentials and roles are durable permission sets. A token expires in 24 hours and you create a new one. The role stays the same. If you embedded permissions directly in tokens, you would have to reconfigure permissions every time you issued a new token.

The separation also enables instant permission changes. Modifying a role's bindings immediately affects every token referencing that role -- no need to reissue tokens.

## Putting it all together

Here is a complete example showing all five objects working together.

**Connections:**
- `work` (Google Account -- work Gmail, Drive, Calendar)
- `anthropic` (HTTP Proxy -- Anthropic Claude API)

**Policies:**
- `drafter` -- allow list_emails, read_email, read_thread, create_draft; require approval for send_email, reply; deny everything else.
- `redact-pii` -- filter action on all read operations with `redact_patterns: ["\\b\\d{3}-\\d{2}-\\d{4}\\b", "\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b"]` (SSNs and phone numbers).
- `sonnet-only` -- allow if model matches `claude-sonnet-*`; deny everything else.

**Role: `developer`**
- Connection `work` with policies `drafter` + `redact-pii`
- Connection `anthropic` with policy `sonnet-only`

**Token: `project-x-agent`**
- References role `developer`
- Expires in 168 hours (7 days)
- Token string: `sieve_tok_a1b2c3...` (shown once at creation)

When the agent calls `list_emails`, Sieve resolves: token -> role `developer` -> connection `work` with policies `drafter` + `redact-pii` -> pre-check allows (drafter rule matches) -> execute via Gmail API with real OAuth token -> post-check applies PII redaction -> return filtered result.
