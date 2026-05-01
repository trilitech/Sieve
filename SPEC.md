# Sieve

**A capability-scoped API gateway for AI agents.**

Sieve sits between untrusted AI agents and your sensitive services (Gmail,
Slack, bank APIs, anything with an API). It holds real credentials in an
isolated process, issues scoped capability tokens to agents, and enforces
policies that can be anything from simple presets to Python scripts to LLM
calls. A single Sieve instance manages multiple connections across providers;
each agent token is scoped to specific connections.

Gmail is the first connector. The architecture is provider-agnostic from
day one.

---

## 1. Problem

You run AI agents (Claude Code, Codex, custom scripts) across many projects.
These agents need access to your services (email, chat, financial data) but:

- Handing each project a raw API token gives **full access** with no way to
  restrict what the agent does.
- Per-service permission models are coarse (Gmail scopes, Slack scopes) ---
  no scope for "read only emails matching a subject keyword" or "post to
  Slack only in #project-x."
- You have multiple accounts across providers and different projects need
  access to different subsets.
- Managing OAuth/API key refresh flows across N projects x M accounts is
  operationally painful.
- Agents running in VMs or containers with bypass-mode permissions could
  exfiltrate tokens from disk or environment.
- Real-world policies don't fit neatly into parameter lists --- they need
  scripts, LLM judgment calls, or custom logic per project.

## 2. Goals

1. **Credential isolation.** Real API tokens live inside Sieve's process
   boundary (a Docker container). Agents never see them.
2. **Capability tokens with scriptable policies.** Sieve issues its own
   tokens. Each token's policy can be a simple preset, a Python script,
   an LLM prompt, or a chain of evaluators.
3. **Approval workflows.** Some actions can require human approval via the
   web UI before Sieve executes them.
4. **Connector architecture.** Gmail was the first connector; Slack
   followed. Linear, Jira Cloud, Asana, bank APIs, etc. plug in via the
   same interface. Each connector defines its operations; the policy
   engine is connector-agnostic. See [`docs/connectors-slack.md`](docs/connectors-slack.md)
   for an example of a curated connector with OAuth + direct-token
   install paths.
5. **Multi-connection.** A single Sieve instance manages many connections
   (accounts/workspaces/API keys) across providers. Each token is scoped
   to specific connections.
6. **Audit trail.** Every request is logged with token, connection,
   operation, policy decision, and result.
7. **Core + extensions philosophy.** The core is small (tokens, audit,
   approval, connector interface, policy evaluator interface). New
   connectors and policy logic are extensions that can be added quickly.

## 3. Non-goals (v1)

- The full connector catalogue. Gmail and Slack ship in v1; GitHub, MCP
  proxy, and HTTP proxy round out the v1 set. Linear, Jira Cloud, and
  Asana are spec'd but not yet implemented.
- End-to-end encryption of content at rest inside Sieve.
- Multi-user / multi-tenant. This runs on your machine for your accounts.

---

## 4. Architecture

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │  Your machine                                                          │
 │                                                                        │
 │  ┌──────────────┐         ┌─────────────────────────────────────────┐  │
 │  │  AI Agent     │  MCP /  │  Sieve (Docker container)               │  │
 │  │  (Claude Code │◄──────►│                                          │  │
 │  │   or other)   │  REST   │  ┌──────────────┐  ┌────────────────┐  │  │
 │  └──────────────┘         │  │ Policy       │  │ Connectors     │  │  │
 │                            │  │ Evaluator    │  │                │  │  │
 │  ┌──────────────┐         │  │              │  │ gmail:work ────┼──┼──► Gmail API
 │  │  Web UI       │◄───────┤  │ ┌──────────┐│  │ gmail:personal─┼──┼──► Gmail API
 │  │  (browser)    │  :8080  │  │ │ builtin  ││  │ slack:team ────┼──┼──► Slack API
 │  └──────────────┘         │  │ │ script   ││  │ bank:checking──┼──┼──► Bank API
 │                            │  │ │ llm      ││  │ (future)       │  │  │
 │  ┌──────────────┐         │  │ │ chain    ││  └────────────────┘  │  │
 │  │  Policy       │         │  │ └──────────┘│  ┌───────────────┐  │  │
 │  │  scripts/     │────────►│  └──────────────┘  │ Audit + Queue │  │  │
 │  │  (mounted)    │         │                     └───────────────┘  │  │
 │  └──────────────┘         │                                          │  │
 │                            │  All credentials stored here only        │  │
 │                            └─────────────────────────────────────────┘  │
 └────────────────────────────────────────────────────────────────────────┘
```

### 4.1. Connectors

A **connector** is a plugin that knows how to talk to a specific service.
Each connector type defines:

```go
type Connector interface {
    // Type returns the connector type name (e.g., "gmail", "slack")
    Type() string

    // Operations returns the operations this connector supports
    Operations() []OperationDef

    // Execute performs an operation and returns the result
    Execute(ctx context.Context, op string, params map[string]any) (any, error)

    // Validate checks if credentials are still valid
    Validate(ctx context.Context) error
}

type OperationDef struct {
    Name        string            // e.g., "list_emails", "send_message"
    Description string            // human-readable
    Params      map[string]ParamDef // parameter schema
    ReadOnly    bool              // hint for policy defaults
}
```

v1 ships with the **Gmail connector**. The interface is designed so that
Slack, bank APIs, calendar, etc. can be added as separate Go packages
or (future) as external processes.

### 4.2. Connection model

A **connection** is an instance of a connector with stored credentials:

```
{
  "id": "work",                        // short alias you choose
  "connector": "gmail",                // connector type
  "display_name": "Work Gmail",
  "config": {                          // connector-specific, stored encrypted
    "email": "you@work.com",
    "oauth_token": "<token>"
  },
  "added_at": "2026-04-06T..."
}
```

Connections are added via the Web UI or CLI. The `id` alias is what
tokens and policies reference --- agents never see the underlying
credentials or email addresses.

**Visibility to agents:** An agent only knows about the connection
aliases its token grants access to. It cannot enumerate others. If a
token is scoped to a single connection, the `connection` parameter is
optional on all tool calls.

### 4.3. Agent-facing interfaces

Sieve exposes **two** interfaces to agents. Both enforce the same policy
pipeline.

**MCP Server (primary for Claude Code)**

Sieve registers as an MCP server via `stdio` or `sse` transport. Tools
are **dynamically generated from the connector's operation definitions**.
For a Gmail connector, this produces:

| Tool | Description |
|------|-------------|
| `list_connections` | List connection aliases this token can access |
| `list_emails` | Search/list emails |
| `read_email` | Read a single email by ID |
| `read_thread` | Read an entire thread |
| `create_draft` | Create a draft |
| `update_draft` | Modify an existing draft |
| `send_email` | Send an email (may require approval) |
| `reply` | Reply to a thread (may require approval) |
| `add_label` | Add a label |
| `remove_label` | Remove a label |
| `archive` | Archive a message |
| `list_labels` | List available labels |
| `get_attachment` | Download an attachment |

Every tool accepts an optional `connection` parameter. Each call passes
through the full policy pipeline before reaching the connector.

**REST API (for non-Claude agents)**

```
GET    /api/v1/connections                                 (list accessible)
GET    /api/v1/connections/:conn/ops/:operation             (generic op call)
POST   /api/v1/connections/:conn/ops/:operation             (generic op call)
# Convenience aliases for Gmail:
GET    /api/v1/connections/:conn/messages?q=...             (list/search)
GET    /api/v1/connections/:conn/messages/:id                (read)
POST   /api/v1/connections/:conn/drafts                      (create draft)
POST   /api/v1/connections/:conn/messages/send               (send)
...
Authorization: Bearer sieve_tok_...
```

### 4.4. Human-facing interface

**Web UI on localhost:8080**

- Connection management (add/remove connections, re-authenticate, status)
- Token management (create, revoke, list, inspect tokens)
- Policy editor (select type: preset / script / LLM / chain)
- Approval queue (pending actions awaiting human review)
- Audit log viewer (filterable by connection, token, operation, time)

### 4.5. Isolation model

The Docker container is the trust boundary:

- All service credentials are stored inside the container's volume.
  Never mounted to the host or exposed via API.
- The container exposes only: MCP transport, REST API port, Web UI port.
- Policy scripts from the host are mounted read-only into the container.
- The Sieve API *never* returns credentials in any response.

---

## 5. Token & Policy Model

### 5.1. Token structure

```
{
  "id": "sieve_tok_a3f8...",
  "name": "claude-code-projectX",
  "connections": ["work", "client-a"],  // which connections this token can access
  "created_at": "2026-04-06T...",
  "expires_at": "2026-04-13T...",       // optional TTL
  "policy_type": "script",              // "builtin", "script", "llm", "chain"
  "policy_config": { ... }              // type-specific configuration
}
```

Tokens are opaque bearer strings. Stored hashed (SHA-256) inside Sieve.
The plaintext is shown once at creation time.

### 5.2. Policy evaluator types

The policy engine is pluggable. Each token references a policy evaluator
that decides what happens with every request.

**Every evaluator receives a `PolicyRequest` and returns a `PolicyDecision`:**

```go
type PolicyRequest struct {
    Operation   string         // "read_email", "send_email", etc.
    Connection  string         // connection alias
    Connector   string         // connector type ("gmail", "slack")
    Params      map[string]any // operation parameters
    Metadata    map[string]any // connector-specific metadata (email headers, etc.)
}

type PolicyDecision struct {
    Action     string         // "allow", "deny", "approval_required"
    Reason     string         // human-readable explanation
    Redactions []Redaction    // content to redact from response
}
```

#### Type 1: `builtin` --- Simple declarative rules

For quick setup. This is the traditional parameter-based policy:

```yaml
policy_type: builtin
policy_config:
  operations:
    list_emails: allow
    read_email: allow
    send_email: approval_required
    reply: approval_required
    "*": deny                          # default for unlisted operations
  rate_limits:
    max_reads_per_hour: 100
    max_sends_per_day: 5
```

Ships with named presets: `read-only`, `drafter`, `responder`,
`full-assist`, `triage`.

#### Type 2: `script` --- Python/shell scripts

The real power. A script receives the full request context as JSON on
stdin and writes a decision as JSON to stdout:

```yaml
policy_type: script
policy_config:
  command: "python3"
  script: "/policies/project_x.py"     # mounted from host
  timeout: 5s
```

Example policy script:

```python
#!/usr/bin/env python3
"""Policy for Project X: read work emails about the project, draft only."""
import json, sys

req = json.load(sys.stdin)
op = req["operation"]
meta = req.get("metadata", {})

# Read operations: only emails related to Project X
if op in ("list_emails", "read_email", "read_thread"):
    subject = meta.get("subject", "")
    if "project x" in subject.lower() or op == "list_emails":
        print(json.dumps({"action": "allow"}))
    else:
        print(json.dumps({"action": "deny", "reason": "not related to Project X"}))

# Drafts allowed, sends need approval
elif op == "create_draft":
    print(json.dumps({"action": "allow"}))
elif op in ("send_email", "reply"):
    print(json.dumps({"action": "approval_required"}))
else:
    print(json.dumps({"action": "deny", "reason": f"operation {op} not permitted"}))
```

Scripts run in a subprocess with a timeout. They can be as simple or
complex as needed --- call APIs, read files, use libraries.

#### Type 3: `llm` --- LLM-based evaluation

For nuanced judgment calls. The LLM receives a prompt template with the
request context and returns a decision:

```yaml
policy_type: llm
policy_config:
  provider: bedrock              # or "ollama", "anthropic", "openai"
  model: claude-sonnet-4-6
  prompt: |
    You are a policy evaluator for an AI agent accessing my email.
    The agent is working on Project X (a client website redesign).

    Rules:
    - Allow reading any email from @client.com or about "Project X"
    - Allow drafting replies to those emails
    - Require approval for sending any email
    - Deny access to emails about salary, medical, or legal matters
    - Deny all other operations

    Request: {{request_json}}

    Respond with JSON: {"action": "allow|deny|approval_required", "reason": "..."}
  timeout: 10s
  fallback: deny                 # if LLM call fails
```

#### Type 4: `chain` --- Compose evaluators

Run multiple evaluators in sequence. First `deny` or `approval_required`
wins. All must `allow` for the request to proceed:

```yaml
policy_type: chain
policy_config:
  evaluators:
    - type: builtin
      config:
        operations:
          send_email: approval_required
          "*": allow
    - type: script
      config:
        command: "python3"
        script: "/policies/redact_sensitive.py"
    - type: llm
      config:
        provider: ollama
        model: llama3
        prompt: "Is this request reasonable? {{request_json}}"
        fallback: allow
```

### 5.3. Policy presets (builtin type)

| Preset | Description |
|--------|-------------|
| `read-only` | List + read only, everything else deny |
| `drafter` | Read + drafts, sends require approval |
| `responder` | Read + reply with approval, no new threads |
| `full-assist` | Everything allowed, sends require approval |
| `triage` | Read + label + archive, no compose/send |

### 5.4. Connection-specific policy overrides

For tokens with multiple connections, the token can specify per-connection
policy overrides that are evaluated **after** the main policy (can only
further restrict, never widen):

```yaml
connection_overrides:
  client-a:
    policy_type: builtin
    policy_config:
      operations:
        send_email: deny
        create_draft: deny
        "*": allow
```

---

## 6. Approval Queue

When a policy evaluator returns `approval_required`:

1. Sieve stores the pending action (full request data).
2. The Web UI shows it in the approval queue with:
   - Which token/agent requested it
   - Connection and operation
   - Full content preview
   - One-click Approve / Reject / Edit-then-Approve
3. Optional: webhook notification when items enter the queue.
4. The agent's request blocks (with a timeout) or returns a
   `pending_approval` status that the agent can poll.
5. On approval, Sieve executes the action and returns the result.

---

## 7. Content Filtering

Content filtering is handled by the policy evaluator itself. A `script`
or `llm` policy can inspect response data and return `redactions`:

```python
# In a policy script, for a read_email response:
result = json.load(sys.stdin)
body = result.get("metadata", {}).get("body", "")

redactions = []
# Redact SSNs
import re
for match in re.finditer(r'\b\d{3}-\d{2}-\d{4}\b', body):
    redactions.append({"field": "body", "start": match.start(), "end": match.end()})

print(json.dumps({"action": "allow", "redactions": redactions}))
```

For the `builtin` policy type, simple regex redaction patterns can be
specified in the config. But for anything sophisticated, use a `script`
or `chain` policy that includes an LLM-based content reviewer.

The key insight: **content filtering is just another policy evaluation**,
not a separate system. This avoids a separate "LLM filter" subsystem.

---

## 8. Audit Log

Every interaction is logged to a structured append-only log:

```json
{
  "timestamp": "2026-04-06T14:23:01Z",
  "token_id": "sieve_tok_a3f8...",
  "token_name": "claude-code-projectX",
  "account": "work",
  "operation": "read_email",
  "params": {"message_id": "18f3a..."},
  "policy_result": "allow",
  "llm_filter_action": "redact",
  "gmail_api_call": "GET /gmail/v1/users/me/messages/18f3a...",
  "response_summary": "1 message returned, 2 fields redacted",
  "duration_ms": 342
}
```

The Web UI provides:
- Filterable log viewer (by token, operation, time range, policy result)
- Per-token activity summary (what did this agent do today?)
- Anomaly highlights (unusual patterns, spikes in access)

---

## 9. Implementation

### 9.1. Tech stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Core server | **Go** | Single binary, low resource usage, good concurrency, easy Docker image |
| Web UI | **Embedded SPA** (Svelte or React) | Bundled into the Go binary for zero-dependency deployment |
| Database | **SQLite** | Single-file, no external deps, sufficient for single-user |
| MCP transport | `stdio` and `sse` | stdio for Claude Code subprocess, SSE for remote agents |
| LLM integration | HTTP client | Call Ollama (local) or cloud APIs |
| Gmail client | Google API Go SDK | Well-maintained, handles OAuth refresh |

### 9.2. Project structure

```
sieve/
├── cmd/
│   └── sieve/                # CLI entrypoint
│       └── main.go
├── internal/
│   ├── connector/            # Connector interface + registry
│   │   └── connector.go
│   ├── connectors/
│   │   └── gmail/            # Gmail connector implementation
│   │       └── gmail.go
│   ├── connections/          # Connection registry (CRUD for instances)
│   │   └── connections.go
│   ├── policy/               # Policy evaluator interface + types
│   │   ├── policy.go         # Interface, types, registry
│   │   ├── builtin.go        # Builtin evaluator
│   │   ├── script.go         # Script evaluator (subprocess)
│   │   ├── llm.go            # LLM evaluator
│   │   ├── chain.go          # Chain evaluator
│   │   └── presets.go        # Named presets
│   ├── tokens/               # Token CRUD, hashing, storage
│   │   └── tokens.go
│   ├── approval/             # Approval queue logic
│   │   └── queue.go
│   ├── audit/                # Audit logging
│   │   └── audit.go
│   ├── database/             # SQLite database layer
│   │   └── database.go
│   ├── mcp/                  # MCP server implementation
│   │   └── server.go
│   ├── api/                  # REST API handlers
│   │   └── router.go
│   └── web/                  # Web UI (Go templates + htmx)
│       ├── server.go
│       └── templates/
├── policies/                 # Example policy scripts
│   ├── project_x.py
│   └── redact_sensitive.py
├── Dockerfile
├── docker-compose.yml
└── sieve.yaml
```

### 9.3. Configuration

Single YAML file:

```yaml
# sieve.yaml
server:
  host: "127.0.0.1"       # never bind to 0.0.0.0 by default
  api_port: 8081
  ui_port: 8080
  mcp_transport: "sse"     # or "stdio"

connectors:
  gmail:
    client_credentials_file: "/data/gmail_credentials.json"
  # Future connectors configured here:
  # slack:
  #   client_id: "..."
  #   client_secret: "..."

policy:
  scripts_dir: "/policies"   # mounted from host, read-only
  llm_providers:             # available LLM providers for policy evaluation
    ollama:
      endpoint: "http://host.docker.internal:11434"
    bedrock:
      region: "us-east-1"
    # anthropic:
    #   api_key_env: "ANTHROPIC_API_KEY"

audit:
  retention_days: 90

database:
  path: "/data/sieve.db"
```

### 9.4. Deployment

```bash
# Build
docker build -t sieve .

# Run
docker run -d \
  --name sieve \
  -p 127.0.0.1:8080:8080 \
  -p 127.0.0.1:8081:8081 \
  -v sieve-data:/data \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  sieve

# First-time setup: open http://localhost:8080

# Add Gmail connections (opens browser for OAuth consent)
docker exec sieve sieve connection add --alias work --connector gmail
docker exec sieve sieve connection add --alias personal --connector gmail
docker exec sieve sieve connection add --alias client-a --connector gmail

# List connections
docker exec sieve sieve connection list
# ALIAS       CONNECTOR   DETAILS                 STATUS
# work        gmail       you@work.com            connected
# personal    gmail       you@gmail.com           connected
# client-a    gmail       client@company.com      connected

# Create a token with a builtin preset policy
docker exec sieve sieve token create \
  --name "claude-project-x" \
  --connections work,client-a \
  --policy-type builtin \
  --preset drafter \
  --expires 7d

# Or with a policy script (mounted in /policies)
docker exec sieve sieve token create \
  --name "claude-project-y" \
  --connections work \
  --policy-type script \
  --script "/policies/project_y.py" \
  --expires 7d

# Output: sieve_tok_a3f8e7... (save this, shown only once)
```

### 9.5. Claude Code integration

Add to `.claude/settings.json` or project `.mcp.json`:

```json
{
  "mcpServers": {
    "sieve": {
      "type": "sse",
      "url": "http://localhost:8081/mcp",
      "headers": {
        "Authorization": "Bearer sieve_tok_a3f8e7..."
      }
    }
  }
}
```

Then in Claude Code, the agent sees tools like `list_emails`,
`read_email`, `create_draft`, etc. --- each call passes through
the full policy pipeline.

---

## 10. Security Considerations

| Threat | Mitigation |
|--------|-----------|
| Agent reads service credentials | All credentials stored in container-only volume; API never exposes them; container runs with `no-new-privileges` and dropped capabilities |
| Agent brute-forces Sieve tokens | Tokens are 256-bit random; rate limiting on auth failures |
| Agent escalates permissions | Tokens are immutable after creation; no API to modify a token's policy; connection list is fixed at creation |
| Agent accesses wrong connection | Token is bound to specific connection aliases; requests to others return 403; agent cannot enumerate connections outside its scope |
| Policy script escape | Scripts run with timeout; mounted read-only; no write access to Sieve internals |
| Agent exfiltrates data via tool output | Policy scripts/LLM can redact content; audit log tracks volume; rate limits cap throughput |
| Token leaked in logs/config | Tokens are shown once at creation; stored hashed in DB |
| Container escape | Run with minimal capabilities, read-only rootfs, non-root user |
| Network exposure | Bind to 127.0.0.1 only; never expose to LAN/internet |

---

## 11. Future Directions (post v1)

- **More connectors**: Slack, Outlook/Microsoft Graph, Google Calendar/Drive,
  bank APIs (Plaid), Notion, Linear, etc.
- **External connector protocol**: Run connectors as separate processes
  that communicate with Sieve via a simple JSON protocol (like LSP for
  services). This lets people write connectors in any language.
- **Token delegation**: A token can mint sub-tokens with equal or lesser permissions
- **Webhook notifications**: Push to Slack/webhook when approval is needed
- **Agent reputation**: Track per-token success/rejection rates, auto-adjust limits
- **Shared instance**: Multi-user mode for teams
- **Policy marketplace**: Share and discover policy scripts for common use cases

---

## 12. Name Rationale

**Sieve** --- a device that separates what passes through based on rules.
In email, [Sieve (RFC 5228)](https://tools.ietf.org/html/rfc5228) is the
standard language for mail filtering. More broadly, the name captures the
core function: every API call passes through the sieve, and only what
matches the policy comes out the other side. Works equally well for email,
chat, financial data, or any other service.
