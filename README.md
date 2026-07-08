# Sieve

**A credential gateway for AI agents.**

Sieve sits between your AI agents and the services they need — Gmail, AWS, LLM APIs, any HTTP API. It holds the real credentials. Agents get scoped sub-tokens with fine-grained policies. You stay in control.

## The problem

You run AI agents — Claude Code, Codex, custom scripts — across projects. These agents are productive when they can access your email, call LLMs, spin up cloud resources. But:

**You can't just hand them your API keys.**

- **Gmail OAuth tokens give full account access.** There's no Gmail scope for "read only emails about Project X" or "draft but never send."
- **LLM API keys are all-or-nothing.** You can't restrict an agent to a specific model, cap spending, or filter what it sends in prompts.
- **AWS IAM policies can do fine-grained permissions, but they're painful.** You either spend hours writing JSON IAM policies across multiple AWS consoles, or you hand over broad access and hope for the best. Sieve lets you write quick, local rules without touching AWS IAM at all.
- **Credentials given to agents are hard to control.** They end up on provider servers, in logs, in prompt history. Revoking means logging into each service's website — Google Cloud Console, AWS IAM, Anthropic dashboard, OpenAI platform — rotating the key, and updating every project that uses it. With 5 services and 10 projects, that's 50 touch points.

## Why Sieve

### Fine-grained permissions beyond what APIs offer

Gmail's permission model has three scopes: readonly, send, modify. Sieve lets you say:

- "Read only emails labeled `project-x`"
- "Draft replies but hold sends for my approval"
- "Never return emails containing the word CONFIDENTIAL"
- "Only emails from `@client.com` are visible"

AWS IAM can do this natively, but writing JSON IAM policies is slow and error-prone. Sieve lets you say the same thing in seconds:

- "Only `t3.micro` instances, max 3, in `us-east-1` only"
- "S3 read-only on bucket `data-exports`, prefix `2024/`"
- "No `0.0.0.0/0` security group rules ever"

LLM APIs have no usage controls. Sieve lets you say:

- "Only `claude-sonnet`, never `opus`"
- "Max $0.50 per request"
- "Require approval for any prompt containing customer data"

These policies are composable. Create a "gmail-drafter" policy, a "redact-pii" policy, and a "sonnet-only" policy. Assign all three to one agent token.

### Compromised sub-tokens are not a disaster

This matters more than it sounds. AI agents are a new attack surface:

- **Prompt injection.** A malicious email or document tricks the agent into exfiltrating data or calling APIs it shouldn't.
- **Supply chain attacks.** An MCP server, VS Code extension, or npm package the agent uses is compromised.
- **Credential leakage.** The agent's context window, logs, or tool outputs end up somewhere they shouldn't. Anthropic, OpenAI, and Google all see the tokens your agent sends through their APIs.

With raw credentials, any of these scenarios is a full compromise. You have to rotate the API key, re-authenticate OAuth, update every project that uses it.

With Sieve sub-tokens:

- **Tokens expire quickly.** Set a 24-hour TTL. The agent gets a fresh token each session. A leaked token is useless tomorrow.
- **Tokens are revocable in one click.** No need to touch the real credential. The Google OAuth token, the AWS access key — they stay safe inside Sieve.
- **Tokens are scoped.** Even if compromised, the attacker can only do what the policy allows. A read-only Gmail token can't send email. A sonnet-only LLM token can't use opus.
- **IP restrictions** (planned). Sieve can restrict tokens to your machine's IP. An exfiltrated token is useless from anywhere else.
- **The real credentials never leave your machine.** They live inside Sieve's process boundary (or Docker container). The agent never sees them.

### One place to manage everything

Without Sieve, each project manages its own OAuth tokens, API keys, refresh flows. You have N projects x M services = N*M credential management problems.

With Sieve:
- Connect your Google account **once**. Every project uses a scoped sub-token.
- Add your Anthropic API key **once**. Every agent gets its own sub-token with its own model/cost policy.
- Revoke an agent's access **in one click**. Create a new token in seconds.
- See **every API call** every agent made in the audit log.

## How it works

```
 Agent (Claude Code)          Sieve                    Service (Gmail, AWS, ...)
         |                      |                              |
         |  sieve_tok_xxx       |                              |
         |--------------------->|                              |
         |                      |  1. Validate token           |
         |                      |  2. Evaluate policy (pre)    |
         |                      |  3. Forward with real creds  |
         |                      |------------------------------>|
         |                      |<------------------------------|
         |                      |  4. Evaluate policy (post)   |
         |                      |  5. Filter/redact response   |
         |  filtered response   |                              |
         |<---------------------|                              |
```

Two-phase policy evaluation: pre-execution (should this operation happen?) and post-execution (should this response be returned?). This enables content filtering that requires seeing the actual data.

## Setup

### Prerequisites

- Go 1.23+ (for building from source) or Docker
- A Google Cloud project with OAuth credentials (for Gmail/Drive/Calendar) — see [Google OAuth setup guide](docs/google-oauth-setup.md) for a 5-minute walkthrough

### Run locally

```bash
git clone https://github.com/trilitech/Sieve
cd sieve

# Build
go build -o sieve ./cmd/sieve

# First run: initialize the keyring (prompts twice for a passphrase
# you'll re-enter on every subsequent start; this passphrase derives
# the key that encrypts every stored credential).
./sieve --setup

# Subsequent runs (or non-interactive start via SIEVE_PASSPHRASE_FILE
# / FD 3 — never an environment variable):
./sieve
# Web UI: http://localhost:19816  (admin only — do not expose to agents)
# API/MCP: http://localhost:19817
```

**First-run admin setup.** On the very first visit to the Web UI, Sieve has no
admin operator yet, so http://localhost:19816 redirects you to **`/setup`** (a
loopback-only page) to create the first admin credential + display name. Set it,
log in, and you land on the connections dashboard. Every subsequent visit uses
the normal `/login` page.

Common flags: `--db PATH` (default `./data/sieve.db`), `--web HOST:PORT`,
`--api HOST:PORT`, `--google-credentials FILE` (auto-discovered from cwd
if a `*client_secret*.json` is present). To distribute Sieve with your own
OAuth apps, also `--google-oauth-client-id` / `--slack-client-id` (and their
`*-secret` variants) — see [CLI reference → OAuth app client flags](docs/cli-reference.md#oauth-app-client-flags).

> **Note on upgrading from an older dev build:** the `connections` table schema
> changed to encrypted columns. On first start against a pre-encryption DB,
> Sieve drops the `connections` table. Reconnect your services once after
> upgrade — everything else (policies, roles, tokens, audit log) is preserved.
> See [docs/credential-encryption.md](docs/credential-encryption.md).

### Run with Docker

```bash
docker compose run --rm -it sieve --setup        # one-time keyring init
docker compose run --rm -it --service-ports sieve  # start (TTY passphrase prompt)
```

For non-interactive deployments (systemd, CI, `docker compose up -d`), the
TTY prompt won't work — point Sieve at a passphrase file with
`SIEVE_PASSPHRASE_FILE=/path/to/file` (env var stays out of the process'
secrets). See [docs/credential-encryption.md](docs/credential-encryption.md).

The Docker image comes with a batteries-included Python environment (requests, httpx, pandas, numpy, anthropic, openai, tiktoken, beautifulsoup4, pydantic) for policy scripts.

## Connect services

### Google (Gmail, Drive, Calendar, Contacts, Sheets, Docs)

1. Open http://localhost:19816/connections
2. Click **Connect Google Account**
3. Complete the OAuth flow
4. One connection, six services — policies control which ones the agent can use

### Slack (channels, users, history, threads, messages)

Two install paths — see [`docs/connectors-slack.md`](docs/connectors-slack.md) for the full walkthrough including required bot scopes and troubleshooting.

**OAuth path:**
1. Set `SLACK_CLIENT_ID` and `SLACK_CLIENT_SECRET` in Sieve's environment (from your Slack app's Basic Information page).
2. Open http://localhost:19816/connections → pick **Slack** → **Install via OAuth** → approve in Slack.
3. Connection lands `status: active`. Agents can list channels, read history, search threads, and post messages — subject to policies.

**Direct bot-token path** (for Slack apps you've already installed):
1. From your Slack app's **OAuth & Permissions** page, copy the bot token (`xoxb-…`).
2. **Add Connection** → **Slack** → **Use existing bot token** → paste and submit.
3. Sieve calls `auth.test` against Slack; on success the connection lands `active`. The token is encrypted at rest — never written to a plaintext column or logged.

Curated operations: `list_channels`, `list_users`, `read_user_profile`, `read_channel_history`, `read_thread`, `post_message`. (`search_messages` is exposed for policy bindings but disabled in v1 — it requires a user-token install which is on the roadmap.)

Multi-workspace setups work — add a second Slack connection with a different alias and address each by name through the agent-facing API.

### LLM APIs (Anthropic, OpenAI, Gemini, Bedrock)

1. Go to Connections → LLM API
2. Click the provider card (e.g., Anthropic)
3. Paste your API key
4. Done — the key stays in Sieve, agents get sub-tokens

### AWS (EC2, S3, Lambda, SES, DynamoDB)

1. Go to Connections → Cloud
2. Enter your AWS access key, secret key, and region
3. Policies control which services and operations the agent can use

### Any HTTP API

1. Go to Connections → HTTP Proxy
2. Enter the target URL, auth header, and your real API key
3. Agents access it via `http://localhost:19817/proxy/{connection}/path`

## Create policies

Policies are reusable rule lists. Each rule has conditions and an action: **allow**, **deny**, **require approval**, or **run script**.

### Built-in presets

- **read-only** — list + read emails, nothing else
- **drafter** — read + draft, sends require approval
- **full-assist** — everything allowed, sends require approval
- **triage** — read + label + archive, no compose/send

### Custom rules

Rules are evaluated top-to-bottom, first match wins:

```
Rule 1: IF operation = send_email, reply  →  Require Approval
Rule 2: IF operation = read_email, label = project-x  →  Allow
Rule 3: IF content contains "CONFIDENTIAL"  →  Deny (post-phase)
Rule 4: Default: Deny
```

### Script rules

For complex logic, write a Python script. Or click the AI button, describe what you want in English, and Sieve generates the script using your configured LLM.

```python
#!/usr/bin/env python3
# Policy: Only allow emails from @company.com about Project X
import json, sys
req = json.load(sys.stdin)
phase = req.get("metadata", {}).get("phase", "pre")
if phase == "post":
    response = req["metadata"].get("response", "")
    data = json.loads(response)
    if "emails" in data:
        filtered = [e for e in data["emails"]
                   if "@company.com" in e.get("from", "")]
        data["emails"] = filtered
        print(json.dumps({"action": "allow", "rewrite": json.dumps(data)}))
    else:
        print(json.dumps({"action": "allow"}))
else:
    print(json.dumps({"action": "allow"}))
```

## Roles

Roles bundle connections with policies. A role defines which connections an agent can access and which policies govern each connection. Tokens reference a role rather than listing connections and policies directly.

A role looks like this in storage:

```json
{
  "name": "developer",
  "bindings": [
    {"connection_id": "work",       "policy_ids": ["drafter", "redact-pii"]},
    {"connection_id": "anthropic",  "policy_ids": ["sonnet-only"]}
  ]
}
```

One role can be shared by many tokens. When you update a role's bindings, every token referencing that role picks up the change immediately. This makes it easy to manage permissions across many agents at once.

Manage roles via the web UI at http://localhost:19816/roles.

## Create tokens

Tokens reference a role, which bundles connections with policies. One token per agent. Create them in the web UI at http://localhost:19816/tokens — the plaintext `sieve_tok_…` is shown exactly once when minted.

## Agent integration

### Claude Code (MCP)

Claude Code speaks Sieve's HTTP transport directly. Add to your project's `.mcp.json` (or `~/.claude/mcp.json` for all projects):

```json
{
  "mcpServers": {
    "sieve": {
      "type": "http",
      "url": "http://localhost:19817/mcp",
      "headers": {
        "Authorization": "Bearer sieve_tok_xxxxx"
      }
    }
  }
}
```

`sieve token create` prints this snippet for you. The agent sees tools like `list_emails`, `read_email`, `create_draft` — each call goes through Sieve's policy pipeline.

### Claude Desktop (MCP)

Claude Desktop only supports stdio MCP servers, so use the built-in `sieve mcp-launch` bridge — it pulls the bearer token from the macOS Keychain so it never lives in plaintext on disk:

```bash
# 1. Install sieve to a directory on Claude Desktop's PATH
go install ./cmd/sieve   # lands at ~/go/bin/sieve

# 2. Store the token in Keychain (mint one at http://localhost:19816/tokens first)
security add-generic-password -a "$USER" -s sieve-token -w 'sieve_tok_xxxxx'
```

Then edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sieve": {
      "command": "sieve",
      "args": ["mcp-launch"]
    }
  }
}
```

Fully quit Claude Desktop (⌘Q) and reopen. See [docs/mcp-integration.md#claude-desktop-configuration](docs/mcp-integration.md#claude-desktop-configuration) for multi-token setups, the non-macOS file fallback, and troubleshooting.

### Gmail REST API

Any Gmail client library works. Just change the base URL:

```python
# Python
from googleapiclient.discovery import build
service = build("gmail", "v1", credentials=SieveCredentials())
service._baseUrl = "http://localhost:19817/gmail/v1/"
```

```bash
# curl
curl http://localhost:19817/gmail/v1/users/me/messages?q=project \
  -H "Authorization: Bearer sieve_tok_xxxxx"
```

Multi-account: use the connection alias as the userId:
```
GET /gmail/v1/users/work/messages    # work account
GET /gmail/v1/users/personal/messages # personal account
GET /gmail/v1/users/me/messages       # default (first) account
```

### HTTP proxy (any API)

```bash
# Anthropic via Sieve
curl http://localhost:19817/proxy/anthropic/v1/messages \
  -H "Authorization: Bearer sieve_tok_xxxxx" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-sonnet-4-20250514","messages":[...]}'

# OpenAI via Sieve
curl http://localhost:19817/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer sieve_tok_xxxxx" \
  -d '{"model":"gpt-4o","messages":[...]}'
```

The agent never sees the real API key. Sieve swaps the sub-token for the real credential transparently.

### MCP built-in tools

Every MCP session exposes five built-in tools alongside the connector-specific tools (like `list_emails`, `drive_list_files`, etc.):

| Tool | Description |
|------|-------------|
| `list_connections` | Discover what service connections are available to this token |
| `list_policies` | List all policies with their names and rule summaries |
| `get_my_policy` | See the full rules that apply to this token (per-connection) |
| `get_policy_schema` | Get the complete JSON schema for policy rules — useful before proposing changes |
| `propose_policy` | Propose a new policy or changes to an existing one (goes to admin approval queue) |

See [MCP Integration Guide](docs/mcp-integration.md) for protocol details and examples.

## Approval queue

When a policy returns "require approval", the operation is held:

1. Agent submits the request
2. Sieve returns immediately (MCP: text response, Gmail API: 429 with Retry-After)
3. The request appears in the approval queue at http://localhost:19816/approvals
4. You review and click Approve or Reject
5. On approval, the operation executes

Agents can also propose new policies via MCP (`propose_policy` tool). Proposals go through the same approval queue.

## Audit log

Every request is logged at http://localhost:19816/audit with:
- Token name and ID
- Connection
- Operation
- Policy decision (allow, deny, approval_required)
- Duration

Filter by token, connection, operation, or date range.

## AI script generation

1. Go to Settings, configure your LLM connection and model
2. In the policy builder, select "Run Script"
3. Click the sparkle icon
4. Describe what you want: *"Only allow emails from @company.com, redact phone numbers"*
5. Sieve generates a Python script using your LLM
6. Review, approve, done

## Architecture

Sieve runs two HTTP servers on separate ports:

- **Port 19817** (API/MCP) — for agents. All traffic authenticated with Sieve tokens, all operations go through the policy pipeline.
- **Port 19816** (Web UI) — for you. Connection management, policy editor, approval queue, audit log, settings. Not exposed to agents.

This separation means an agent cannot access the admin UI even if it knows the URL — it's on a different port that you don't give it.

Data is stored in SQLite (single file at `./data/sieve.db`, WAL mode, `chmod 0600`).

### Credential encryption at rest

Every stored credential (OAuth refresh tokens, LLM API keys, HTTP proxy keys) is encrypted with envelope encryption before it touches the DB:

- A passphrase you enter at startup is stretched with **argon2id** into a 32-byte KEK held only in process memory.
- Each `connections` row has its own random **DEK** (per-record data-encryption key). The DEK encrypts the config JSON under **AES-256-GCM**, and is itself wrapped under the KEK.
- Stopping Sieve → the KEK is gone. A stolen DB file, backup, snapshot, or SQLi read against `connections.config_ciphertext` yields only ciphertext.

The trade-off: **reboot requires re-entering the passphrase.** Sieve refuses to start without one. You can automate this for non-interactive deployments by pointing `SIEVE_PASSPHRASE_FILE` at a mounted secret file (e.g., systemd `LoadCredential=`, Docker secrets).

Full threat model, rotation procedure, and deployment recipes: [docs/credential-encryption.md](docs/credential-encryption.md).

## Configuration

```yaml
# sieve.yaml
server:
  host: "127.0.0.1"   # bind address (0.0.0.0 for all interfaces)
  api_port: 19817      # agent-facing API/MCP port
  ui_port: 19816       # human-facing web UI port
  # Optional: path to a file containing the keyring passphrase. If unset,
  # Sieve prompts on TTY or reads from SIEVE_PASSPHRASE_FILE / FD 3.
  # passphrase_file: "/run/secrets/sieve-passphrase"

connectors:
  google:
    client_credentials_file: "./data/gmail_credentials.json"

policy:
  scripts_dir: "./policies"

database:
  path: "./data/sieve.db"
```

## License

MIT
