# CLI Reference

Sieve provides a command-line interface for server management, connection setup, token administration, role configuration, and policy management.

```
sieve <command> [arguments]
```

## sieve serve

Start the Sieve server. This launches two HTTP servers on separate ports:

- **API/MCP port** (default 19817) -- agent-facing traffic. Handles MCP (JSON-RPC 2.0), the REST API, the Gmail-compatible API, and the HTTP proxy. All requests require a valid Sieve token.
- **Web UI port** (default 19816) -- human-facing admin interface. Connection management, policy editor, approval queue, audit log, settings. Not exposed to agents.

```bash
sieve serve
```

The server reads configuration from `sieve.yaml`, searched in the following order:

1. `./sieve.yaml` (current directory)
2. `/etc/sieve/sieve.yaml`
3. `/data/sieve.yaml`

If no config file is found, built-in defaults are used (`127.0.0.1:19817` for API, `127.0.0.1:19816` for UI, `./data/sieve.db` for database).

On startup the server:

- Opens (or creates) the SQLite database
- Registers connector types (Google, HTTP Proxy, MCP Proxy)
- Initializes all saved connections
- Seeds built-in policy presets (read-only, drafter, full-assist, triage)
- Starts an audit log cleanup goroutine (purges entries older than 90 days, runs daily)

Graceful shutdown on SIGINT or SIGTERM with a 5-second timeout.

---

## sieve connection

Manage service connections (Google accounts, API keys, HTTP proxies).

### sieve connection add

Add a new connection. The OAuth flow or credential entry is completed via the web UI after adding.

```bash
sieve connection add --alias <alias> --connector <type> [--display-name <name>]
```

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--alias` | Yes | Unique identifier for this connection (e.g., `work`, `personal`, `anthropic`) |
| `--connector` | Yes | Connector type: `google`, `httpproxy`, or `mcpproxy` |
| `--display-name` | No | Human-readable name (defaults to the alias) |

**Examples:**

```bash
# Add a Google connection (complete OAuth at http://localhost:19816/connections)
sieve connection add --alias work --connector google --display-name "Work Gmail"

# Add an HTTP proxy connection
sieve connection add --alias anthropic --connector httpproxy
```

### sieve connection list

List all configured connections.

```bash
sieve connection list
```

Output columns: ALIAS, CONNECTOR, DISPLAY NAME, CREATED.

### sieve connection remove

Remove a connection by alias.

```bash
sieve connection remove <alias>
```

**Example:**

```bash
sieve connection remove personal
```

---

## sieve role

Manage roles. A role is a reusable bundle of connection+policy bindings. Tokens reference roles instead of directly listing connections and policies.

### sieve role list

List all roles.

```bash
sieve role list
```

Output columns: ID, NAME, BINDINGS (count), CREATED.

### sieve role create

Create a new role with connection-to-policy bindings.

```bash
sieve role create --name <name> --bindings <json>
```

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--name` | Yes | Unique name for the role |
| `--bindings` | No | JSON array of binding objects. Each binding has `connection_id` (string) and `policy_ids` (array of strings). |

The bindings JSON format:

```json
[
  {
    "connection_id": "work",
    "policy_ids": ["drafter", "redact-pii"]
  },
  {
    "connection_id": "anthropic",
    "policy_ids": ["sonnet-only"]
  }
]
```

**Examples:**

```bash
# Role with one connection, two policies
sieve role create --name reader \
  --bindings '[{"connection_id":"work","policy_ids":["read-only"]}]'

# Role with multiple connections
sieve role create --name developer \
  --bindings '[{"connection_id":"work","policy_ids":["drafter","redact-pii"]},{"connection_id":"anthropic","policy_ids":["sonnet-only"]}]'

# Empty role (no bindings yet -- add them via the web UI)
sieve role create --name placeholder
```

### sieve role delete

Delete a role by ID.

```bash
sieve role delete <id>
```

---

## sieve token

Manage capability tokens issued to AI agents.

### sieve token create

Create a new token referencing a role.

```bash
sieve token create --name <name> --role <role-name> [--expires <duration>]
```

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--name` | Yes | Human-readable name for the token (e.g., `proj-x-agent`) |
| `--role` | Yes | Name of the role this token should reference |
| `--expires` | No | Token TTL as a Go duration (e.g., `168h` for 7 days, `720h` for 30 days). Omit for no expiry. |

On success, the command prints:
- Token ID and metadata
- The plaintext token (shown only once -- save it)
- A ready-to-use `.mcp.json` config snippet

**Examples:**

```bash
# Create a token that expires in 7 days
sieve token create --name proj-x --role developer --expires 168h

# Create a non-expiring token
sieve token create --name analyst --role read-only
```

If the role name doesn't exist, the command prints available role names.

### sieve token list

List all tokens with their status.

```bash
sieve token list
```

Output columns: ID, NAME, ROLE ID, STATUS (`active`, `revoked`, or `expired`), EXPIRES.

### sieve token revoke

Revoke a token immediately. Revoked tokens can no longer authenticate.

```bash
sieve token revoke <id>
```

**Example:**

```bash
sieve token revoke tok_abc123
```

---

## sieve policy

Manage policies (rule lists that govern what operations agents can perform).

### sieve policy list

List all policies.

```bash
sieve policy list
```

Output columns: ID, NAME, TYPE, CREATED.

### sieve policy create

Create a new policy.

```bash
sieve policy create --name <name> --type <type> [--config <json>]
```

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--name` | Yes | Unique name for the policy |
| `--type` | Yes | Policy type: `rules` (declarative rules) or `script` (external script) |
| `--config` | No | JSON object with the policy configuration. For `rules` type, this contains `rules`, `default_action`, and `scope`. |

**Examples:**

```bash
# Create a simple deny-all policy
sieve policy create --name deny-all --type rules \
  --config '{"default_action":"deny","rules":[]}'

# Create a read-only Gmail policy
sieve policy create --name gmail-readonly --type rules \
  --config '{"default_action":"deny","rules":[{"match":{"operations":["list_emails","read_email","read_thread","list_labels","get_attachment"]},"action":"allow"}]}'

# Create a policy with approval for sends
sieve policy create --name drafter --type rules \
  --config '{"default_action":"deny","rules":[{"match":{"operations":["list_emails","read_email","read_thread","list_labels","get_attachment","create_draft","update_draft"]},"action":"allow"},{"match":{"operations":["send_email","send_draft","reply"]},"action":"approval_required"}]}'
```

See [Policy Rules Reference](policy-rules-reference.md) for the full configuration schema.

### sieve policy delete

Delete a policy by ID.

```bash
sieve policy delete <id>
```

---

## sieve version

Print the Sieve version.

```bash
sieve version
# Output: sieve v0.1.0
```

## sieve help

Print the usage summary.

```bash
sieve help
```
