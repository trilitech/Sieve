# Setting Up Connections

This guide walks through setting up every connection type in Sieve. Connections hold the real credentials for external services. Agents never see these credentials -- they use scoped Sieve tokens instead.

All connection setup happens in the Sieve web UI at `http://localhost:19816/connections`.

## Google Account

A single Google connection provides access to six services: Gmail, Drive, Calendar, Contacts (People API), Sheets, and Docs -- over 35 operations total. Policies control which operations the agent can use.

### Prerequisites

- A Google Cloud project with OAuth 2.0 credentials (client ID and client secret).
- The OAuth consent screen configured with the necessary scopes.

If you have not set up Google OAuth credentials yet, follow the [Google OAuth setup guide](google-oauth-setup.md) for a step-by-step walkthrough.

### Setup steps

1. Open `http://localhost:19816/connections`.
2. Under the **Google** category, find the **Google Account** card.
3. Enter a **Connection Alias** (e.g., `work`). This is how agents and API paths will reference this connection.
4. Enter a **Display Name** (e.g., "Work Gmail"). This is shown in the Sieve UI.
5. Click **Connect Google Account**.
6. You will be redirected to Google's OAuth consent screen. Sign in with the Google account you want to connect and grant the requested permissions.
7. After completing OAuth, you are redirected back to Sieve. The connection appears in the Active Connections table.

### What you get

One row in the Active Connections table showing:

| Alias | Service | Display Name | Added |
|-------|---------|--------------|-------|
| work  | google  | Work Gmail   | just now |

The agent can now use any of these operations (subject to policies):

- **Gmail**: list_emails, read_email, read_thread, create_draft, update_draft, send_email, send_draft, reply, add_label, remove_label, archive, list_labels, get_attachment
- **Drive**: drive.list_files, drive.get_file, drive.download_file, drive.upload_file, drive.share_file
- **Calendar**: calendar.list_events, calendar.get_event, calendar.create_event, calendar.update_event, calendar.delete_event
- **People**: people.list_contacts, people.get_contact, people.create_contact, people.update_contact, people.delete_contact
- **Sheets**: sheets.get_spreadsheet, sheets.read_range, sheets.write_range, sheets.create_spreadsheet
- **Docs**: docs.get_document, docs.list_documents, docs.create_document, docs.update_document

### How the agent accesses it

**Via MCP:** Tools appear as `list_emails`, `drive_list_files`, `calendar_create_event`, etc. (dots replaced with underscores). With multiple Google connections, tools are prefixed: `work_list_emails`, `personal_list_emails`.

**Via Gmail REST API:** Use the connection alias as the userId in the path:
```
GET /gmail/v1/users/work/messages       # "work" connection
GET /gmail/v1/users/personal/messages   # "personal" connection
GET /gmail/v1/users/me/messages         # default (first) connection
```

### Multi-account

Add multiple Google connections with different aliases. For example, `work` for your work account and `personal` for your personal account. Each goes through its own OAuth flow and holds its own credentials. You can apply different policies to each in the same role.

## LLM Providers

LLM provider connections are HTTP proxy connections with pre-configured target URLs and auth headers. The agent sends requests through Sieve; Sieve swaps the token for the real API key.

### Anthropic (Claude)

1. Go to `http://localhost:19816/connections`.
2. Under **LLM Providers**, find the **Anthropic (Claude)** card.
3. Enter a **Connection Alias** (e.g., `anthropic`).
4. Enter a **Display Name** (e.g., "Claude").
5. Enter your **API Key** (starts with `sk-ant-api03-...`). Get one at [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys).
6. Click **Connect Anthropic**.

What is created: an HTTP proxy connection with target `https://api.anthropic.com`, auth header `x-api-key`, and extra headers `anthropic-version: 2023-06-01` and `content-type: application/json`.

**Agent access via proxy:**
```bash
curl http://localhost:19817/proxy/anthropic/v1/messages \
  -H "Authorization: Bearer sieve_tok_xxxxx" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"Hello"}]}'
```

### OpenAI

1. Under **LLM Providers**, find the **OpenAI** card.
2. Enter alias (e.g., `openai`), display name (e.g., "OpenAI"), and API key.
3. The API key must include the `Bearer ` prefix (e.g., `Bearer sk-proj-...`). Get one at [platform.openai.com/api-keys](https://platform.openai.com/api-keys).
4. Click **Connect OpenAI**.

What is created: an HTTP proxy to `https://api.openai.com` with auth header `Authorization`.

**Agent access via proxy:**
```bash
curl http://localhost:19817/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer sieve_tok_xxxxx" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}'
```

### Gemini (Google)

1. Under **LLM Providers**, find the **Gemini (Google)** card.
2. Enter alias (e.g., `gemini`), display name (e.g., "Gemini"), and API key (starts with `AIza...`). Get one at [aistudio.google.com/apikey](https://aistudio.google.com/apikey).
3. Click **Connect Gemini**.

What is created: an HTTP proxy to `https://generativelanguage.googleapis.com` with auth header `x-goog-api-key`.

**Agent access via proxy:**
```bash
curl http://localhost:19817/proxy/gemini/v1beta/models/gemini-pro:generateContent \
  -H "Authorization: Bearer sieve_tok_xxxxx" \
  -H "Content-Type: application/json" \
  -d '{"contents":[{"parts":[{"text":"Hello"}]}]}'
```

### AWS Bedrock

1. Under **LLM Providers**, find the **AWS Bedrock** card.
2. Enter a **Connection Alias** (e.g., `bedrock`) and **Display Name** (e.g., "Bedrock").
3. Enter the **Bedrock Endpoint URL** (e.g., `https://bedrock-runtime.us-east-1.amazonaws.com`).
4. Enter your **AWS Access Key ID** (starts with `AKIA...`).
5. Enter your **AWS Secret Access Key**.
6. Enter the **Region** (e.g., `us-east-1`).
7. Click **Connect Bedrock**.

Prerequisites: An IAM user or role with the `bedrock:InvokeModel` permission. See [AWS Bedrock docs](https://docs.aws.amazon.com/bedrock/latest/userguide/getting-started.html).

What is created: an HTTP proxy to your Bedrock endpoint with auth header `Authorization` and extra headers `content-type: application/json`.

### OpenAI-Compatible (Ollama, Together AI, Groq)

For self-hosted models or alternative providers that use the OpenAI-compatible API format.

1. Under **LLM Providers**, find the **OpenAI-Compatible** card.
2. Enter alias (e.g., `ollama`), display name (e.g., "Ollama").
3. Enter the **Base URL** (e.g., `http://localhost:11434/v1` for Ollama, `https://api.together.xyz/v1` for Together AI, `https://api.groq.com/openai/v1` for Groq).
4. Enter an **API Key** if required (include the `Bearer ` prefix). For local Ollama, you can leave this empty.
5. Click **Connect Endpoint**.

What is created: an HTTP proxy to your specified endpoint with auth header `Authorization`.

## Cloud Providers

### AWS Account

For general AWS service access (S3, Lambda, DynamoDB, SES, EC2, and more).

1. Go to `http://localhost:19816/connections`.
2. Under **Cloud**, find the **AWS Account** card.
3. Enter a **Connection Alias** (e.g., `aws-prod`).
4. Enter a **Display Name** (e.g., "AWS Production").
5. Enter the **Default Region** (e.g., `us-east-1`).
6. Enter your **AWS Access Key ID** (starts with `AKIA...`).
7. Enter your **AWS Secret Access Key**.
8. Click **Connect AWS**.

Prerequisites: IAM credentials with permissions for the AWS services you want to use. See [AWS IAM docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html).

What is created: an HTTP proxy connection with the region as the target URL and auth header `X-Sieve-Aws-Auth`. Sieve handles AWS auth signing internally.

**Agent access:** Agents interact with AWS services through MCP tools (e.g., `ec2.run_instances`, `s3.list_objects`, `lambda.invoke`) or via the HTTP proxy. Policies can restrict which AWS services, regions, instance types, and resources the agent can access.

### Hyperstack

For GPU cloud VMs (NVIDIA H100, A100, L40S).

1. Under **Cloud**, find the **Hyperstack** card.
2. Enter alias (e.g., `hyperstack`), display name (e.g., "Hyperstack GPU").
3. Enter your **API Key**. Get one from the [Hyperstack dashboard](https://infrahub.nexgencloud.com/).
4. Click **Connect Hyperstack**.

What is created: an HTTP proxy to `https://infrahub-api.nexgencloud.com` with auth header `api_key`.

**Agent access:** Available operations include hyperstack.list_vms, hyperstack.get_vm, hyperstack.create_vm, hyperstack.delete_vm, hyperstack.start_vm, hyperstack.stop_vm, hyperstack.restart_vm, hyperstack.list_flavors, hyperstack.list_images.

## Generic HTTP Proxy

For any HTTP API not covered by the specific cards above (Stripe, Twilio, GitHub, internal APIs, etc.).

1. Under the **Generic** category, find the **HTTP Proxy** card.
2. Enter a **Connection Alias** (e.g., `stripe`).
3. Enter a **Display Name** (e.g., "Stripe API").
4. Enter the **Target Base URL** (e.g., `https://api.stripe.com`).
5. Enter the **Auth Header Name** (e.g., `Authorization`).
6. Enter the **Auth Value** -- your real API key or token (e.g., `Bearer sk_live_...`).
7. Click **Connect HTTP Proxy**.

### How it works

Sieve acts as a transparent proxy. When the agent sends a request to `http://localhost:19817/proxy/{alias}/any/path`, Sieve:

1. Validates the agent's Sieve token.
2. Evaluates policies (pre-execution).
3. Strips the agent's `Authorization` header.
4. Injects the real auth credential (the auth value you configured) into the configured auth header.
5. Forwards the request to `{target_url}/any/path`.
6. Returns the response (after post-execution policy filtering).

The agent never sees the real API key.

### Agent access

```bash
# Example: Stripe via Sieve
curl http://localhost:19817/proxy/stripe/v1/charges \
  -H "Authorization: Bearer sieve_tok_xxxxx"

# Example: Twilio via Sieve
curl http://localhost:19817/proxy/twilio/2010-04-01/Accounts.json \
  -H "Authorization: Bearer sieve_tok_xxxxx"
```

### Connection table entry

| Alias  | Service    | Display Name | Added    |
|--------|------------|--------------|----------|
| stripe | http_proxy | Stripe API   | just now |

## Generic MCP Proxy

For wrapping an existing MCP server with Sieve's policy pipeline.

1. Under the catalog, find the **MCP Proxy** card.
2. Enter a **Connection Alias** (e.g., `db-tools`).
3. Enter a **Display Name** (e.g., "Database Tools").
4. Enter the **MCP Server URL** -- the upstream MCP server's endpoint (e.g., `http://localhost:3000/mcp`).
5. Optionally enter an **Auth Header** and **Auth Value** if the upstream server requires authentication.
6. Optionally enter a **Server Name** for display purposes.
7. Click **Connect MCP Proxy**.

### How it works

When the connection is created, Sieve connects to the upstream MCP server, sends an `initialize` handshake, and calls `tools/list` to discover all available tools. These tools are then exposed to agents through Sieve's MCP interface, with every tool call passing through the policy pipeline.

For example, if the upstream server exposes tools `query_database` and `create_table`, agents will see those tools in their `tools/list` response (subject to policies). When the agent calls `query_database`, Sieve evaluates policies first, then forwards the call to the upstream server via JSON-RPC.

### Agent access

Tools from the upstream server appear alongside other tools in the agent's MCP `tools/list` response. The agent calls them like any other MCP tool -- it does not need to know that Sieve is proxying to an upstream server.

With multiple MCP proxy connections, tool names are prefixed with the connection alias to avoid collisions: `db-tools_query_database`, `fs-tools_read_file`.

### Connection table entry

| Alias    | Service   | Display Name   | Added    |
|----------|-----------|----------------|----------|
| db-tools | mcp_proxy | Database Tools | just now |

## After creating a connection

Creating a connection makes it available in Sieve, but agents cannot use it until you:

1. **Create a policy** (or use a built-in preset) that defines what operations are allowed.
2. **Create a role** that pairs the connection with one or more policies.
3. **Create a token** that references the role.

The token string is what you give to the agent. See [Understanding Sieve's Data Model](concepts.md) for how these pieces fit together.
