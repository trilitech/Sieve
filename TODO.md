# Sieve Roadmap

Planned native connectors. All of these can be used today via the generic HTTP Proxy or MCP Proxy connectors — native support adds first-class policy rules, operation-level controls, and a better setup UX.

## Development & Project Management

- [ ] **GitHub** — Repos, PRs, issues, code search, actions. OAuth App or GitHub App auth. Policy rules: repo scope, read-only vs write, branch restrictions, org limits.
- [ ] **GitLab** — Projects, merge requests, issues, pipelines. OAuth or personal access token. Similar policy model to GitHub.
- [ ] **Linear** — Issues, projects, cycles, teams. OAuth or API key. Policy rules: team scope, read-only, label filters.
- [ ] **Jira** — Issues, sprints, boards, JQL search. OAuth or API token. Policy rules: project scope, issue type filters, transition restrictions.
- [ ] **Notion** — Pages, databases, blocks, search. OAuth. Policy rules: workspace scope, page-level access, read-only databases.

## Communication

- [ ] **Slack** — Messages, channels, reactions, files, users. OAuth with bot/user tokens. Policy rules: channel scope, read-only, no DMs, message content filters.
- [ ] **Discord** — Messages, channels, guilds, reactions. Bot token. Policy rules: guild scope, channel restrictions, no DMs.
- [ ] **Microsoft Teams** — Messages, channels, chats. Microsoft Graph API. Policy rules: team scope, read-only channels.

## Productivity

- [ ] **Microsoft 365** — Outlook (email), OneDrive (files), SharePoint (docs), Teams. Microsoft Graph API with OAuth. Policy rules mirror Google services: email read-only, file access by folder, calendar restrictions.

## Data & Analytics

- [ ] **PostgreSQL** — Direct SQL queries with policy-enforced row-level security. Connection via connection string. Policy rules: table allowlist, read-only, query complexity limits, result row limits.
- [ ] **MySQL** — Same model as PostgreSQL.
- [ ] **Snowflake** — Warehouse queries. Policy rules: schema/table scope, query cost limits.
- [ ] **BigQuery** — Google Cloud analytics. Policy rules: dataset scope, query byte limits.

## Payments & Business

- [ ] **Stripe** — Customers, payments, subscriptions, invoices. API key auth. Policy rules: read-only, no refunds, amount limits, customer scope.
- [ ] **Twilio** — SMS, voice calls, WhatsApp. API key auth. Policy rules: recipient allowlist, message content filters, no voice calls.

## Cloud Infrastructure

- [ ] **GCP** — Compute Engine, Cloud Storage, BigQuery, Cloud Run. Service account auth. Policy rules: project scope, resource type restrictions, region limits.
- [ ] **Azure** — VMs, Blob Storage, Cosmos DB. Service principal auth. Policy rules: resource group scope, read-only, region limits.
- [ ] **Vercel** — Deployments, domains, environment variables. API token auth. Policy rules: project scope, no production deploys, read-only env vars.
- [ ] **Cloudflare** — DNS, Workers, Pages, WAF. API token auth. Policy rules: zone scope, read-only DNS, no WAF changes.

## Security Priority

Native connectors are prioritized by:
1. How commonly AI agents need the service
2. How dangerous unrestricted access is (email > file storage > read-only APIs)
3. How much policy granularity improves over the generic proxy

The generic HTTP Proxy and MCP Proxy connectors are always available as a fallback for any service with an HTTP API or MCP server.
