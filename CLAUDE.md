# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Sieve is

A credential gateway between AI agents and real services (Gmail, AWS, LLM APIs, arbitrary HTTP). Sieve holds the real credentials, issues scoped sub-tokens to agents, and runs every request through a two-stage policy pipeline (pre-execution decision + post-execution response filters). See `README.md` and `SPEC.md` for the full product rationale.

## Build, run, test

```bash
# Build (NOTE: README/Dockerfile reference ./cmd/sieve, but no cmd/sieve/main.go
# currently exists in the repo — the only main package is e2e/testserver/.
# If `go build ./cmd/sieve` fails, that's expected, not a regression you need to fix.)

# Run all Go tests
go test ./...

# Run a single Go package's tests
go test ./internal/policy

# Run a single test
go test ./internal/policy -run TestRulesEvaluator

# Playwright e2e tests (spawns a Go test server with mock connectors)
npx playwright test
npx playwright test e2e/web-ui.spec.ts -g "Policy lifecycle"

# Docker
docker compose up -d
```

The Playwright suite (`e2e/web-ui.spec.ts`) launches `e2e/testserver/main.go`, which wires the real `internal/*` services against an in-memory SQLite DB and the mock connector in `internal/testing/mockconnector`. When debugging a failing e2e test, reproduce by running `go run ./e2e/testserver/` directly and hitting the URLs it prints.

## Architecture: the load-bearing concepts

The codebase is small but the layering matters. Reading these in order will make everything else fall into place:

1. **`internal/connector`** — the `Connector` interface (`Type`, `Operations`, `Execute`, `Validate`) and `OperationDef`. Every service integration (Gmail, HTTP proxy, MCP proxy, mock) implements this. `internal/connectors/*` are the concrete implementations.

2. **`internal/policy`** — the `Evaluator` interface and `PolicyDecision`. Policy types: `rules`, `script`, `llm`, `chain`, `composite`, `builtin`. `CreateEvaluator` is the factory dispatched by type string. **Important:** the rules evaluator runs in a single pre-execution pass; post-execution content filtering is expressed as `ResponseFilter` objects attached to the decision, NOT as a second evaluator call. The `Phase` field on `PolicyRequest` is kept only for backward compatibility with Python scripts that branch on `metadata.phase`.

3. **`internal/policies`, `internal/roles`, `internal/tokens`** — the storage layer.
   - A **policy** is a stored, named evaluator config.
   - A **role** is a list of *bindings*: `{connection_id, policy_ids[]}`. A binding with empty `policy_ids` means DENY ALL for that connection.
   - A **token** references a role. Agents authenticate with `sieve_tok_xxx` bearer tokens; the role determines which connections + policies apply.

4. **`internal/api/router.go`** — serves two surfaces on port 19817:
   - `/api/v1/...` — Sieve-native generic connector API + approval polling.
   - `/gmail/v1/...` — Gmail-compatible REST API; existing Gmail clients work by changing base URL. Multi-account uses connection alias as `userId` (e.g., `/gmail/v1/users/work/messages`); `me` resolves to the first connection.
   - `authMiddleware` validates the bearer token and injects it into context via the unexported `tokenContextKey`.

5. **`internal/mcp/server.go`** — the MCP server (also on 19817 at `/mcp`). Tool naming is connector-prefixed (`google_list_emails`) when the token has multiple connections, unprefixed when it has one. The MCP approval flow is **non-blocking** — when a policy returns `approval_required`, the server returns immediately with an approval ID/URL. Contrast with the REST API, which blocks via `approval.WaitForResolution` because synchronous HTTP clients expect that.

6. **`internal/web/server.go`** — the admin UI on port **19816** (separate port = defense in depth). Two security patterns to preserve:
   - `rejectIfAgentToken` blocks any request that carries a Sieve bearer token, so a compromised agent can't self-approve via UI endpoints even if it discovers the URL.
   - OAuth uses a `pendingOAuth` map keyed by random state. The connection is **not** persisted until OAuth completes successfully — prevents orphaned connections with no credentials. State has a 10-minute TTL.

7. **`internal/database`** — single SQLite file at `./data/sieve.db` (WAL mode, foreign keys ON, `chmod 0600`). The `connections` table stores encrypted config blobs (`config_ciphertext`, `config_nonce`, `dek_wrapped`, `dek_nonce`, `enc_version`); plaintext is never persisted. A singleton `crypto_meta` row holds the argon2id salt, params, and KEK verifier. **Pre-alpha: there is no incremental migration path.** `migrate()` is a single canonical `CREATE TABLE IF NOT EXISTS` schema (the source of truth); there are no `ALTER`/rebuild steps. A DB created by an older build has an incompatible shape, so `rejectLegacySchema()` refuses to start (markers: a legacy `policies` table, a plaintext `connections.config` column, or a `tokens` table that still carries the legacy `role_id` column or lacks `role_ids`) with a clear message — the remedy is to delete `./data/sieve.db` and re-add connections. Authorization lives entirely in the `iam_*` tables + `roles`/`tokens` (tokens carry a `role_ids` JSON set; there is no legacy single-role `role_id` column). The legacy `policies` policy-store table and `internal/policies` package are gone.

8. **`internal/secrets`** — envelope encryption + keyring lifecycle. `Keyring.Setup` (first run) / `Keyring.Load` (subsequent starts) derive a 32-byte KEK via argon2id. `Encrypt`/`Decrypt` generate a fresh per-record DEK, AES-256-GCM the payload, and wrap the DEK under the KEK. `Rotate` re-wraps every DEK on passphrase change without touching ciphertext blobs. **The keyring is a required dependency of `connections.NewService`** — every code path that reads or writes a connection config returns `secrets.ErrKeyringNotLoaded` when the keyring is unloaded; API/web handlers map that sentinel to HTTP 503 "service locked". Passphrase intake priority: TTY prompt → `SIEVE_PASSPHRASE_FILE` → FD 3 (systemd `LoadCredential=`). Never an env var. See `docs/credential-encryption.md`.

9. **`internal/approval`, `internal/audit`, `internal/scriptgen`, `internal/settings`** — supporting services. `scriptgen` is the "AI button" that asks a configured LLM to generate a Python policy script from an English description.

### Port topology

- **19817** (API + MCP) — agent-facing, every request authenticated + policy-checked.
- **19816** (Web UI) — human-facing, never expose to agents.

The two-port split is structural, not cosmetic. Don't add agent-callable endpoints to the web server, and don't add admin endpoints to the API router.

### Policy script convention

Scripts (Python by default, any language works) read JSON from stdin, write a JSON `PolicyDecision` to stdout. They get called once with `metadata.phase == "pre"` and once with `metadata.phase == "post"` (the post call also has `metadata.response`). Built-in policy scripts live in `policies/`. Format details: `docs/policy-scripts.md`.

## Conventions worth knowing

- Policy edit/save action names map between UI and storage: `require_approval` ↔ `approval_required` (see commit `22c292e`). When touching policy-related serialization, preserve this mapping in both directions.
- Gmail connector defaults `maxResults` to 100 (commit `862b291`). Don't silently drop the param.
- The Docker runtime ships a Python venv at `/opt/sieve-py` with `requests httpx pandas numpy openai anthropic google-generativeai beautifulsoup4 lxml pyyaml pyjwt cryptography regex pydantic jinja2 tiktoken` available to policy scripts. If you add a new dependency to a default policy script, update the Dockerfile.
- `internal/testing/mockconnector` is the connector you wire up in tests when you need deterministic responses without hitting Google/AWS/etc. `internal/testing/testenv.New` automatically sets up a loaded keyring with a fixed test passphrase (`test-passphrase`) using cheap argon2 params; tests using `testenv.Env.Connections` get encrypted read/write "for free". The e2e testserver (`e2e/testserver/main.go`) takes `--test-passphrase` (default `e2e-test-passphrase`) for the same reason.
- Don't add plaintext credential fields to the `connections` schema. If a new credential type needs storing, route it through `connections.Config` so it flows through the existing envelope-encryption path.
- Don't add env-var-based passphrase intake. Env leaks through `/proc/<pid>/environ`, `ps`, and crash dumps. `SIEVE_PASSPHRASE_FILE` is fine (points at a file); `SIEVE_PASSPHRASE` is not.
- Slack connector specifics: classic non-rotating tokens — there's no `_on_token_refresh` wiring on the Slack `Connector` (neither bot nor user tokens rotate), only on Gmail/Linear/Jira/Asana. A connection has one of two identities via `auth_kind`: **bot** (`oauth`/`token`, `xoxb-` token, stored in `oauth_token`/`bot_token`) or **user** (`user_token`, `xoxp-`/`xoxe.` token, stored in `user_token`). `accessToken()` and `validate()` in `config.go` branch on the kind; the user kind requires an `xoxp-`/`xoxe.` prefix and rejects `xoxb-` (no silent downgrade to bot). `search_messages` is a normal IAM-grantable operation (bindable to any Slack connection in the rule builder) — it runs for real on user-token connections (Slack's `search.messages` only accepts user tokens) and returns the typed `connector.ErrOperationNotEnabled` sentinel on bot connections; the gate is in `opSearchMessages` (`c.cfg.AuthKind != KindUserToken`). Keeping the op grantable to either kind means a role's grant stays stable across re-auth/identity change — the identity gate lives at execution, not grant time. The API layer maps the sentinel to HTTP 501 with `{"error":"operation_not_enabled", ...}`; the MCP layer surfaces it as a tool error with the `operation_not_enabled:` text prefix. Web install paths (all in `internal/web/slack.go`, routes in `server.go`): bot OAuth (`/connections/slack/oauth/start`, requests `scope`), user OAuth (`/connections/slack/oauth/user/start`, requests `user_scope` incl. `search:read`), bot paste (`/connections/slack/token`), user paste (`/connections/slack/user-token`). The shared OAuth callback (`slackOAuthExchange`) decides bot-vs-user by presence of `authed_user.access_token` in the `oauth.v2.access` response — no side-channel flag; reauth preserves the stored identity (`slackConnIsUserIdentity`). Slack OAuth client credentials (`client_id` + `client_secret`) are stored in the `connections` table as an envelope-encrypted reserved row (`connector_type='_oauth_app:slack'`, id `oauth_app__slack`) — same DEK/KEK path as connection configs; rotation re-wraps automatically; reads require the keyring (locked → HTTP 503). Operators paste creds in the admin UI; the env-var fallback `SLACK_CLIENT_ID`/`SLACK_CLIENT_SECRET` is retained only as a 12-factor escape hatch for automated deployments. The `connections.status` field is non-secret and is returned without keyring decryption — `Service.Get`/`List`/`SetStatus` all work with the keyring unloaded; only `GetWithConfig`/`Add`/`UpdateConfig`/`Get/Put/ListOAuthApps` require it. Operator setup walkthrough: `docs/connectors-slack.md`. Quick reference: `docs/connections-guide.md` § Slack Workspace. Agent re-auth contract: HTTP 403 with `{"error":"reauth_required","reauth_url":...}` envelope on both pre-flight (`connections.ErrReauthRequired`) and post-flight (`connector.ErrNeedsReauth`) paths — see `docs/agent-error-contract.md`.

