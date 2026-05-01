# Quickstart: Slack, Linear, Jira, and Asana Connectors

This walks through adding each connector to a local Sieve install and verifying the happy path. Assumes you've cloned the repo and have `go`, `npm`, and Docker available.

## Prereqs

```bash
# From repo root
go build ./...
go test ./internal/connectors/...
npm install
```

The first command is the smoke test that the new connector packages compile. The second runs the per-connector unit tests against the in-package mock servers (no network).

If you want to exercise the admin UI: start Sieve in dev mode (`go run ./e2e/testserver/` then open the printed URL) — the testserver wires the in-memory SQLite, the keyring at the test passphrase, and the mock Slack/Linear/Jira HTTP servers, so OAuth flows complete locally without hitting real services.

## Slack (P1)

### OAuth path (production-like)

1. Create a Slack app at <https://api.slack.com/apps>. Under **OAuth & Permissions**, add the bot scopes:
   `channels:read groups:read users:read users.profile:read channels:history groups:history chat:write`.
   Add the redirect URL `http://<your-sieve-host>:19816/oauth/callback`.
2. Copy the Client ID and Client Secret into your Sieve settings (`SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET`) — `internal/settings` reads these from the operator config file (NOT env vars).
3. In the admin UI, **Add Connection** → **Slack**. Enter an alias (e.g., `acme-workspace`). Click **Install via OAuth**. Approve in Slack.
4. The redirect lands you back on the Sieve admin UI with the connection in `status: active`.

### Direct bot-token path

1. From the same Slack app's **Install App** page, copy the bot token (`xoxb-…`).
2. In the admin UI, **Add Connection** → **Slack** → **Use existing bot token**. Paste the token. Submit.
3. Sieve calls `auth.test`; on success the connection lands with `status: active`.

### Verify

```bash
# Create a token with a role bound to this connection + a "post to #bot-test only" rules policy.
# Then from a separate terminal:
curl -s -X POST http://localhost:19817/api/v1/connections/<conn-id>/operations/slack.post_message \
  -H "Authorization: Bearer sieve_tok_..." \
  -H "Content-Type: application/json" \
  -d '{"channel":"#bot-test","text":"hello from sieve"}'
```

Expected: 200 with the Slack message ack. Audit log entry visible in admin UI within 5s. Posting to `#general` returns `{"error": "policy_denied", ...}`.

## Linear (P2)

### OAuth path

1. Create a Linear OAuth application at <https://linear.app/settings/api/applications>. Scopes: `read,write,issues:create`. Redirect URL: `http://<your-sieve-host>:19816/oauth/callback`.
2. Copy Client ID + Client Secret into `LINEAR_CLIENT_ID` / `LINEAR_CLIENT_SECRET` in your settings.
3. **Add Connection** → **Linear** → **Install via OAuth**. Approve.
4. Connection lands with `status: active`.

### Personal API key path

1. Create a personal API key at <https://linear.app/settings/api> (`lin_api_…`).
2. **Add Connection** → **Linear** → **Use API key**. Paste. Submit.
3. Sieve issues `query { viewer { id email } }`; on `viewer != null` the connection lands `active`.

### Verify

```bash
curl -s -X POST http://localhost:19817/api/v1/connections/<conn-id>/operations/linear.list_issues \
  -H "Authorization: Bearer sieve_tok_..." \
  -H "Content-Type: application/json" \
  -d '{"team_key":"BOT","first":5}'
```

Expected: 200 with up to 5 BOT-team issues.

For the response-filter test (User Story 2 acceptance scenario 2), attach a script policy that redacts `customer:\w+` and call `linear.get_issue` for an issue containing `customer:acme` in the description — verify the agent receives `[REDACTED]`.

## Jira Cloud (P3)

### OAuth (3LO) path

1. Create an Atlassian OAuth 2.0 (3LO) app at <https://developer.atlassian.com/console/myapps/>. Add scopes: `read:jira-user read:jira-work write:jira-work offline_access`. Redirect URL: `http://<your-sieve-host>:19816/oauth/callback`.
2. Copy Client ID + Client Secret into `JIRA_CLIENT_ID` / `JIRA_CLIENT_SECRET`.
3. **Add Connection** → **Jira Cloud** → **Install via OAuth**. Approve and pick a site. The connector resolves `cloudId` via `/oauth/token/accessible-resources` and stores it.
4. Connection lands `active`.

### API token path

1. Generate an Atlassian API token at <https://id.atlassian.com/manage-profile/security/api-tokens>.
2. **Add Connection** → **Jira Cloud** → **Use API token**. Enter site URL (`https://acme.atlassian.net`), email, API token. Submit.
3. Sieve calls `GET /rest/api/3/myself`; on 200 with `accountId` the connection lands `active`.

### Verify

```bash
curl -s -X POST http://localhost:19817/api/v1/connections/<conn-id>/operations/jira.search_issues \
  -H "Authorization: Bearer sieve_tok_..." \
  -H "Content-Type: application/json" \
  -d '{"jql":"project = BOT","max_results":5}'
```

Expected: 200 with up to 5 BOT issues. The result shape is `{ items: [...], next_cursor: "..." }` per FR-014; each issue includes `description` (raw ADF) and `description_text` (plain-text rendering) per FR-015 when `description` is in the requested field set.

## Asana (P4)

### OAuth path

1. Create an Asana OAuth app at <https://app.asana.com/0/my-apps>. Add the redirect URL `http://<your-sieve-host>:19816/oauth/callback`. (Asana grants full access to the authorizing user's data; per-resource access is enforced by the user's existing Asana role/permissions.)
2. Copy Client ID + Client Secret into `ASANA_CLIENT_ID` / `ASANA_CLIENT_SECRET` in your settings file.
3. **Add Connection** → **Asana** → **Install via OAuth**. Approve.
4. The connector resolves your default workspace via `GET /users/me?opt_fields=gid,workspaces.gid,workspaces.name` and stores the first workspace as `default_workspace_gid`.
5. Connection lands `active`.

### Personal Access Token path

1. Create a Personal Access Token at <https://app.asana.com/0/my-apps> → "Create new token". Copy the `1/...` value (shown only once).
2. **Add Connection** → **Asana** → **Use Personal Access Token**. Paste the token. If your account belongs to multiple workspaces, optionally select a default workspace; otherwise the first one is used. Submit.
3. Sieve calls `GET /users/me`; on 200 with `data.gid` the connection lands `active`.

### Verify

```bash
# Replace <project-gid> with a real Asana project GID from your workspace.
curl -s -X POST http://localhost:19817/api/v1/connections/<conn-id>/operations/asana.list_tasks \
  -H "Authorization: Bearer sieve_tok_..." \
  -H "Content-Type: application/json" \
  -d '{"project":"<project-gid>","page_size":5}'
```

Expected: 200 with up to 5 tasks. Result shape is `{ items: [...], next_cursor: "..." }` per FR-014. Each task that has rich text in `html_notes` carries both `notes` (HTML) and `notes_text` (plain text) per FR-015. To create a task:

```bash
curl -s -X POST http://localhost:19817/api/v1/connections/<conn-id>/operations/asana.create_task \
  -H "Authorization: Bearer sieve_tok_..." \
  -H "Content-Type: application/json" \
  -d '{"project":"<project-gid>","name":"Smoke test from Sieve","notes":"hello"}'
```

For the project-scoping policy test (User Story 4 acceptance scenario 3), attach a rules policy that restricts `asana.list_tasks` to a specific project GID and verify cross-project queries are denied.

## Status field migration check

After upgrading to a build that includes this feature, on first start the migration adds the `status` column (default `active`) to the `connections` table. To verify:

```bash
sqlite3 ./data/sieve.db "PRAGMA table_info(connections);" | grep status
sqlite3 ./data/sieve.db "SELECT id, connector_type, status FROM connections;"
```

Expected: every row shows `active`. SC-008 verification: `SELECT COUNT(*) FROM connections;` matches the pre-migration count.

## Reauth flow check (SC-007)

1. With an `active` Slack connection, revoke the bot token from the Slack app's **Install App** page.
2. Issue any Slack operation through Sieve. The first call returns `{"error": "reauth_required", ...}`.
3. Within 60 seconds, the connections list in the admin UI shows the row's `status: reauth_required`.
4. Click **Re-install** (OAuth path) or **Update token** (token path). On success, status returns to `active` and operations resume.

## Disabling a connection

In the admin UI, click **Disable** on a connection row. Status becomes `disabled`. Any agent operation returns `{"error": "disabled", ...}`. Click **Re-enable** to return to `active`.

## Running the full e2e suite

```bash
npx playwright test e2e/web-ui.spec.ts
```

The spec includes new groups for Slack/Linear/Jira covering OAuth + token paths, the `status` lifecycle, and the per-connector smoke ops against the mock servers wired by `e2e/testserver/main.go`.
