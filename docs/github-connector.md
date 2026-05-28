# GitHub Connector

Sieve's `github` connector sits between an agent and the GitHub REST API.
The agent never sees your real PAT or App private key; every request
passes through Sieve's policy pipeline.

## Two auth modes

Sieve supports two ways to authenticate with GitHub. A single connection
can hold multiple credentials of either kind and route requests to the
right one automatically.

### Fine-grained personal access token (PAT)

Paste a token Sieve stores (encrypted) and uses as-is. One PAT covers
one user account **or** one org — it's a GitHub constraint, not ours.
To access both a personal account and an org, add two credentials to
one Sieve connection.

### GitHub App (recommended for orgs)

Sieve walks you through creating a GitHub App in your account using
GitHub's **manifest flow**: one click to create the App, one click to
install it on an org. Sieve holds the App's private key; installation
tokens are auto-refreshed every hour.

Advantages over PATs:

- No long-lived secret to rotate.
- Per-installation permissions are granular and GitHub-visible.
- Works for all repos in an org (or a selected subset) via one install.

**Note**: Your Sieve host must be reachable from GitHub's servers during setup,
because GitHub calls back to `/connections/github/app/created` and
`/connections/github/app/installed` during the flow.

- On a remote VM, assign a public IP or DNS name, open port 19816, and (for production) use HTTPS via a reverse proxy (e.g., Nginx or Caddy).
- Register your public URL as the callback and webhook in the GitHub App manifest.
- For local/dev, use a tunneling service like ngrok to expose Sieve to the internet.

## Setting up a PAT connection

1. On GitHub, go to **Settings → Developer settings → Personal access
   tokens → Fine-grained tokens**. Click **Generate new token**. Pick the
   resource owner (your user or an org), select repo access, and grant
   the repository permissions your agent will need (typically
   `Contents: R/W`, `Issues: R/W`, `Pull requests: R/W`, `Metadata: R`).
2. In Sieve, go to the **Connections** page and find the GitHub card.
3. Fill in:
   - **Connection Alias** — short ID for the connection (e.g. `my-github`)
   - **Display Name** — human label
   - **Scope** — `User` or `Org`
   - **Owner login** — GitHub login of the user or org the PAT covers
   - **Fine-grained PAT** — the `github_pat_...` you just created
4. Click **Add via PAT**. Sieve validates the token by hitting
   `/user` or `/orgs/{name}` before saving. If the login doesn't match
   the declared scope, the token is rejected.

## Setting up a GitHub App connection

1. In Sieve, go to the GitHub card's **Or install as GitHub App**
   section.
2. Fill in connection alias, display name, and optionally an org slug
   (leave blank to create the App under your personal account).
3. Click **Install as GitHub App**. Sieve generates a manifest and
   auto-submits it to GitHub. You confirm the App creation on
   GitHub's page.
4. GitHub redirects to Sieve, which exchanges a one-time code for the
   App's private key and ID, then redirects you back to GitHub's
   install page.
5. Pick which account or org to install into (and optionally which
   repos). Click **Install**.
6. GitHub redirects back to Sieve, which fetches the installation's
   account info and persists the connection.

The whole flow is ~30 seconds of clicks. No copy-paste of secrets.

## Auth routing

Each request is routed to the credential whose scope covers the owner
referenced in the request:

- Path `/repos/{owner}/...` → scope name = owner
- Path `/orgs/{org}/...` → scope name = org
- Path `/users/{user}/...` → scope name = user
- `/user`, `/search/*`, `/graphql`, `/notifications` → ownerless,
  falls back to `default_credential_index`

If an owner is specified but no credential in the connection covers it,
Sieve returns an error rather than sending the request with the wrong
token (which would burn rate limit for no reason).

## Operations

Curated operations (typed params, policy-friendly):

| Operation | Read-only | Description |
|---|---|---|
| `github_list_repos` | yes | List repos for an org or the authenticated user |
| `github_get_file` | yes | Read a file from a repo |
| `github_put_file` | no | Create or update a file |
| `github_list_issues` | yes | List issues in a repo |
| `github_create_issue` | no | Open a new issue |
| `github_comment_issue` | no | Comment on an issue or PR |
| `github_list_prs` | yes | List pull requests |
| `github_get_pr` | yes | Get a PR with merge state |
| `github_create_pr` | no | Open a new PR |
| `github_search_code` | yes | Search code using GitHub's query syntax |

Plus `github_request` — a raw-request escape hatch that takes
`{method, path, query?, body?}` and runs it through the same auth
router. Use it to reach anything the curated set doesn't cover.

> **`github_request` bypasses connector-layer guardrails.** The
> cross-fork PR allow-list (`cross_fork_pr_allowlist`) is enforced
> inside the curated `github_create_pr` op only. An agent permitted to
> call `github_request` can `POST /repos/{owner}/{repo}/pulls` with any
> cross-fork head and reach upstream without the allow-list firing.
> For the allow-list to be a real control, deny `github_request` in
> the role's policies — `github-read-only` already does this.

## Cross-fork PR allow-list

Connections expose an optional `cross_fork_pr_allowlist` field — a list
of GitHub user logins (case-insensitive, no wildcards) whose forks the
connector accepts as cross-fork PR heads when an agent calls
`github_create_pr`. Default is empty, which means "deny all cross-fork
PRs". Same-repo heads (no `user:` prefix) are unaffected.

Blocked attempts are logged as `policy_result:
github.cross_fork_head_denied`. **The allow-list is only consulted by
`github_create_pr`; see the warning under "Operations" above about
`github_request`.**

## Policy presets

Two presets ship with Sieve, both with `scope: "github"`:

- **github-read-only** — allows the 6 read ops. Denies everything else
  including `github_request`.
- **github-with-approval** — reads pass through, writes require
  human approval via the approval queue.

For repo-level allowlisting, start from `github-read-only` and add an
`owner: "<org>/*"` matcher to each rule. The rules engine already
supports glob matching against `params["owner"]`.

## Security notes

- Connection configs are stored envelope-encrypted (same pipeline as
  Gmail OAuth tokens); plaintext never persists.
- App installation tokens live in memory only and are refreshed five
  minutes before expiry.
- Response bodies are capped at 5 MiB per request.
- Redirects are disabled; file paths are validated against `..`,
  backslashes, and percent-encoded traversal sequences before being
  sent upstream.
- The agent-facing MCP/API port (19817) and the web admin port (19816)
  are separate; App setup endpoints live on the admin port and reject
  requests that carry a Sieve bearer token (`rejectIfAgentToken`).
