# Setting up Google OAuth credentials for Sieve

Sieve needs a Google OAuth "client ID" to connect to your Google account.

## Two ways to connect

**1. Zero setup (default).** If Sieve is launched with a Google client ID —
via the `--google-oauth-client-id` / `--google-oauth-client-secret` flags, the
`GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` env vars, or a build-time
default — you don't register anything; just click **Connect Google Account**.
The flow uses [PKCE](oauth-pkce.md) and a loopback redirect, so no confidential
secret ever lives on your machine. The rest of this page is unnecessary in that
case. (See [CLI reference → OAuth app client flags](cli-reference.md#oauth-app-client-flags).)

**2. Bring your own client (BYO).** For self-hosters, air-gapped deployments, or
anyone who prefers to own the Google Cloud project, register your own OAuth
client and point Sieve at the downloaded `credentials.json` — the one-time
(~5 min) setup below. A BYO client is used only when no shipped/env client ID is
present.

> Which am I on? Open the Google connection card — if it offers **Connect Google
> Account** directly, you're on the zero-setup path. If it reports that Google
> OAuth isn't configured, follow the BYO steps below.

## Is this sensitive?

**Not really.** Google explicitly documents that OAuth client credentials for
desktop/installed applications are [not treated as secrets](https://developers.google.com/identity/protocols/oauth2):

> "The process results in a client ID and, in some cases, a client secret,
> which you embed in the source code of your application. In this context,
> the client secret is obviously not treated as a secret."

The client ID identifies the *app*, not your *account*. Your actual account access is protected by the OAuth consent flow — you explicitly approve what the app can do each time you connect. The credentials file can safely be committed to a private repo or shared with collaborators.

That said, Sieve's `.gitignore` excludes it by default to keep things clean.

## Google Cloud API Quick setup (gcloud CLI)

If you have the [`gcloud` CLI](https://cloud.google.com/sdk/docs/install) installed, the first half of the setup (project + API enablement) is one CLI command. The second half (OAuth consent screen + Desktop OAuth client) needs to be done in the browser — the stable `gcloud` commands don't yet support creating those for external/desktop apps.

```bash
# 1. One-time auth
gcloud auth login

# 2. Create a project (or reuse one) and select it
gcloud projects create sieve-oauth --name="Sieve"
gcloud config set project sieve-oauth

# 3. Enable every API Sieve supports (drop any you don't need)
gcloud services enable \
  gmail.googleapis.com \
  drive.googleapis.com \
  calendar-json.googleapis.com \
  people.googleapis.com \
  sheets.googleapis.com \
  docs.googleapis.com
```

Notes:

- Calendar's service name is `calendar-json.googleapis.com`, not
  `calendar.googleapis.com` — easy to get wrong.
- Project IDs must be globally unique; pick your own if `sieve-oauth` is
  taken.
- Verify with `gcloud services list --enabled`.

Then jump to **[Step 4](#4-configure-the-oauth-consent-screen)** below to
finish the browser-only parts (consent screen, OAuth client, download JSON,
wire it into `sieve.yaml`).

## Step by step (browser)

### 1. Go to Google Cloud Console

Open https://console.cloud.google.com/

Sign in with any Google account (personal is fine — this doesn't affect which
accounts you can connect later).

### 2. Create a project (or select an existing one)

- Click the project dropdown at the top of the page
- Click **New Project**
- Name it something like "Sieve"
- Click **Create**
- Note the Project ID on the Welcome Page of the project. 

### 3. Enable the APIs

Go to **APIs & Services → Library** (or https://console.cloud.google.com/apis/library).

Search for and enable each of these:

- **Gmail API**
- **Google Drive API**
- **Google Calendar API**
- **Google People API** (Contacts)
- **Google Sheets API**
- **Google Docs API**

Click each one, then click **Enable**.

You can skip any you don't plan to use — Sieve will only access services
you've enabled here.

> Tip: prefer one command over six clicks? See
> [Quick setup (gcloud CLI)](#quick-setup-gcloud-cli) above.

### 4. Configure the OAuth consent screen

Go to **APIs & Services → OAuth consent screen** (or https://console.cloud.google.com/apis/credentials/consent).

- **User Type — pick by audience:**
  - **Internal** — *strongly preferred if this is for your own organization.*
    Available only when the project is owned by your Google Workspace org. An
    Internal app needs **no verification and no CASA** (even with restricted
    Gmail/Drive scopes), shows employees no "unverified app" warning, and has no
    100-user cap — but only `@your-domain` accounts can use it. This is the
    lowest-friction, lowest-liability path for an org rollout.
  - **External** — required if anyone outside your org (personal accounts,
    contractors, the public) must connect. Restricted scopes then trigger
    verification + an annual CASA assessment; see
    [Distribution: internal vs external](oauth-pkce.md#distribution-internal-org-only-vs-external-public).
- Click **Create**
- Fill in:
  - **App name**: Sieve
  - **User support email**: your email
  - **Developer contact email**: your email
- Click **Save and Continue** through the remaining steps (Scopes, Test Users, Summary)
- Click **Back to Dashboard**

**Note (External apps only):** the app starts in "Testing" mode — only test users
you add under **Test users** can use it, or you click "Advanced → Go to Sieve
(unsafe)" to bypass the unverified-app warning. **Internal apps skip this
entirely** — every member of your org can connect immediately, no warning.

### 5. Create OAuth credentials

Go to **APIs & Services → Credentials** (or https://console.cloud.google.com/apis/credentials).

- Click **+ Create Credentials → OAuth client ID**
- Application type: **Web application**
- Name: Sieve (or anything)
- Under **Authorized redirect URIs**, add:
  ```
  http://localhost:19816/oauth/callback
  ```
  (If you access Sieve via a different hostname/port, use that instead)
- Click **Create**

### 6. Download the credentials JSON

After creating, you'll see a dialog with your Client ID and Client Secret.

- Click **Download JSON**
- Save the file as `data/gmail_credentials.json` in your Sieve directory

The file looks like this:

```json
{
  "web": {
    "client_id": "123456789-xxxxxxxx.apps.googleusercontent.com",
    "client_secret": "GOCSPX-xxxxxxxx",
    "redirect_uris": ["http://localhost:19816/oauth/callback"],
    ...
  }
}
```

### 7. Configure Sieve

Make sure your `sieve.yaml` points to the file:

```yaml
connectors:
  google:
    client_credentials_file: "./data/gmail_credentials.json"
```

### 8. Connect your account

1. Start Sieve: `./sieve serve`
2. Open http://localhost:19816/connections
3. Click **Connect Google Account**
4. Sign in with the Google account you want to connect
5. Approve the requested permissions
6. Done — your connection appears in the list

You can connect multiple Google accounts. Each gets its own alias
(e.g., "work", "personal") and policies are configured per-connection.

**Multi-account access for agents:** Agents use the connection alias as the
`userId` in Gmail API paths. For example:
- `/gmail/v1/users/work/messages` — accesses the "work" connection
- `/gmail/v1/users/personal/messages` — accesses the "personal" connection
- `/gmail/v1/users/me/messages` — uses the default (first) Google connection

## Troubleshooting

### "redirect_uri_mismatch" error

The redirect URI in Google Cloud Console must **exactly** match what Sieve
sends. Check:

- Port matches (default: 19816)
- Path is `/oauth/callback` (not `/oauth/callback/` with trailing slash)
- Protocol is `http` (not `https`, unless you're behind a reverse proxy)
- If accessing via hostname (not localhost), the hostname must match

### "This app isn't verified" warning

Expected in Testing mode. Either:
- Add your email as a test user in the OAuth consent screen
- Or click **Advanced → Go to Sieve (unsafe)** to proceed

### "Access blocked: This app's request is invalid"

Usually means the redirect URI doesn't match. Click "error details" on the
Google error page — it shows the exact URI mismatch.

## Sharing credentials with collaborators

Since the client ID/secret are not account credentials (they just identify
the app), you can share the JSON file with collaborators. Each person still
needs to go through the OAuth consent flow with their own Google account.

For teams, you can:
- Commit the file to a private repo
- Share it via a secure channel
- Or have each person create their own Google Cloud project
