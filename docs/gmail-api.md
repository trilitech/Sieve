# Gmail-Compatible REST API

Sieve exposes a Gmail-compatible REST API that mirrors Google's Gmail API.
Any tool, script, or library that speaks the Gmail API can use Sieve
instead — just change the base URL and use a Sieve token.

## Quick start

Replace the Gmail API base URL and use your Sieve token:

```
# Instead of:
GET https://gmail.googleapis.com/gmail/v1/users/me/messages?q=project
Authorization: Bearer ya29.google_oauth_token

# Use:
GET http://localhost:19817/gmail/v1/users/me/messages?q=project
Authorization: Bearer sieve_tok_xxxxx
```

Every request goes through Sieve's policy pipeline. The agent never
touches your real Google credentials.

## Python example

```python
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import google.auth.transport.requests

# Create a minimal credentials object with your Sieve token
class SieveCredentials:
    token = "sieve_tok_xxxxx"
    expired = False
    valid = True
    def refresh(self, request): pass
    def apply(self, headers):
        headers["Authorization"] = f"Bearer {self.token}"

# Build the Gmail service pointing at Sieve
service = build(
    "gmail", "v1",
    credentials=SieveCredentials(),
    cache_discovery=False,
)
# Override the base URL
service._baseUrl = "http://localhost:19817/gmail/v1/"

# Use it exactly like the normal Gmail API
results = service.users().messages().list(userId="me", q="triangular").execute()
for msg in results.get("messages", []):
    print(msg["id"], msg.get("snippet", ""))
```

## curl examples

### List / search emails

```bash
curl "http://localhost:19817/gmail/v1/users/me/messages?q=from:boss@company.com&maxResults=10" \
  -H "Authorization: Bearer sieve_tok_xxxxx"
```

### Read a single email

```bash
curl "http://localhost:19817/gmail/v1/users/me/messages/MESSAGE_ID" \
  -H "Authorization: Bearer sieve_tok_xxxxx"
```

By default, Sieve returns its simplified parsed shape (`id`, `from`, `to`,
`subject`, `body`, attachment metadata) — suitable for interactive agent use.
For byte-faithful archival, request Google's `format=raw`:

```bash
curl "http://localhost:19817/gmail/v1/users/me/messages/MESSAGE_ID?format=raw" \
  -H "Authorization: Bearer sieve_tok_xxxxx"
```

Returns Google's wire shape verbatim: `{id, threadId, labelIds, internalDate,
raw}`, where `raw` is the base64url-encoded RFC822 message (full headers
including `Message-ID`/`References`/`In-Reply-To`, all MIME parts, attachments
inline). This routes to a distinct connector operation (`read_email_raw`) so
archival roles can be granted only this surface, or vice versa.

Decode the raw payload locally:

```bash
RAW=$(curl -sH "Authorization: Bearer sieve_tok_xxxxx" \
  "http://localhost:19817/gmail/v1/users/me/messages/MESSAGE_ID?format=raw" \
  | jq -r .raw)
echo "$RAW" | tr '_-' '/+' | base64 -d > message.eml
```

### Read a thread

```bash
curl "http://localhost:19817/gmail/v1/users/me/threads/THREAD_ID" \
  -H "Authorization: Bearer sieve_tok_xxxxx"
```

### List labels

```bash
curl "http://localhost:19817/gmail/v1/users/me/labels" \
  -H "Authorization: Bearer sieve_tok_xxxxx"
```

### Send an email

```bash
curl -X POST "http://localhost:19817/gmail/v1/users/me/messages/send" \
  -H "Authorization: Bearer sieve_tok_xxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "to": ["recipient@example.com"],
    "subject": "Hello from Sieve",
    "body": "This email was sent through Sieve."
  }'
```

Note: if the token's policy requires approval for sends, this request
will block until approved in the Sieve admin UI.

`messages/send` takes the **same structured body as drafts** — `to`, `cc`,
`bcc`, `subject`, `body`, and the threading fields (`in_reply_to_message_id`,
etc.). To send a reply that threads correctly, set `in_reply_to_message_id` to
the parent message's id. As with drafts, unknown fields are rejected with `400`
(never silently dropped), and an opaque `raw` MIME blob is not accepted — send
structured fields so policies can inspect the message.

### Create a draft

```bash
curl -X POST "http://localhost:19817/gmail/v1/users/me/drafts" \
  -H "Authorization: Bearer sieve_tok_xxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "to": ["recipient@example.com"],
    "cc": ["team@example.com"],
    "bcc": ["archive@example.com"],
    "subject": "Draft via Sieve",
    "body": "This is a draft."
  }'
```

Accepted body fields: `to`, `cc`, `bcc`, `subject`, `body`, `attachments` (see
below), the threading fields below, and `forward_message_id` (see [Forward a
message](#forward-a-message)). **Unknown fields are rejected with `400`** (they
are never silently dropped), so a typo can't leave you thinking a field took
effect when it didn't. An opaque `raw` MIME blob is **not** accepted — the
endpoint takes structured fields so response/pre-execution policies can inspect
the content; attachments below are the structured, inspectable way to send files.

#### Attachments

To attach files, pass an `attachments` array. Each entry is a structured object
— `filename`, `mime_type`, and `content` (the file's bytes, base64-encoded) —
so every attachment stays fully inspectable by policy (filename, type, size,
bytes). This is the structured alternative to an opaque `raw` MIME blob. Sieve
assembles the `multipart/mixed` message server-side; the caller never builds MIME.

```bash
curl -X POST "http://localhost:19817/gmail/v1/users/me/drafts" \
  -H "Authorization: Bearer sieve_tok_xxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "to": ["adviser@example.com"],
    "subject": "Funding schedule",
    "body": "Please review the attached.",
    "attachments": [
      { "filename": "schedule.pdf",
        "mime_type": "application/pdf",
        "content": "<base64 bytes>" }
    ]
  }'
```

`attachments` works the same on `drafts`, `drafts` update, `messages/send`,
`reply`, and the forward endpoints.

#### Draft (or send) a reply into an existing thread

To reply *into* a conversation instead of starting a new thread, set
`in_reply_to_message_id` to the Gmail message id of the parent. Sieve looks up
that message and fills in the `threadId`, the `In-Reply-To`/`References`
headers, and a `Re:` subject (when you don't supply one) so the reply threads
correctly in the recipient's client and in downstream ticketing systems:

```bash
curl -X POST "http://localhost:19817/gmail/v1/users/me/drafts" \
  -H "Authorization: Bearer sieve_tok_xxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "to": ["recipient@example.com"],
    "body": "Thanks — see attached.",
    "in_reply_to_message_id": "18febc0f2a1b2c3d"
  }'
```

The same `in_reply_to_message_id` field works on `messages/send` (send a reply
directly) and `drafts` update. Advanced callers who already have the raw values
may instead pass `thread_id`, `in_reply_to` (parent `Message-ID`), and
`references` explicitly; these override the looked-up values.

### Forward a message

To forward an existing message, set `forward_message_id` to its Gmail message
id. **Do not hand-assemble a forwarded block** — Sieve looks up the source and
assembles a faithful forward server-side: the genuine `From`/`Date`/`Subject`/
`To`, the original body in **both** plain text and HTML (so links and formatting
survive), and the original attachments, all beneath your own note. The subject
defaults to `Fwd: <source subject>` unless you supply one.

```bash
# Draft a forward (human reviews and sends)
curl -X POST "http://localhost:19817/gmail/v1/users/me/drafts" \
  -H "Authorization: Bearer sieve_tok_xxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "to": ["trustee@example.com"],
    "body": "Forwarding the below — please action before Monday.",
    "forward_message_id": "1a04998e3adc301a"
  }'
```

`forward_message_id` also works on `messages/send` (send the forward directly).
There is additionally a path-style route: `POST /messages/{id}/forward`, where
`{id}` is the source message and the body carries the recipients and note.

Forwarding is a **separately-grantable** operation (`forward_draft` /
`forward_email`), distinct from `create_draft`/`send_email` — because forwarding
existing mail to new recipients is an exfiltration primitive, a role can grant
composing and replying without granting forwarding. You may also add extra files
via `attachments`, alongside the source's own attachments.

### List drafts

```bash
curl "http://localhost:19817/gmail/v1/users/me/drafts?maxResults=50" \
  -H "Authorization: Bearer sieve_tok_xxxxx"
```

Returns lightweight stubs (draft id plus the message's id/thread_id/to/subject/
snippet — no body), so you can find and verify drafts you created.

### Delete a draft

```bash
curl -X DELETE "http://localhost:19817/gmail/v1/users/me/drafts/DRAFT_ID" \
  -H "Authorization: Bearer sieve_tok_xxxxx"
```

### Modify labels (add/remove)

```bash
# Add a label
curl -X POST "http://localhost:19817/gmail/v1/users/me/messages/MESSAGE_ID/modify" \
  -H "Authorization: Bearer sieve_tok_xxxxx" \
  -H "Content-Type: application/json" \
  -d '{"addLabelIds": ["Label_123"]}'

# Archive (remove INBOX label)
curl -X POST "http://localhost:19817/gmail/v1/users/me/messages/MESSAGE_ID/modify" \
  -H "Authorization: Bearer sieve_tok_xxxxx" \
  -H "Content-Type: application/json" \
  -d '{"removeLabelIds": ["INBOX"]}'
```

`modify` applies **one label change per call** — each label op (`add_label` /
`remove_label` / `archive`) is separately policy-gated. A request with more than
one label across `addLabelIds`/`removeLabelIds` is rejected with `400` rather
than silently applying only the first; issue a separate `modify` per label.

`GET /messages` additionally accepts repeated `labelIds` (restrict to messages
carrying all listed labels) and `includeSpamTrash=true`, matching the Gmail
`messages.list` API.

## Available endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/gmail/v1/users` | List available Google accounts (Sieve extension) |
| GET | `/gmail/v1/users/{userId}/messages` | list_emails |
| GET | `/gmail/v1/users/{userId}/messages/{id}` | read_email (or read_email_raw when `?format=raw`) |
| GET | `/gmail/v1/users/{userId}/threads/{id}` | read_thread |
| POST | `/gmail/v1/users/{userId}/messages/send` | send_email (or forward_email when `forward_message_id` is set) |
| POST | `/gmail/v1/users/{userId}/messages/{id}/forward` | forward_email |
| POST | `/gmail/v1/users/{userId}/drafts` | create_draft (or forward_draft when `forward_message_id` is set) |
| GET | `/gmail/v1/users/{userId}/drafts` | list_drafts |
| DELETE | `/gmail/v1/users/{userId}/drafts/{id}` | delete_draft |
| GET | `/gmail/v1/users/{userId}/labels` | list_labels |
| GET | `/gmail/v1/users/{userId}/messages/{messageId}/attachments/{attachmentId}` | get_attachment |
| POST | `/gmail/v1/users/{userId}/messages/{id}/modify` | add_label / remove_label / archive |

### Get an attachment

```bash
curl "http://localhost:19817/gmail/v1/users/me/messages/MESSAGE_ID/attachments/ATTACHMENT_ID" \
  -H "Authorization: Bearer sieve_tok_xxxxx"
```

The response includes the attachment metadata (filename, MIME type, size) and the decoded data.

`{userId}` is `me` (default Gmail connection) or a connection alias (e.g., `work`, `personal`).

### Discovering accounts

Call `GET /gmail/v1/users` to list the Google accounts your token can access:

```bash
curl http://localhost:19817/gmail/v1/users \
  -H "Authorization: Bearer sieve_tok_xxxxx"
```

Response:
```json
{
  "users": [
    {"id": "work", "displayName": "Work Gmail", "emailAddress": "you@work.com"},
    {"id": "personal", "displayName": "Personal", "emailAddress": "you@gmail.com"}
  ]
}
```

Use the `id` as the `{userId}` in subsequent requests.

## Query parameters

For `GET /gmail/v1/users/me/messages`:

| Parameter | Description |
|-----------|-------------|
| `q` | Gmail search query (same syntax as Gmail search box) |
| `maxResults` | Maximum number of results (default 100, max 500) |
| `pageToken` | Token for paginating through results |

## How it works

```
Your script/agent          Sieve                         Gmail API
       │                     │                              │
       │  GET /gmail/v1/...  │                              │
       │  Bearer sieve_tok   │                              │
       │────────────────────>│                              │
       │                     │  1. Validate Sieve token     │
       │                     │  2. Evaluate policy rules    │
       │                     │  3. If allowed:              │
       │                     │     GET gmail.googleapis.com │
       │                     │────────────────────────────>│
       │                     │     (using real OAuth token) │
       │                     │<────────────────────────────│
       │                     │  4. Post-phase policy check  │
       │                     │  5. Filter/redact if needed  │
       │  JSON response      │                              │
       │<────────────────────│                              │
       │                     │  6. Log to audit trail       │
```

## Differences from the real Gmail API

- **Authentication**: Sieve tokens instead of Google OAuth tokens
- **Base URL**: `http://localhost:19817` instead of `https://gmail.googleapis.com`
- **Policy enforcement**: Requests can be denied, require approval, or have content filtered
- **Response format**: Sieve returns its own email object format (slightly simplified from Gmail's raw format). Fields: `id`, `thread_id`, `from`, `to`, `cc`, `subject`, `body`, `body_html`, `date`, `labels`, `snippet`, `has_attachment`
- **Send format**: The send endpoint accepts a simple JSON object with `to`, `subject`, `body` fields instead of Gmail's base64-encoded MIME message

## Multiple Gmail accounts

A single Sieve token can access multiple Gmail accounts. Call
`GET /gmail/v1/users` first to discover which accounts are available,
then use the `userId` path parameter to address a specific inbox:

### Single-account tokens

Use `me` (just like the real Gmail API):

```bash
GET /gmail/v1/users/me/messages
```

### Multi-account tokens

Use the connection alias as the `userId`:

```bash
# Read from work inbox
GET /gmail/v1/users/work/messages?q=project

# Read from personal inbox
GET /gmail/v1/users/personal/messages?q=vacation

# Send from work
POST /gmail/v1/users/work/messages/send
```

`me` still works and defaults to the first Gmail connection on the token.

### Python example (multi-account)

```python
# Read from work account
work_results = service.users().messages().list(
    userId="work", q="project deadline"
).execute()

# Read from personal account
personal_results = service.users().messages().list(
    userId="personal", q="flight confirmation"
).execute()

# "me" uses the default (first) Gmail connection
default_results = service.users().messages().list(
    userId="me", q="hello"
).execute()
```

Each connection has its own policy rules. A token might allow full
read/write on `work` but read-only on `personal`.
