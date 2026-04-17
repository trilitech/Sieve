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

### Create a draft

```bash
curl -X POST "http://localhost:19817/gmail/v1/users/me/drafts" \
  -H "Authorization: Bearer sieve_tok_xxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "to": ["recipient@example.com"],
    "subject": "Draft via Sieve",
    "body": "This is a draft."
  }'
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

## Available endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/gmail/v1/users` | List available Google accounts (Sieve extension) |
| GET | `/gmail/v1/users/{userId}/messages` | list_emails |
| GET | `/gmail/v1/users/{userId}/messages/{id}` | read_email |
| GET | `/gmail/v1/users/{userId}/threads/{id}` | read_thread |
| POST | `/gmail/v1/users/{userId}/messages/send` | send_email |
| POST | `/gmail/v1/users/{userId}/drafts` | create_draft |
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
