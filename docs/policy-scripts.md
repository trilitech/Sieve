# Writing Policy Scripts for Sieve

Policy scripts are programs that Sieve calls to make access control decisions.
They receive a JSON request on **stdin** and write a JSON decision to **stdout**.

Scripts can be written in any language. Python is the default.

> **IAM filter/guard scripts.** When used as IAM filter-library guards or response
> filters (see `docs/architecture/iam/01-spec.md` §7.1), a script is referenced by
> **path** and run under an allowlisted interpreter — **`python3` or `node`** by
> default (Python or JavaScript; the stdin-JSON→stdout-JSON contract below is
> identical for both). The path must sit under an allowlisted scripts directory
> (default `/opt/sieve-py`).

## How scripts are called

Sieve calls your script **twice** per operation:

1. **Pre-phase** (before execution): Should this operation be allowed?
2. **Post-phase** (after execution): Should this response be returned to the agent?

Your script receives different context in each phase and can make different
decisions.

## Input format

Your script receives a JSON object on stdin:

```json
{
  "operation": "list_emails",
  "connection": "work",
  "connector": "google",
  "params": { ... },
  "metadata": { ... }
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `operation` | string | The operation being performed (see Operations below) |
| `connection` | string | The connection alias (e.g., "work", "personal") |
| `connector` | string | The connector type (e.g., "google") |
| `params` | object | The parameters the agent passed to the operation |
| `metadata` | object | Additional context (differs by phase) |

### Pre-phase metadata

In the pre-phase, `metadata` contains the same data as `params` — the
operation arguments the agent provided.

```json
{
  "operation": "list_emails",
  "params": { "query": "from:boss@company.com", "max_results": 10 },
  "metadata": { "query": "from:boss@company.com", "max_results": 10 }
}
```

### Post-phase metadata

In the post-phase, `metadata` contains:

| Key | Type | Description |
|-----|------|-------------|
| `phase` | string | Always `"post"` |
| `response` | string | The full JSON response from the connector |

```json
{
  "operation": "list_emails",
  "params": { "query": "triangular", "max_results": 5 },
  "metadata": {
    "phase": "post",
    "response": "{\"emails\":[{\"id\":\"abc\",\"subject\":\"Hello\",...}],\"total\":5}"
  }
}
```

The `response` is a JSON string (you'll need to parse it). Its structure
depends on the operation — see Response Formats below.

## Output format

Write a JSON object to stdout:

```json
{
  "action": "allow",
  "reason": "optional explanation",
  "rewrite": "optional edited response JSON"
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | **yes** | `"allow"`, `"deny"`, or `"approval_required"` |
| `reason` | string | no | Human-readable explanation (shown to agent on deny, logged on allow) |
| `rewrite` | string | no | Edited response. If set with `action: "allow"`, the agent receives this instead of the original. Only meaningful in post-phase. Use this to remove emails from lists, strip sensitive content, redact patterns — any modification. |

The `rewrite` field is the edited version of the entire response. Parse
the response JSON, modify it however you need, and return the modified
version as a JSON string. This is the single mechanism for all content
editing — filtering, redacting, rewriting.

## Deciding by phase

Your script is called in both phases. Check `metadata.phase` to distinguish:

```python
#!/usr/bin/env python3
import json, sys

req = json.load(sys.stdin)
phase = req.get("metadata", {}).get("phase", "pre")

if phase == "post":
    # Post-phase: inspect and optionally filter the response
    response = req["metadata"]["response"]
    # ... decide based on response content
else:
    # Pre-phase: inspect the operation and params
    op = req["operation"]
    # ... decide based on what the agent is trying to do
```

If your script only cares about one phase, return `{"action": "allow"}` for
the other.

## Gmail operations

These are the operations available for Gmail connections:

### Read operations

| Operation | Params | Description |
|-----------|--------|-------------|
| `list_emails` | `query` (string), `max_results` (int), `page_token` (string) | Search/list emails |
| `read_email` | `message_id` (string, required) | Read a single email |
| `read_thread` | `thread_id` (string, required) | Read an entire thread |
| `list_labels` | *(none)* | List available labels |
| `get_attachment` | `message_id` (string), `attachment_id` (string) | Download attachment |

### Write operations

| Operation | Params | Description |
|-----------|--------|-------------|
| `create_draft` | `to` ([]string), `cc` ([]string), `subject` (string), `body` (string), `reply_to` (string) | Create a draft |
| `update_draft` | `draft_id` (string), `to`, `cc`, `subject`, `body` | Update a draft |
| `send_email` | `to` ([]string), `cc` ([]string), `subject` (string), `body` (string), `reply_to` (string) | Send an email |
| `send_draft` | `draft_id` (string, required) | Send an existing draft |
| `reply` | `message_id` (string, required), `to`, `cc`, `subject`, `body` (required) | Reply to an email |
| `add_label` | `message_id` (string), `label_id` (string) | Add a label |
| `remove_label` | `message_id` (string), `label_id` (string) | Remove a label |
| `archive` | `message_id` (string, required) | Archive (remove INBOX label) |

## Gmail response formats

### list_emails response

```json
{
  "emails": [
    {
      "id": "18f3a...",
      "thread_id": "18f3a...",
      "from": "sender@example.com",
      "to": ["recipient@example.com"],
      "cc": [],
      "subject": "Meeting tomorrow",
      "body": "Let's meet at 3pm...",
      "body_html": "<p>Let's meet at 3pm...</p>",
      "date": "2026-04-08T10:30:00Z",
      "labels": ["INBOX", "IMPORTANT"],
      "snippet": "Let's meet at 3pm...",
      "has_attachment": false
    }
  ],
  "next_page_token": "",
  "total": 42
}
```

### read_email response

Same as a single email object from `list_emails`.

### read_thread response

```json
{
  "id": "18f3a...",
  "messages": [ ...email objects... ]
}
```

## Examples

### Block emails containing a keyword

```python
#!/usr/bin/env python3
"""Filter out emails mentioning 'CONFIDENTIAL'."""
import json, sys

req = json.load(sys.stdin)
phase = req.get("metadata", {}).get("phase", "pre")

if phase != "post":
    print(json.dumps({"action": "allow"}))
    sys.exit(0)

response = req["metadata"].get("response", "")
if "confidential" in response.lower():
    try:
        data = json.loads(response)
        if "emails" in data:
            filtered = [e for e in data["emails"]
                       if "confidential" not in json.dumps(e).lower()]
            removed = len(data["emails"]) - len(filtered)
            data["emails"] = filtered
            print(json.dumps({
                "action": "allow",
                "rewrite": json.dumps(data),
                "reason": f"Removed {removed} email(s)"
            }))
        else:
            print(json.dumps({"action": "deny", "reason": "Contains confidential content"}))
    except json.JSONDecodeError:
        print(json.dumps({"action": "deny", "reason": "Contains confidential content"}))
else:
    print(json.dumps({"action": "allow"}))
```

### Only allow emails from specific senders

```python
#!/usr/bin/env python3
"""Only allow reading emails from @company.com."""
import json, sys

req = json.load(sys.stdin)
op = req["operation"]
phase = req.get("metadata", {}).get("phase", "pre")

# Don't filter in post-phase or for non-read operations
if phase == "post" or op not in ("read_email", "read_thread", "list_emails"):
    print(json.dumps({"action": "allow"}))
    sys.exit(0)

# For list_emails, we can't filter before execution (we don't know
# the results yet), so allow and filter in post-phase
if op == "list_emails":
    print(json.dumps({"action": "allow"}))
    sys.exit(0)

# For read_email/read_thread, allow (post-phase script will filter)
print(json.dumps({"action": "allow"}))
```

### Redact sensitive patterns

```python
#!/usr/bin/env python3
"""Redact SSNs and credit card numbers from email responses."""
import json, re, sys

req = json.load(sys.stdin)
phase = req.get("metadata", {}).get("phase", "pre")

if phase != "post":
    print(json.dumps({"action": "allow"}))
    sys.exit(0)

response = req["metadata"].get("response", "")
patterns = [
    (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN REDACTED]'),
    (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[CARD REDACTED]'),
]

modified = response
for pattern, replacement in patterns:
    modified = re.sub(pattern, replacement, modified)

if modified != response:
    print(json.dumps({
        "action": "allow",
        "rewrite": modified,
        "reason": "Redacted sensitive patterns"
    }))
else:
    print(json.dumps({"action": "allow"}))
```

### Require approval for large sends

```python
#!/usr/bin/env python3
"""Require approval if sending to more than 5 recipients."""
import json, sys

req = json.load(sys.stdin)
op = req["operation"]
params = req.get("params", {})

if op not in ("send_email", "reply"):
    print(json.dumps({"action": "allow"}))
    sys.exit(0)

to = params.get("to", [])
cc = params.get("cc", [])
total = len(to) + len(cc)

if total > 5:
    print(json.dumps({
        "action": "approval_required",
        "reason": f"Sending to {total} recipients — requires approval"
    }))
else:
    print(json.dumps({"action": "allow"}))
```

## Timeouts

Scripts must return within 5 seconds (configurable per rule). If a script
times out or exits non-zero, the request is **denied** with an error message.

## Debugging

Script stderr is captured and included in deny messages. Use `print(..., file=sys.stderr)` for debug output that won't interfere with the JSON response.

```python
import sys
print("debug: checking email", file=sys.stderr)
```

Check the audit log at http://localhost:19816/audit to see policy decisions
and reasons for each request.
