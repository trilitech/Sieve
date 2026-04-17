# Policy Rules Reference

This document is the complete reference for Sieve's declarative rules-based policy engine. Rules determine what operations an AI agent can perform, under what conditions, and how responses are filtered.

## Policy structure

A rules-type policy has three top-level fields:

```json
{
  "rules": [ ... ],
  "default_action": "deny",
  "scope": "gmail"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `rules` | array of Rule | Yes | Ordered list of rules. Evaluated top-to-bottom, first match wins. |
| `default_action` | string | No | Action when no rule matches. `"allow"` or `"deny"`. Defaults to `"deny"` (fail-closed). |
| `scope` | string | No | Hint for what service this policy targets. Not enforced -- used by the UI for field suggestions. |

## Rule format

Each rule in the `rules` array:

```json
{
  "match": { ... },
  "action": "allow",
  "reason": "Read operations are permitted",
  "filter_exclude": "CONFIDENTIAL",
  "redact_patterns": ["\\b\\d{3}-\\d{2}-\\d{4}\\b"],
  "response_filter": { ... },
  "script": { ... }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `match` | object | No | Conditions that must all be true for this rule to fire (AND logic). Omit or set to `null` to match everything (catch-all rule). |
| `action` | string | Yes | What to do when matched: `allow`, `deny`, `approval_required`, `filter`, or `script`. |
| `reason` | string | No | Human-readable explanation. Shown to agents on deny, logged on allow. |
| `filter_exclude` | string | No | Remove items from list responses that contain this text (case-insensitive). Legacy shorthand for `response_filter.exclude_containing`. |
| `redact_patterns` | array of string | No | Regex patterns. Matched text in responses is replaced with `[REDACTED]`. Legacy shorthand for `response_filter.redact_patterns`. |
| `response_filter` | object | No | Post-execution response filter applied when this rule matches with `allow`. |
| `script` | object | No | Script configuration. Only used when `action` is `"script"`. |

## Actions

### allow

Permit the operation. If `response_filter`, `filter_exclude`, or `redact_patterns` are set, the response is post-processed before returning to the agent.

### deny

Block the operation. The agent receives an error with the `reason` text.

### approval_required

Hold the operation for human review. The request appears in the approval queue at the Sieve admin UI. For MCP clients, the server returns immediately with an approval ID and a URL to poll for resolution. For REST API clients, the server responds with HTTP 429 and a `Retry-After` header.

### filter

Alias for `allow`. Permits the operation with response filtering. Primarily used in the web UI to distinguish "allow with filters" from plain "allow".

### script

Delegate the decision to an external script. The script receives a JSON request on stdin and writes a JSON decision to stdout. Requires the `script` field:

```json
{
  "match": { "operations": ["send_email"] },
  "action": "script",
  "script": {
    "command": "python3",
    "path": "./policies/check-send.py",
    "timeout": "5s"
  }
}
```

| Script field | Description |
|--------------|-------------|
| `command` | Interpreter command (e.g., `python3`, `node`) |
| `path` | Path to the script file |
| `timeout` | Maximum execution time (Go duration, e.g., `5s`) |

See [Policy Scripts](policy-scripts.md) for the full script protocol.

## Response filter

The `response_filter` object controls post-execution response processing:

```json
{
  "response_filter": {
    "exclude_containing": "CONFIDENTIAL",
    "redact_patterns": ["\\b\\d{3}-\\d{2}-\\d{4}\\b"],
    "script_path": "./policies/filter.py",
    "script_command": "python3"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `exclude_containing` | string | Remove items from list responses that contain this text (case-insensitive) |
| `redact_patterns` | array of string | Regex patterns whose matches are replaced with `[REDACTED]` |
| `script_path` | string | Path to a post-filter script |
| `script_command` | string | Interpreter for the post-filter script (e.g., `python3`) |

Global response filters can also be set at the policy level in `response_filters` (array), which apply after any per-rule filters.

## Match fields

All conditions within a single `match` block use AND logic: every specified field must match for the rule to fire. Omitted fields are ignored (they don't constrain matching).

An empty or null `match` block matches everything -- use this for catch-all rules at the bottom of the list.

### Common fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| Operations | `operations` | array of string | Exact match, `"*"` wildcard | Operation names to match. Empty = match all operations. |
| Content contains | `content_contains` | string | Case-insensitive substring | Match if the response metadata contains this text |

### Gmail fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| From | `from` | array of string | Glob (`*@domain.com`) | Sender address. Checked in metadata then params. |
| To | `to` | array of string | Glob (`*@domain.com`) | Recipient address. Checked in metadata then params. |
| Subject contains | `subject_contains` | array of string | Case-insensitive substring | Match if subject contains any of these strings |
| Labels | `labels` | array of string | Case-insensitive exact | Match if the email has at least one of these labels |

**Gmail operations:** `list_emails`, `read_email`, `read_thread`, `create_draft`, `update_draft`, `send_email`, `send_draft`, `reply`, `add_label`, `remove_label`, `archive`, `list_labels`, `get_attachment`

**Example -- read-only with label filtering:**

```json
{
  "rules": [
    {
      "match": {
        "operations": ["list_emails", "read_email", "read_thread", "list_labels"],
        "labels": ["project-x"]
      },
      "action": "allow",
      "reason": "Read project-x emails only"
    },
    {
      "match": { "operations": ["send_email", "send_draft", "reply"] },
      "action": "approval_required",
      "reason": "Sends require approval"
    }
  ],
  "default_action": "deny"
}
```

### LLM fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| Model | `model` | array of string | Glob (`claude-*`, `*-sonnet-*`) | LLM model name. Prefix and suffix wildcards supported. |
| Providers | `providers` | array of string | Case-insensitive exact | Provider name (e.g., `anthropic`, `openai`, `google`) |
| Max tokens | `max_tokens` | int | Numeric comparison | Deny if request's `max_tokens` exceeds this value |
| Max cost | `max_cost` | float | Numeric comparison | Deny if estimated cost exceeds this value (dollars) |
| Extended thinking | `extended_thinking` | string | Exact (`enabled`/`disabled`) | Match against extended thinking mode. Boolean `true` maps to `"enabled"`. |
| System prompt contains | `system_prompt_contains` | string | Case-insensitive substring | Match against `system` or `system_prompt` parameter |
| Max temperature | `max_temperature` | float | Numeric comparison | Deny if `temperature` exceeds this value |
| JSON mode | `json_mode` | string | Special (`required`/`forbidden`) | `"required"`: only match if response format is JSON. `"forbidden"`: only match if it is not JSON. |
| Grounding | `grounding` | string | Exact (`enabled`/`disabled`) | Match against grounding mode. Boolean `true` maps to `"enabled"`. |
| Safety threshold | `safety_threshold` | string | Case-insensitive exact | Match against `safety` or `safety_settings` parameter |

**Example -- Sonnet only, cost cap:**

```json
{
  "rules": [
    {
      "match": {
        "model": ["claude-sonnet-*"],
        "max_cost": 0.50,
        "max_tokens": 4096
      },
      "action": "allow"
    }
  ],
  "default_action": "deny"
}
```

### HTTP Proxy fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| Path | `path` | string | Glob (prefix/suffix `*`) | Request path. Supports prefix and suffix wildcards. |
| Body contains | `body_contains` | string | Case-insensitive substring | Match against request body text |

**Example -- restrict API paths:**

```json
{
  "rules": [
    {
      "match": { "path": "/v1/messages*" },
      "action": "allow"
    },
    {
      "match": { "path": "/v1/admin*" },
      "action": "deny",
      "reason": "Admin endpoints are blocked"
    }
  ],
  "default_action": "deny"
}
```

### Google Drive fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| MIME type | `mime_type` | string | Glob | File MIME type (e.g., `application/pdf`, `image/*`) |
| Owner | `owner` | string | Glob | File owner email address |
| Shared status | `shared_status` | string | Case-insensitive exact | `"shared with me"` or `"owned by me"` |

**Drive operations:** `drive.list_files`, `drive.get_file`, `drive.download_file`, `drive.upload_file`, `drive.share_file`

**Example -- read-only PDFs:**

```json
{
  "rules": [
    {
      "match": {
        "operations": ["drive.list_files", "drive.get_file", "drive.download_file"],
        "mime_type": "application/pdf"
      },
      "action": "allow"
    }
  ],
  "default_action": "deny"
}
```

### Google Calendar fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| Calendar ID | `calendar_id` | string | Case-insensitive exact | Calendar identifier (e.g., `primary`, a specific calendar ID) |
| Attendee | `attendee` | string | Glob | Attendee email address |

**Calendar operations:** `calendar.list_events`, `calendar.get_event`, `calendar.create_event`, `calendar.update_event`, `calendar.delete_event`

**Example -- read-only on primary calendar:**

```json
{
  "rules": [
    {
      "match": {
        "operations": ["calendar.list_events", "calendar.get_event"],
        "calendar_id": "primary"
      },
      "action": "allow"
    },
    {
      "match": { "operations": ["calendar.create_event"] },
      "action": "approval_required"
    }
  ],
  "default_action": "deny"
}
```

### Google People (Contacts) fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| Contact group | `contact_group` | string | Case-insensitive exact | Contact group name. Also checks `group` param. |
| Allowed fields | `allowed_fields` | string | Comma-separated allowlist | Each field in the request's `fields` param must be in this list. |

**People operations:** `people.list_contacts`, `people.get_contact`, `people.create_contact`, `people.update_contact`, `people.delete_contact`

**Example -- read contacts, only name and email:**

```json
{
  "rules": [
    {
      "match": {
        "operations": ["people.list_contacts", "people.get_contact"],
        "allowed_fields": "name,email"
      },
      "action": "allow"
    }
  ],
  "default_action": "deny"
}
```

### Google Sheets fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| Spreadsheet ID | `spreadsheet_id` | string | Case-insensitive exact | Specific spreadsheet ID to allow |
| Range pattern | `range_pattern` | string | Glob | A1 notation range pattern (e.g., `Sheet1!*`) |

**Sheets operations:** `sheets.get_spreadsheet`, `sheets.read_range`, `sheets.write_range`, `sheets.create_spreadsheet`

**Example -- read-only on a specific spreadsheet:**

```json
{
  "rules": [
    {
      "match": {
        "operations": ["sheets.get_spreadsheet", "sheets.read_range"],
        "spreadsheet_id": "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms"
      },
      "action": "allow"
    }
  ],
  "default_action": "deny"
}
```

### Google Docs fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| Document ID | `document_id` | string | Case-insensitive exact | Specific document ID to allow |
| Title contains | `title_contains` | string | Case-insensitive substring | Match if document title contains this text |

**Docs operations:** `docs.get_document`, `docs.list_documents`, `docs.create_document`, `docs.update_document`

**Example -- read docs with "Report" in title:**

```json
{
  "rules": [
    {
      "match": {
        "operations": ["docs.get_document", "docs.list_documents"],
        "title_contains": "Report"
      },
      "action": "allow"
    }
  ],
  "default_action": "deny"
}
```

### AWS EC2 fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| Instance type | `instance_type` | array of string | Case-insensitive exact | Allowed EC2 instance types (e.g., `t3.micro`, `t3.small`) |
| Region | `region` | string | Case-insensitive exact | AWS region (e.g., `us-east-1`) |
| Max count | `max_count` | int | Numeric comparison | Maximum number of instances. Checks `max_count` then `count` params. |
| AMI | `ami` | string | Glob | AMI ID. Also checks `image_id` param. |
| VPC | `vpc` | string | Case-insensitive exact | VPC or subnet ID. Checks `vpc_id` then `subnet_id` params. |
| Ports | `ports` | string | Comma-separated allowlist | Allowed ports. The request's `port` param must be in this list. |
| CIDR | `cidr` | string | Exact or negation (`!0.0.0.0/0`) | CIDR block. Prefix with `!` to deny a specific value (e.g., `!0.0.0.0/0` blocks open-to-world). |
| Tag | `tag` | string | Case-insensitive exact | Tag in `key=value` format. Checks `tag` then `tags` params. |

**Example -- restrict EC2 to small instances in us-east-1:**

```json
{
  "rules": [
    {
      "match": {
        "instance_type": ["t3.micro", "t3.small"],
        "region": "us-east-1",
        "max_count": 3,
        "cidr": "!0.0.0.0/0"
      },
      "action": "allow"
    }
  ],
  "default_action": "deny"
}
```

### AWS S3 fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| Bucket | `bucket` | string | Glob (prefix/suffix `*`) | S3 bucket name |
| Key prefix | `key_prefix` | string | Prefix match | S3 object key must start with this prefix |

**Example -- read-only on a specific bucket and prefix:**

```json
{
  "rules": [
    {
      "match": {
        "operations": ["s3.get_object", "s3.list_objects"],
        "bucket": "data-exports",
        "key_prefix": "2024/"
      },
      "action": "allow"
    }
  ],
  "default_action": "deny"
}
```

### AWS Lambda fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| Function name | `function_name` | string | Glob | Lambda function name. Supports prefix and suffix wildcards. |

### AWS SES fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| Recipient | `recipient` | string | Glob | Recipient email. Also checks `to` param. |
| Sender identity | `sender_identity` | string | Case-insensitive exact | Verified sender address. Checks `sender` then `from` params. |

### AWS DynamoDB fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| Table name | `table_name` | string | Case-insensitive exact | DynamoDB table name. Also checks `table` param. |
| Index name | `index_name` | string | Case-insensitive exact | Secondary index name. Also checks `index` param. |

### Hyperstack fields

| Field | JSON key | Type | Matching | Description |
|-------|----------|------|----------|-------------|
| Flavor | `flavor` | string | Case-insensitive exact | VM flavor (instance type) |
| Max VMs | `max_vms` | int | Numeric comparison | Maximum number of VMs. Checked against `count` param. |

**Example -- limit Hyperstack VMs:**

```json
{
  "rules": [
    {
      "match": {
        "flavor": "n1-RTX-A6000x1",
        "max_vms": 2
      },
      "action": "allow"
    }
  ],
  "default_action": "deny"
}
```

## Matching behavior reference

| Behavior | Fields | How it works |
|----------|--------|--------------|
| **Exact match** | `providers`, `instance_type`, `region`, `calendar_id`, `spreadsheet_id`, `document_id`, `vpc`, `table_name`, `index_name`, `flavor`, `contact_group`, `sender_identity`, `shared_status`, `tag` | Case-insensitive string comparison |
| **Glob** | `from`, `to`, `model`, `path`, `bucket`, `mime_type`, `owner`, `attendee`, `ami`, `function_name`, `recipient`, `range_pattern` | Supports `*` prefix (`*@domain.com`), `*` suffix (`claude-*`), or exact. Case-insensitive. |
| **Substring** | `content_contains`, `subject_contains`, `body_contains`, `system_prompt_contains`, `title_contains` | Case-insensitive substring search |
| **Prefix** | `key_prefix` | Value must start with the specified prefix (case-sensitive) |
| **Numeric** | `max_tokens`, `max_cost`, `max_count`, `max_temperature`, `max_vms` | Request value must not exceed the configured limit |
| **Allowlist** | `operations`, `ports`, `allowed_fields` | Value must be in the comma-separated or array list |
| **Negation** | `cidr` | Prefix with `!` to deny a specific value (e.g., `!0.0.0.0/0`) |
| **Special** | `json_mode` | `"required"` matches JSON response format; `"forbidden"` matches non-JSON |
| **Toggle** | `extended_thinking`, `grounding` | `"enabled"` or `"disabled"`. Boolean `true` maps to `"enabled"`. |

## Evaluation semantics

### First-match-wins

Rules are evaluated top-to-bottom. The first rule whose `match` conditions all hold determines the outcome. No further rules are evaluated. This makes rule ordering critical:

1. Put specific rules first (narrow conditions)
2. Put broader rules after
3. Put catch-all rules last (empty match or `"operations": ["*"]`)

If no rule matches, the `default_action` applies (defaults to `"deny"`).

### AND logic within a rule

All conditions in a `match` block must be true for the rule to fire. Adding more conditions makes a rule narrower, not broader. To create OR logic, use multiple rules.

```json
{
  "rules": [
    { "match": { "from": ["*@company.com"] }, "action": "allow" },
    { "match": { "from": ["*@partner.com"] }, "action": "allow" },
    { "action": "deny" }
  ]
}
```

### Composite evaluation across multiple policies

When a role binds multiple policies to a single connection, they are combined into a composite evaluator. All policies must agree on `"allow"` for the operation to proceed. If any policy returns `"deny"` or `"approval_required"`, that decision takes precedence. Response filters from all policies are combined and applied in order.

### Pre-execution and post-execution phases

Rules evaluate in a single pre-execution phase. Post-execution content filtering is handled separately via `response_filter`, `filter_exclude`, and `redact_patterns` fields on matching rules. This means:

- Pre-phase: "Should this operation be allowed?" -- checks operations, params, conditions
- Post-phase: "How should the response be modified?" -- applies filters and redactions to the actual response data

## Complete example

A comprehensive policy for a project assistant with Gmail, LLM, and Drive access:

```json
{
  "rules": [
    {
      "match": {
        "operations": ["list_emails", "read_email", "read_thread", "list_labels"],
        "from": ["*@company.com", "*@partner.com"]
      },
      "action": "allow",
      "reason": "Read emails from company and partners",
      "redact_patterns": ["\\b\\d{3}-\\d{2}-\\d{4}\\b"]
    },
    {
      "match": {
        "operations": ["create_draft", "update_draft"],
        "to": ["*@company.com"]
      },
      "action": "allow",
      "reason": "Draft to internal recipients"
    },
    {
      "match": { "operations": ["send_email", "send_draft", "reply"] },
      "action": "approval_required",
      "reason": "All sends require human review"
    },
    {
      "match": {
        "operations": ["drive.list_files", "drive.get_file", "drive.download_file"],
        "mime_type": "application/pdf"
      },
      "action": "allow",
      "reason": "Read PDF files from Drive"
    },
    {
      "match": { "operations": ["drive.upload_file", "drive.share_file"] },
      "action": "deny",
      "reason": "No uploading or sharing"
    },
    {
      "match": {
        "model": ["claude-sonnet-*"],
        "max_tokens": 4096,
        "max_cost": 0.50
      },
      "action": "allow",
      "reason": "Sonnet models with cost cap"
    }
  ],
  "default_action": "deny"
}
```
