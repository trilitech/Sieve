package scriptgen

// Scope-specific context templates. These are appended to the system prompt
// so the LLM knows exactly what fields are available in each API type.

const GmailTemplate = `
## Gmail API Context

Available operations: list_emails, read_email, read_thread, create_draft, update_draft,
send_email, send_draft, reply, add_label, remove_label, archive, list_labels, get_attachment

### Email stub (returned by list_emails — headers only, NO body):
- id: string
- thread_id: string
- from: string (email address)
- to: []string
- cc: []string
- subject: string
- date: string (RFC3339)
- labels: []string (e.g., ["INBOX", "IMPORTANT", "project-x"])
- snippet: string (short preview text)

### Full email (returned by read_email and read_thread — includes body):
- All stub fields, plus:
- body: string (plain text)
- body_html: string
- has_attachment: bool
- attachments: []{id, filename, mime_type, size}

### Pre-phase metadata (same as params):
- For list_emails: {"query": "search string", "max_results": int}
- For read_email: {"message_id": "..."}
- For send_email: {"to": [...], "subject": "...", "body": "..."}

### Post-phase metadata:
- {"phase": "post", "response": "<JSON string of email or list>"}
- For list_emails response: {"emails": [...stubs...], "total": int, "next_page_token": "..."}
  (stubs only — to inspect a body in a script, look at read_email responses instead)
- For read_email response: single full email object with body

### Example script (filter emails by sender domain):
` + "```python" + `
#!/usr/bin/env python3
# Policy: Only allow reading emails from @company.com
import json, sys
req = json.load(sys.stdin)
phase = req.get("metadata", {}).get("phase", "pre")
if phase != "post":
    print(json.dumps({"action": "allow"}))
    sys.exit(0)
response = req["metadata"].get("response", "")
try:
    data = json.loads(response)
    if "emails" in data:
        filtered = [e for e in data["emails"] if "@company.com" in e.get("from", "")]
        data["emails"] = filtered
        print(json.dumps({"action": "allow", "rewrite": json.dumps(data)}))
    else:
        from_addr = data.get("from", "")
        if "@company.com" in from_addr:
            print(json.dumps({"action": "allow"}))
        else:
            print(json.dumps({"action": "deny", "reason": "sender not from company.com"}))
except:
    print(json.dumps({"action": "deny", "reason": "failed to parse response"}))
` + "```" + `
`

const LLMTemplate = `
## LLM API Context

This policy applies to LLM API calls (Anthropic, OpenAI, Gemini, Bedrock).

### Pre-phase params (what the agent is trying to send):
- For Anthropic messages.create: {"model": "...", "messages": [...], "max_tokens": int, "system": "...", "temperature": float}
- For OpenAI chat.completions: {"model": "...", "messages": [...], "max_tokens": int, "temperature": float}
- For Gemini generateContent: {"model": "...", "contents": [...], "generationConfig": {...}}

The params are the raw JSON body being sent to the LLM API.

### Post-phase metadata:
- {"phase": "post", "response": "<full JSON response from the LLM>"}

### Common policy patterns:
- Model restriction: check params["model"] in pre-phase
- Prompt filtering: check params["messages"] content in pre-phase
- Response filtering: check response content in post-phase
- Cost estimation: check model + max_tokens in pre-phase

### Example script (restrict to specific models):
` + "```python" + `
#!/usr/bin/env python3
# Policy: Only allow claude-sonnet and gpt-4o-mini models
import json, sys
req = json.load(sys.stdin)
phase = req.get("metadata", {}).get("phase", "pre")
if phase == "post":
    print(json.dumps({"action": "allow"}))
    sys.exit(0)
model = req.get("params", {}).get("model", "")
body = req.get("metadata", {}).get("body", "")
if not model and body:
    try:
        model = json.loads(body).get("model", "")
    except:
        pass
allowed = ["claude-sonnet-4-20250514", "gpt-4o-mini"]
if any(m in model for m in allowed):
    print(json.dumps({"action": "allow"}))
else:
    print(json.dumps({"action": "deny", "reason": f"model '{model}' not allowed"}))
` + "```" + `
`

const HTTPProxyTemplate = `
## HTTP Proxy Context

This policy applies to generic HTTP proxy requests.

### Pre-phase params:
- method: string (GET, POST, PUT, DELETE, PATCH)
- path: string (the URL path being accessed, e.g., "/v1/charges")

### Post-phase metadata:
- {"phase": "post", "response": "<full HTTP response body as string>"}

### Common policy patterns:
- Path restriction: check params["path"] in pre-phase
- Method restriction: check params["method"] in pre-phase
- Request body filtering: check metadata for sensitive content
- Response redaction: rewrite response to remove sensitive fields

### Example script (restrict to specific API paths):
` + "```python" + `
#!/usr/bin/env python3
# Policy: Only allow read operations on specific paths
import json, sys
req = json.load(sys.stdin)
phase = req.get("metadata", {}).get("phase", "pre")
if phase == "post":
    print(json.dumps({"action": "allow"}))
    sys.exit(0)
method = req.get("params", {}).get("method", req.get("metadata", {}).get("method", ""))
path = req.get("params", {}).get("path", req.get("metadata", {}).get("path", ""))
allowed_paths = ["/v1/messages", "/v1/models"]
if method == "GET" or any(path.startswith(p) for p in allowed_paths):
    print(json.dumps({"action": "allow"}))
else:
    print(json.dumps({"action": "deny", "reason": f"{method} {path} not allowed"}))
` + "```" + `
`

// GetTemplate returns the appropriate template for a scope.
func GetTemplate(scope string) string {
	switch scope {
	case "gmail":
		return GmailTemplate
	case "llm":
		return LLMTemplate
	case "http_proxy":
		return HTTPProxyTemplate
	default:
		return HTTPProxyTemplate // generic fallback
	}
}
