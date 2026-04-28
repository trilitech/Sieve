// Package scriptgen generates Python policy scripts from natural language
// descriptions using an LLM. It reads the user's configured LLM connection
// from settings, builds a prompt with scope-specific context, calls the LLM
// via the HTTP proxy connector, and extracts the generated Python code.
package scriptgen

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/settings"
)

// Service generates Python policy scripts via LLM.
type Service struct {
	connections *connections.Service
	settings   *settings.Service
}

// NewService creates a new script generation service.
func NewService(conns *connections.Service, settings *settings.Service) *Service {
	return &Service{
		connections: conns,
		settings:    settings,
	}
}

// GenerateRequest is the input for script generation.
type GenerateRequest struct {
	Description string // "Only allow emails from @company.com about Project X"
	Scope       string // "gmail", "llm", "http_proxy"
}

// GenerateResult is the output from script generation.
type GenerateResult struct {
	Script      string // The generated Python script
	Explanation string // One-line explanation
}

// Generate calls the configured LLM to generate a Python policy script.
func (s *Service) Generate(ctx context.Context, req *GenerateRequest) (*GenerateResult, error) {
	// 1. Read LLM settings.
	connID, err := s.settings.Get(settings.KeyLLMConnection)
	if err != nil || connID == "" {
		return nil, fmt.Errorf("LLM connection not configured — go to Settings to set it up")
	}

	model, err := s.settings.Get(settings.KeyLLMModel)
	if err != nil || model == "" {
		return nil, fmt.Errorf("LLM model not configured — go to Settings to set it up")
	}

	maxTokensStr, _ := s.settings.Get(settings.KeyLLMMaxTokens)
	maxTokens := 4096
	if maxTokensStr != "" {
		if n, err := strconv.Atoi(maxTokensStr); err == nil && n > 0 {
			maxTokens = n
		}
	}

	// 2. Get the connector for this connection.
	conn, err := s.connections.GetConnector(connID)
	if err != nil {
		return nil, fmt.Errorf("failed to get LLM connection %q: %w", connID, err)
	}

	// 3. Build the prompt.
	scopeTemplate := scopeTemplateFor(req.Scope)
	userMessage := fmt.Sprintf("Generate a Sieve policy script for the %s scope.\n\nDescription: %s\n\n%s",
		req.Scope, req.Description, scopeTemplate)

	// 4. Determine the provider format and build the request.
	connDetail, err := s.connections.GetWithConfig(connID)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection config: %w", err)
	}

	targetURL, _ := connDetail.Config["target_url"].(string)
	isAnthropic := strings.Contains(strings.ToLower(targetURL), "anthropic")

	var apiPath string
	var bodyJSON string

	if isAnthropic {
		apiPath = "/v1/messages"
		body := map[string]any{
			"model":      model,
			"max_tokens": maxTokens,
			"system":     systemPrompt,
			"messages": []map[string]any{
				{"role": "user", "content": userMessage},
			},
		}
		b, _ := json.Marshal(body)
		bodyJSON = string(b)
	} else {
		apiPath = "/v1/chat/completions"
		body := map[string]any{
			"model":      model,
			"max_tokens": maxTokens,
			"messages": []map[string]any{
				{"role": "system", "content": systemPrompt},
				{"role": "user", "content": userMessage},
			},
		}
		b, _ := json.Marshal(body)
		bodyJSON = string(b)
	}

	// 5. Call the connector.
	result, err := conn.Execute(ctx, "proxy_request", map[string]any{
		"method":       "POST",
		"path":         apiPath,
		"body":         bodyJSON,
		"content_type": "application/json",
	})
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}

	// 6. Parse the response.
	respMap, ok := result.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected response type from connector")
	}

	status, _ := respMap["status"].(int)
	respBody, _ := respMap["body"].(string)

	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("LLM API returned status %d: %s", status, truncate(respBody, 500))
	}

	text, err := extractLLMText(respBody, isAnthropic)
	if err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	script, explanation := extractScript(text)

	return &GenerateResult{
		Script:      script,
		Explanation: explanation,
	}, nil
}

// extractLLMText pulls the text content from an Anthropic or OpenAI response body.
func extractLLMText(body string, isAnthropic bool) (string, error) {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return "", fmt.Errorf("invalid JSON response: %w", err)
	}

	if isAnthropic {
		// Anthropic: content[0].text
		content, ok := parsed["content"].([]any)
		if !ok || len(content) == 0 {
			return "", fmt.Errorf("no content in Anthropic response")
		}
		block, ok := content[0].(map[string]any)
		if !ok {
			return "", fmt.Errorf("invalid content block in Anthropic response")
		}
		text, ok := block["text"].(string)
		if !ok {
			return "", fmt.Errorf("no text in Anthropic content block")
		}
		return text, nil
	}

	// OpenAI: choices[0].message.content
	choices, ok := parsed["choices"].([]any)
	if !ok || len(choices) == 0 {
		return "", fmt.Errorf("no choices in OpenAI response")
	}
	choice, ok := choices[0].(map[string]any)
	if !ok {
		return "", fmt.Errorf("invalid choice in OpenAI response")
	}
	message, ok := choice["message"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("no message in OpenAI choice")
	}
	text, ok := message["content"].(string)
	if !ok {
		return "", fmt.Errorf("no content in OpenAI message")
	}
	return text, nil
}

// extractScript pulls Python code from the LLM output text. It looks for
// ```python ... ``` blocks first, falling back to the entire text.
// It also extracts a one-line explanation if present.
func extractScript(text string) (script string, explanation string) {
	// Try to extract a ```python block.
	re := regexp.MustCompile("(?s)```python\\s*\n(.*?)```")
	matches := re.FindStringSubmatch(text)
	if len(matches) >= 2 {
		script = strings.TrimSpace(matches[1])
	} else {
		// No code block found; use the whole text.
		script = strings.TrimSpace(text)
	}

	// Try to extract an explanation line before the code block.
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "```") || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "import ") && !strings.HasPrefix(line, "from ") &&
			!strings.HasPrefix(line, "def ") && !strings.HasPrefix(line, "{") {
			explanation = line
			break
		}
	}

	return script, explanation
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func scopeTemplateFor(scope string) string {
	switch scope {
	case "gmail":
		return gmailTemplate
	case "llm":
		return llmTemplate
	case "http_proxy":
		return httpProxyTemplate
	default:
		return gmailTemplate
	}
}

// --- Prompts and templates ---

const systemPrompt = `You are a code generator for Sieve, a policy proxy for AI agents.
You generate Python scripts that act as policy filters. The script receives a JSON request
on stdin and writes a JSON decision to stdout.

Input format:
{"operation": "...", "connection": "...", "connector": "...", "params": {...}, "metadata": {...}}

In post-phase, metadata includes: {"phase": "post", "response": "<JSON string>"}

Output format:
{"action": "allow|deny|approval_required", "reason": "...", "rewrite": "optional edited response"}

The script runs in BOTH pre and post phases. Check metadata.phase to distinguish.
Return {"action": "allow"} for phases you don't care about.

IMPORTANT: The script must be a complete, self-contained Python program.
Start with a comment block explaining what the script does.
Use only standard library + requests, httpx, regex, pyyaml, beautifulsoup4, pydantic.

Return ONLY the Python script inside a single python code block. Before the code block,
write a one-line explanation of what the script does.`

const gmailTemplate = `Scope: Gmail

Available operations:
- send_email: params include "to" ([]string), "subject" (string), "body" (string), "cc" ([]string), "bcc" ([]string)
- read_email: params include "id" (string)
- list_emails: params include "query" (string), "max_results" (int)
- create_draft: params include "to" ([]string), "subject" (string), "body" (string)
- modify_labels: params include "id" (string), "add_labels" ([]string), "remove_labels" ([]string)

Email fields available in the request params:
- to, from, subject, body, cc, bcc, labels, thread_id, message_id

In post-phase responses, the response field contains the Gmail API response as a JSON string
with fields like: id, threadId, labelIds, snippet, payload (headers, body, parts).`

const llmTemplate = `Scope: LLM API

Available operations:
- proxy_request: params include "method" (string), "path" (string), "body" (string)

The body for LLM requests typically contains:
- model (string): the model name
- messages ([]object): chat messages with "role" and "content"
- max_tokens (int): maximum tokens to generate
- temperature (float): sampling temperature
- system (string): system prompt (Anthropic format)
- tools ([]object): tool/function definitions

In post-phase, the response contains the LLM API response which typically includes:
- For Anthropic: content[].text, model, usage
- For OpenAI: choices[].message.content, model, usage

Common policies: block certain models, limit max_tokens, filter system prompts,
redact PII from responses, enforce content policies.`

const httpProxyTemplate = `Scope: HTTP Proxy

Available operations:
- proxy_request: params include "method" (string), "path" (string), "body" (string), "headers" (object)

HTTP request fields:
- method: GET, POST, PUT, DELETE, PATCH, etc.
- path: the URL path being requested (e.g., "/v1/messages", "/api/data")
- body: the request body as a string (often JSON)
- headers: request headers as key-value pairs
- content_type: the Content-Type header

In post-phase, the response contains:
- status (int): HTTP status code
- headers (object): response headers
- body (string): response body

Common policies: restrict allowed paths, block certain HTTP methods,
filter request/response bodies, enforce rate limits, validate request schemas.`
