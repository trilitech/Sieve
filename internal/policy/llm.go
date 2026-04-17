package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// LLMConfig holds configuration for the LLM evaluator.
type LLMConfig struct {
	Provider string        `json:"provider"` // "ollama", "bedrock", "anthropic", "openai"
	Model    string        `json:"model"`
	Prompt   string        `json:"prompt"`   // template with {{request_json}} placeholder
	Timeout  time.Duration `json:"timeout"`  // default 10s
	Fallback string        `json:"fallback"` // "allow" or "deny", default "deny"
}

// maxLLMResponseBytes caps how much of an LLM response we will read into
// memory. Beyond this we treat the response as failed and take the fallback
// decision. Prevents OOM from misbehaving/malicious upstream LLMs.
const maxLLMResponseBytes = 5 * 1024 * 1024 // 5 MiB

// readLimitedLLMResponse reads up to maxLLMResponseBytes from r. Returns an
// error if the response exceeds the cap.
func readLimitedLLMResponse(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxLLMResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxLLMResponseBytes {
		return nil, fmt.Errorf("response exceeds %d byte limit", maxLLMResponseBytes)
	}
	return b, nil
}

// truncateForAudit caps an error fragment so a large upstream error body
// cannot bloat policy decision reasons and audit log entries.
func truncateForAudit(s string) string {
	const maxAuditChars = 500
	if len(s) > maxAuditChars {
		return s[:maxAuditChars] + "... (truncated)"
	}
	return s
}

// LLMEvaluator calls an LLM API to make policy decisions.
type LLMEvaluator struct {
	config    LLMConfig
	providers map[string]LLMProviderConfig
}

// NewLLMEvaluator creates an LLMEvaluator from a generic config map.
func NewLLMEvaluator(config map[string]any, providers map[string]LLMProviderConfig) (*LLMEvaluator, error) {
	var lc LLMConfig

	if v, ok := config["provider"]; ok {
		if s, ok := v.(string); ok {
			lc.Provider = s
		}
	}
	if v, ok := config["model"]; ok {
		if s, ok := v.(string); ok {
			lc.Model = s
		}
	}
	if v, ok := config["prompt"]; ok {
		if s, ok := v.(string); ok {
			lc.Prompt = s
		}
	}
	if v, ok := config["fallback"]; ok {
		if s, ok := v.(string); ok {
			lc.Fallback = s
		}
	}

	lc.Timeout = parseTimeout(config["timeout"], 10*time.Second)

	if lc.Provider == "" {
		return nil, fmt.Errorf("llm evaluator: provider is required")
	}
	if lc.Prompt == "" {
		return nil, fmt.Errorf("llm evaluator: prompt template is required")
	}
	if lc.Fallback == "" || lc.Fallback == "allow" {
		// Security: fallback="allow" would auto-allow on any LLM error.
		// Always override to "deny" for fail-closed behavior.
		lc.Fallback = "deny"
	}

	return &LLMEvaluator{
		config:    lc,
		providers: providers,
	}, nil
}

// Type returns the evaluator type identifier.
func (l *LLMEvaluator) Type() string {
	return "llm"
}

// Evaluate calls the LLM provider and parses the response for a policy decision.
func (l *LLMEvaluator) Evaluate(ctx context.Context, req *PolicyRequest) (*PolicyDecision, error) {
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return l.fallbackDecision("failed to marshal request: " + err.Error()), nil
	}

	prompt := strings.ReplaceAll(l.config.Prompt, "{{request_json}}", string(reqJSON))

	switch l.config.Provider {
	case "ollama":
		return l.evaluateOllama(ctx, prompt)
	case "anthropic":
		return l.evaluateAnthropic(ctx, prompt)
	case "openai":
		return l.evaluateOpenAI(ctx, prompt)
	case "bedrock":
		return l.evaluateOpenAI(ctx, prompt) // Bedrock uses OpenAI-compatible API
	default:
		return nil, fmt.Errorf("llm evaluator: unknown provider %q", l.config.Provider)
	}
}

// evaluateOllama calls the Ollama /api/generate endpoint.
func (l *LLMEvaluator) evaluateOllama(ctx context.Context, prompt string) (*PolicyDecision, error) {
	timeout := l.config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := "http://localhost:11434"
	if pc, ok := l.providers[l.config.Provider]; ok && pc.Endpoint != "" {
		endpoint = pc.Endpoint
	}

	model := l.config.Model
	if model == "" {
		if pc, ok := l.providers[l.config.Provider]; ok && pc.Model != "" {
			model = pc.Model
		}
	}

	body := map[string]any{
		"model":  model,
		"prompt": prompt,
		"stream": false,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return l.fallbackDecision("failed to marshal ollama request: " + err.Error()), nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/api/generate", bytes.NewReader(bodyBytes))
	if err != nil {
		return l.fallbackDecision("failed to create HTTP request: " + err.Error()), nil
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return l.fallbackDecision("ollama request failed: " + err.Error()), nil
	}
	defer resp.Body.Close()

	respBody, err := readLimitedLLMResponse(resp.Body)
	if err != nil {
		return l.fallbackDecision("failed to read ollama response: " + err.Error()), nil
	}

	if resp.StatusCode != http.StatusOK {
		return l.fallbackDecision(fmt.Sprintf("ollama returned status %d: %s", resp.StatusCode, truncateForAudit(string(respBody)))), nil
	}

	// Parse the Ollama response to extract the generated text.
	var ollamaResp struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
		return l.fallbackDecision("failed to parse ollama response: " + err.Error()), nil
	}

	// Try to extract a JSON decision from the generated text.
	decision, err := extractDecisionFromText(ollamaResp.Response)
	if err != nil {
		return l.fallbackDecision("failed to extract decision from LLM response: " + err.Error()), nil
	}

	return decision, nil
}

// evaluateAnthropic calls the Anthropic Messages API.
func (l *LLMEvaluator) evaluateAnthropic(ctx context.Context, prompt string) (*PolicyDecision, error) {
	timeout := l.config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := "https://api.anthropic.com"
	apiKey := ""
	if pc, ok := l.providers[l.config.Provider]; ok {
		if pc.Endpoint != "" {
			endpoint = pc.Endpoint
		}
		apiKey = os.Getenv(pc.APIKeyEnv)
	}

	model := l.config.Model
	if model == "" {
		if pc, ok := l.providers[l.config.Provider]; ok && pc.Model != "" {
			model = pc.Model
		} else {
			model = "claude-sonnet-4-20250514"
		}
	}

	body := map[string]any{
		"model":      model,
		"max_tokens": 1024,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
	}
	bodyBytes, _ := json.Marshal(body)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return l.fallbackDecision("failed to create request: " + err.Error()), nil
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	if apiKey != "" {
		httpReq.Header.Set("x-api-key", apiKey)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return l.fallbackDecision("anthropic request failed: " + err.Error()), nil
	}
	defer resp.Body.Close()

	respBody, err := readLimitedLLMResponse(resp.Body)
	if err != nil {
		return l.fallbackDecision("failed to read anthropic response: " + err.Error()), nil
	}
	if resp.StatusCode != http.StatusOK {
		return l.fallbackDecision(fmt.Sprintf("anthropic returned status %d: %s", resp.StatusCode, truncateForAudit(string(respBody)))), nil
	}

	var anthropicResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &anthropicResp); err != nil {
		return l.fallbackDecision("failed to parse anthropic response: " + err.Error()), nil
	}

	if len(anthropicResp.Content) == 0 {
		return l.fallbackDecision("empty response from anthropic"), nil
	}

	return extractDecisionFromText(anthropicResp.Content[0].Text)
}

// evaluateOpenAI calls the OpenAI Chat Completions API (also works for Bedrock).
func (l *LLMEvaluator) evaluateOpenAI(ctx context.Context, prompt string) (*PolicyDecision, error) {
	timeout := l.config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := "https://api.openai.com"
	apiKey := ""
	if pc, ok := l.providers[l.config.Provider]; ok {
		if pc.Endpoint != "" {
			endpoint = pc.Endpoint
		}
		apiKey = os.Getenv(pc.APIKeyEnv)
	}

	model := l.config.Model
	if model == "" {
		if pc, ok := l.providers[l.config.Provider]; ok && pc.Model != "" {
			model = pc.Model
		} else {
			model = "gpt-4o"
		}
	}

	body := map[string]any{
		"model":      model,
		"max_tokens": 1024,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
	}
	bodyBytes, _ := json.Marshal(body)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return l.fallbackDecision("failed to create request: " + err.Error()), nil
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return l.fallbackDecision("openai request failed: " + err.Error()), nil
	}
	defer resp.Body.Close()

	respBody, err := readLimitedLLMResponse(resp.Body)
	if err != nil {
		return l.fallbackDecision("failed to read openai response: " + err.Error()), nil
	}
	if resp.StatusCode != http.StatusOK {
		return l.fallbackDecision(fmt.Sprintf("openai returned status %d: %s", resp.StatusCode, truncateForAudit(string(respBody)))), nil
	}

	var openaiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &openaiResp); err != nil {
		return l.fallbackDecision("failed to parse openai response: " + err.Error()), nil
	}

	if len(openaiResp.Choices) == 0 {
		return l.fallbackDecision("empty response from openai"), nil
	}

	return extractDecisionFromText(openaiResp.Choices[0].Message.Content)
}

// extractDecisionFromText looks for a JSON object with "action" and "reason" in the text.
func extractDecisionFromText(text string) (*PolicyDecision, error) {
	// Try to find a JSON object in the text.
	start := strings.Index(text, "{")
	if start == -1 {
		return nil, fmt.Errorf("no JSON object found in response")
	}

	// Find the matching closing brace.
	depth := 0
	end := -1
	for i := start; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i + 1
				break
			}
		}
		if end != -1 {
			break
		}
	}

	if end == -1 {
		return nil, fmt.Errorf("no complete JSON object found in response")
	}

	var decision PolicyDecision
	if err := json.Unmarshal([]byte(text[start:end]), &decision); err != nil {
		return nil, fmt.Errorf("failed to parse decision JSON: %w", err)
	}

	if decision.Action == "" {
		return nil, fmt.Errorf("decision missing 'action' field")
	}

	return &decision, nil
}

// fallbackDecision returns a PolicyDecision using the configured fallback action.
func (l *LLMEvaluator) fallbackDecision(reason string) *PolicyDecision {
	return &PolicyDecision{
		Action: l.config.Fallback,
		Reason: "llm fallback: " + reason,
	}
}
