package anthropic

import (
	"errors"
	"fmt"
	"strings"
)

// Config is the decoded shape of an Anthropic connection's config map.
// Constructed via parseConfig, which validates required fields and
// normalises optional ones to their defaults.
type Config struct {
	APIKey           string
	BaseURL          string
	AnthropicVersion string
}

// parseConfig validates the operator-supplied config map and returns
// a populated Config. It deliberately fails loud on missing or
// suspiciously-shaped fields rather than silently substituting defaults
// for required values — a misconfigured connection should be obvious
// at add-time, not at the first agent call.
func parseConfig(raw map[string]any) (*Config, error) {
	apiKey, _ := raw["api_key"].(string)
	if apiKey == "" {
		return nil, errors.New("anthropic: api_key is required")
	}
	if !strings.HasPrefix(apiKey, "sk-ant-") {
		// Soft sanity check. Anthropic keys carry this prefix; rejecting
		// non-conforming values catches the common operator mistake of
		// pasting an OpenAI key into the Anthropic form.
		return nil, fmt.Errorf("anthropic: api_key must start with %q (got prefix %q)",
			"sk-ant-", firstN(apiKey, 7))
	}

	baseURL, _ := raw["base_url"].(string)
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("anthropic: base_url must start with http:// or https:// (got %q)", baseURL)
	}

	version, _ := raw["anthropic_version"].(string)
	version = strings.TrimSpace(version)
	if version == "" {
		version = defaultAnthropicVersion
	}

	return &Config{
		APIKey:           apiKey,
		BaseURL:          baseURL,
		AnthropicVersion: version,
	}, nil
}

// firstN returns the first n bytes of a string, or the full string if
// shorter. Used only to produce informative error messages without
// leaking the rest of an API key.
func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
