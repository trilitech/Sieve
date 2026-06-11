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
	// Trim leading/trailing whitespace consistent with base_url and
	// anthropic_version below. Pasted keys frequently arrive with a
	// trailing newline or surrounding spaces; without the trim the
	// prefix check would reject the (otherwise-valid) key and an
	// untrimmed value would fail auth upstream with a confusing 401.
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, errors.New("anthropic: api_key is required")
	}
	if !strings.HasPrefix(apiKey, "sk-ant-") {
		// Soft sanity check. Anthropic keys carry this prefix; rejecting
		// non-conforming values catches the common operator mistake of
		// pasting an OpenAI key into the Anthropic form.
		//
		// Deliberately do NOT echo any of the rejected key in the error
		// message — even a 7-character prefix would land in logs and
		// audit rows. The operator sees the value in the form field they
		// just typed; we don't need to reflect it.
		return nil, errors.New("anthropic: api_key must start with \"sk-ant-\"")
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
