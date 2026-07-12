package linear

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
)

// Config is the persisted, decrypted connection config for a Linear
// connection.
//
// Linear's API is GraphQL-only at https://api.linear.app/graphql. Auth is
// either a Personal API Key (Authorization: <key>, no "Bearer ") or an
// OAuth access token (Authorization: Bearer <token>). v1 supports only
// Personal API Keys — the simpler shape. OAuth can be added later by
// introducing a `token_type` field that selects between the two header
// formats in client.go.
//
// BaseURL defaults to https://api.linear.app and can be overridden for
// tests; production self-hosting is not a Linear feature.
type Config struct {
	APIKey  string `json:"api_key"`
	BaseURL string `json:"base_url,omitempty"`
}

const defaultBaseURL = "https://api.linear.app"

// parseConfig decodes the connection config that connections.Service
// hands the factory. The map originates from JSON (encrypted at rest,
// decrypted on read), so we re-marshal/unmarshal to coerce types
// cleanly — matching the gitlab connector's pattern.
func parseConfig(raw map[string]any) (*Config, error) {
	if raw == nil {
		return nil, errors.New("linear: empty config")
	}
	// Drop reserved runtime keys (injected _on_token_refresh callbacks hold
	// func values json.Marshal can't encode). See connector.ConfigWithoutReservedKeys.
	buf, err := json.Marshal(connector.ConfigWithoutReservedKeys(raw))
	if err != nil {
		return nil, fmt.Errorf("linear: re-marshal config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(buf, &c); err != nil {
		return nil, fmt.Errorf("linear: decode config: %w", err)
	}

	// Trim before validating: pasted keys commonly carry trailing newline
	// and URLs frequently have stray whitespace.
	c.APIKey = strings.TrimSpace(c.APIKey)
	c.BaseURL = strings.TrimSpace(c.BaseURL)
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")

	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.APIKey == "" {
		return errors.New("linear: api_key required")
	}
	if c.BaseURL == "" {
		c.BaseURL = defaultBaseURL
	}
	if !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		return fmt.Errorf("linear: base_url must start with http:// or https:// (got %q)", c.BaseURL)
	}
	return nil
}
