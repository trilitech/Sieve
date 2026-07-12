package notion

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
)

// Config is the persisted, decrypted connection config for a Notion
// connection.
//
// Notion authenticates with an internal integration token (Authorization:
// Bearer <token>) plus the required Notion-Version header — see client.go.
// v1 supports internal integration tokens only; public-integration OAuth is a
// deliberate omission (the cleanest add path is an auth_kind field selecting
// the token exchange, mirroring the slack connector).
//
// BaseURL defaults to https://api.notion.com and can be overridden to point at
// a test endpoint (requires an outbound_allowlist CIDR for a private address).
type Config struct {
	APIKey  string `json:"api_key"`
	BaseURL string `json:"base_url,omitempty"`
}

const defaultBaseURL = "https://api.notion.com"

// parseConfig decodes the connection config the connections.Service hands the
// factory. The map originates from JSON (encrypted at rest, decrypted on
// read), so we re-marshal/unmarshal to coerce types cleanly — matching the
// gitlab/linear connectors.
//
// Reserved runtime keys (e.g. the injected _on_token_refresh callbacks) are
// dropped first: they hold func values json.Marshal cannot encode, and this
// connector never uses them. See connector.ConfigWithoutReservedKeys.
func parseConfig(raw map[string]any) (*Config, error) {
	if raw == nil {
		return nil, errors.New("notion: empty config")
	}
	buf, err := json.Marshal(connector.ConfigWithoutReservedKeys(raw))
	if err != nil {
		return nil, fmt.Errorf("notion: re-marshal config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(buf, &c); err != nil {
		return nil, fmt.Errorf("notion: decode config: %w", err)
	}

	// Trim before validating: pasted tokens commonly carry a trailing newline
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
		return errors.New("notion: api_key required")
	}
	if c.BaseURL == "" {
		c.BaseURL = defaultBaseURL
	}
	if !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		return fmt.Errorf("notion: base_url must start with http:// or https:// (got %q)", c.BaseURL)
	}
	return nil
}
