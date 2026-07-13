package asana

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
)

// Config is the persisted, decrypted connection config for an Asana connection.
//
// Asana authenticates with a Bearer token — a Personal Access Token (PAT) or an
// OAuth access token; both are used identically (Authorization: Bearer <token>)
// so the connector stores whichever in api_key. BaseURL defaults to
// https://app.asana.com and can be overridden for a test endpoint (requires an
// outbound_allowlist CIDR for a private address).
type Config struct {
	APIKey  string `json:"api_key"`
	BaseURL string `json:"base_url,omitempty"`
}

const defaultBaseURL = "https://app.asana.com"

// parseConfig decodes the connection config the connections.Service hands the
// factory. The map originates from JSON (encrypted at rest, decrypted on read),
// so we re-marshal/unmarshal to coerce types cleanly — matching the
// gitlab/linear/notion connectors.
//
// Reserved runtime keys (e.g. the injected _on_token_refresh callbacks) are
// dropped first: they hold func values json.Marshal cannot encode, and this
// connector never uses them. See connector.ConfigWithoutReservedKeys.
func parseConfig(raw map[string]any) (*Config, error) {
	if raw == nil {
		return nil, errors.New("asana: empty config")
	}
	buf, err := json.Marshal(connector.ConfigWithoutReservedKeys(raw))
	if err != nil {
		return nil, fmt.Errorf("asana: re-marshal config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(buf, &c); err != nil {
		return nil, fmt.Errorf("asana: decode config: %w", err)
	}

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
		return errors.New("asana: api_key required")
	}
	if c.BaseURL == "" {
		c.BaseURL = defaultBaseURL
	}
	if !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		return fmt.Errorf("asana: base_url must start with http:// or https:// (got %q)", c.BaseURL)
	}
	return nil
}
