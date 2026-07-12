package gitlab

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
)

// Config is the persisted, decrypted connection config for a GitLab
// connection.
//
// Unlike the github connector — which holds multiple PAT/App credentials
// keyed by user/org scope — a single GitLab connection holds exactly one
// PAT. A GitLab PAT authenticates the API as the token owner without
// per-namespace scoping at the auth layer, so a multi-cred shape would
// be premature complexity for v1. Operators who need separate trust
// boundaries per namespace add separate connections.
//
// OAuth tokens are NOT supported in v1; only PATs sent via the
// PRIVATE-TOKEN header. See gitlab.go's package comment for the
// rationale + the cleanest add path if OAuth support is ever needed.
//
// BaseURL defaults to https://gitlab.com and can be overridden to point
// at a self-hosted GitLab instance.
type Config struct {
	Token   string `json:"token"`
	BaseURL string `json:"base_url,omitempty"`
}

const defaultBaseURL = "https://gitlab.com"

// parseConfig decodes the connection config that connections.Service
// hands the factory. The map originates from JSON (encrypted at rest,
// decrypted on read), so we re-marshal/unmarshal to coerce types
// cleanly — matching the github connector's pattern.
//
// Reserved runtime keys (e.g. the injected _on_token_refresh callbacks) are
// dropped first: they hold func values that json.Marshal cannot encode, and
// this connector never uses them. See connector.ConfigWithoutReservedKeys.
func parseConfig(raw map[string]any) (*Config, error) {
	if raw == nil {
		return nil, errors.New("gitlab: empty config")
	}
	buf, err := json.Marshal(connector.ConfigWithoutReservedKeys(raw))
	if err != nil {
		return nil, fmt.Errorf("gitlab: re-marshal config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(buf, &c); err != nil {
		return nil, fmt.Errorf("gitlab: decode config: %w", err)
	}

	// Trim before validating: pasted tokens commonly carry a trailing
	// newline and URLs frequently have stray whitespace. Without
	// trimming, the token would be sent verbatim and fail upstream
	// auth with a confusing message.
	c.Token = strings.TrimSpace(c.Token)
	c.BaseURL = strings.TrimSpace(c.BaseURL)
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")

	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.Token == "" {
		return errors.New("gitlab: token required")
	}
	if c.BaseURL == "" {
		c.BaseURL = defaultBaseURL
	}
	if !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		return fmt.Errorf("gitlab: base_url must start with http:// or https:// (got %q)", c.BaseURL)
	}
	return nil
}
