package github

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Credential kinds.
const (
	KindFPAT            = "fpat"
	KindAppInstallation = "app_installation"
)

// Scope types.
const (
	ScopeUser = "user"
	ScopeOrg  = "org"
)

// Config is the persisted, decrypted connection config for a GitHub connection.
// A single connection can hold multiple credentials, each scoped to a user or
// an org. The connector picks the credential that covers the owner of each
// request; if no specific scope matches and DefaultIndex is set, that
// credential is used as fallback (for owner-less endpoints like /user,
// /search/*, /graphql, /notifications).
type Config struct {
	Credentials  []Credential `json:"credentials"`
	DefaultIndex *int         `json:"default_credential_index,omitempty"`

	// CrossForkPRAllowlist names GitHub user logins (case-insensitive) whose
	// forks the connector accepts as cross-fork PR heads via the curated
	// github_create_pr op. Default is empty == deny all cross-fork PRs.
	// Wildcards are NOT honoured; an entry of "*" is treated as a literal
	// user named "*". The escape-hatch github_request op is unaffected
	// regardless of allow-list state.
	CrossForkPRAllowlist []string `json:"cross_fork_pr_allowlist,omitempty"`
}

// Credential is a single PAT or App installation entry within a Config.
type Credential struct {
	Kind  string `json:"kind"`
	Scope Scope  `json:"scope"`

	// Fine-grained PAT (Kind == KindFPAT).
	Token string `json:"token,omitempty"`

	// GitHub App installation (Kind == KindAppInstallation).
	AppID          int64  `json:"app_id,omitempty"`
	InstallationID int64  `json:"installation_id,omitempty"`
	PrivateKeyPEM  string `json:"private_key_pem,omitempty"`
}

// Scope identifies which user or org a credential covers.
type Scope struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

func (s Scope) matches(owner string) bool {
	return strings.EqualFold(s.Name, owner)
}

func (s Scope) String() string {
	return s.Type + ":" + s.Name
}

// parseConfig decodes the connection config that connections.Service hands the
// factory. The map originates from JSON (encrypted at rest, decrypted on read),
// so we re-marshal/unmarshal to coerce types cleanly.
func parseConfig(raw map[string]any) (*Config, error) {
	if raw == nil {
		return nil, errors.New("github: empty config")
	}
	buf, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("github: re-marshal config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(buf, &c); err != nil {
		return nil, fmt.Errorf("github: decode config: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if len(c.Credentials) == 0 {
		return errors.New("github: at least one credential required")
	}
	for i, cred := range c.Credentials {
		if err := cred.validate(); err != nil {
			return fmt.Errorf("github: credential %d: %w", i, err)
		}
	}
	if c.DefaultIndex != nil {
		if *c.DefaultIndex < 0 || *c.DefaultIndex >= len(c.Credentials) {
			return fmt.Errorf("github: default_credential_index %d out of range", *c.DefaultIndex)
		}
	}
	for i, u := range c.CrossForkPRAllowlist {
		if strings.TrimSpace(u) == "" {
			return fmt.Errorf("github: cross_fork_pr_allowlist[%d] is empty", i)
		}
	}
	return nil
}

// allowsCrossForkUser reports whether the given GitHub user appears in
// the connection's cross-fork allow-list. Comparison is case-insensitive
// after trimming whitespace on both sides; an empty list (or empty user)
// returns false, which is the default-deny semantics specified by W1.4.
func (c *Config) allowsCrossForkUser(user string) bool {
	needle := strings.ToLower(strings.TrimSpace(user))
	if needle == "" {
		return false
	}
	for _, u := range c.CrossForkPRAllowlist {
		if strings.ToLower(strings.TrimSpace(u)) == needle {
			return true
		}
	}
	return false
}

func (c Credential) validate() error {
	switch c.Scope.Type {
	case ScopeUser, ScopeOrg:
	default:
		return fmt.Errorf("scope.type must be %q or %q, got %q", ScopeUser, ScopeOrg, c.Scope.Type)
	}
	if c.Scope.Name == "" {
		return errors.New("scope.name required")
	}
	switch c.Kind {
	case KindFPAT:
		if c.Token == "" {
			return errors.New("token required for fpat")
		}
	case KindAppInstallation:
		if c.AppID == 0 || c.InstallationID == 0 || c.PrivateKeyPEM == "" {
			return errors.New("app_id, installation_id, private_key_pem required for app_installation")
		}
	default:
		return fmt.Errorf("unknown credential kind %q", c.Kind)
	}
	return nil
}
