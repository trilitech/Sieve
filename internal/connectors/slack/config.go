// Package slack implements the Slack connector for Sieve.
//
// Authentication: two peer methods.
//   - "oauth": classic non-rotating Slack bot tokens obtained via the
//     OAuth v2 install flow (classic scopes only for v1; granular-scope
//     token rotation deferred).
//   - "token": admin pastes a pre-existing bot token (xoxb-...) from a
//     Slack app they own.
//
// Curated operations cover the most common AI-agent workflows
// (channels, users, history, threads, search, post). See ops.go for
// the dispatch table.
package slack

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// Auth-kind discriminator. Mirrors the auth_kind field on Linear/Jira
// /Asana configs so the four connectors share a vocabulary; agents and
// docs talk about "auth_kind: oauth | token | user_oauth" everywhere.
const (
	KindOAuth = "oauth"
	KindToken = "token"
	// KindUserOAuth is a user-token install: the OAuth flow requested
	// `user_scope` and Sieve stored the authorizing operator's user
	// token (xoxp-… / xoxe.xoxp-…) from authed_user. Unlike the bot
	// kinds, this unlocks search.messages and acts with the operator's
	// own Slack access. A distinct kind (rather than a flag on KindOAuth)
	// keeps validate()/accessToken()/opSearchMessages readable — every
	// branch that cares about "is this a user install?" tests one value.
	KindUserOAuth = "user_oauth"
)

// Config is the persisted, decrypted connection config for a Slack
// connection. All credential fields are encrypted at rest as part of
// the connections row's `config_ciphertext` blob — never plaintext
// columns.
type Config struct {
	AuthKind  string   `json:"auth_kind"`           // KindOAuth | KindToken | KindUserOAuth
	TeamID    string   `json:"team_id"`             // Slack workspace ID, e.g. "T012ABCDEF"
	TeamName  string   `json:"team_name,omitempty"` // Display-only
	BotUserID string   `json:"bot_user_id,omitempty"`
	Scopes    []string `json:"scopes,omitempty"` // Granted scope set

	// ActingUserID is the authorizing operator's Slack user ID (authed_user.id),
	// populated for KindUserOAuth installs. Non-secret metadata used for UI
	// labeling and audit attribution — safe to surface without the keyring.
	ActingUserID string `json:"acting_user_id,omitempty"`

	// AuthKind == KindOAuth | KindUserOAuth: populated by the OAuth callback
	// after oauth.v2.access. Classic bot tokens don't expire/rotate; user
	// tokens rotate when the Slack app enables Token Rotation, in which case
	// this map also carries `refresh_token` and `expiry` (RFC3339) and the
	// connector renews via a refreshing token source.
	OAuthToken map[string]any `json:"oauth_token,omitempty"`

	// AuthKind == KindToken: pasted directly by the admin.
	BotToken string `json:"bot_token,omitempty"`
}

// parseConfig decodes the raw config map (as stored in the encrypted
// blob) into a typed Config. Returns an error on shape violations so
// callers don't silently mis-key.
func parseConfig(raw map[string]any) (*Config, error) {
	if raw == nil {
		return nil, fmt.Errorf("slack: nil config")
	}
	c := &Config{}
	c.AuthKind, _ = raw["auth_kind"].(string)
	c.TeamID, _ = raw["team_id"].(string)
	c.TeamName, _ = raw["team_name"].(string)
	c.BotUserID, _ = raw["bot_user_id"].(string)
	c.ActingUserID, _ = raw["acting_user_id"].(string)
	c.BotToken, _ = raw["bot_token"].(string)
	if scopes, ok := raw["scopes"].([]any); ok {
		for _, s := range scopes {
			if str, ok := s.(string); ok {
				c.Scopes = append(c.Scopes, str)
			}
		}
	}
	if t, ok := raw["oauth_token"].(map[string]any); ok {
		c.OAuthToken = t
	}
	return c, nil
}

// validate enforces the auth-kind specific invariants. Called by the
// factory before we hand the connector out to callers — a misconfigured
// connection should fail loudly here, not on the first agent operation.
func (c *Config) validate() error {
	switch c.AuthKind {
	case KindOAuth:
		if c.OAuthToken == nil {
			return fmt.Errorf("slack: oauth config missing oauth_token map")
		}
		access, _ := c.OAuthToken["access_token"].(string)
		if access == "" {
			return fmt.Errorf("slack: oauth_token.access_token is empty")
		}
		if strings.HasPrefix(access, "xoxe.xoxp-") || strings.HasPrefix(access, "xoxp-") {
			// User-token prefixes in a bot install: the operator picked the
			// wrong kind. Fail loudly so a mismatched credential never lands.
			return fmt.Errorf("slack: oauth (bot) install got a user token (want xoxb- or xoxe.); use auth_kind %q", KindUserOAuth)
		}
		if !strings.HasPrefix(access, "xoxb-") && !strings.HasPrefix(access, "xoxe.") {
			// xoxb- = classic bot token; xoxe.* = enterprise bot. Reject
			// xoxa- (legacy) — those need different call paths.
			return fmt.Errorf("slack: unsupported access_token prefix (want xoxb- or xoxe.)")
		}
	case KindUserOAuth:
		if c.OAuthToken == nil {
			return fmt.Errorf("slack: user_oauth config missing oauth_token map")
		}
		access, _ := c.OAuthToken["access_token"].(string)
		if access == "" {
			return fmt.Errorf("slack: oauth_token.access_token is empty")
		}
		// xoxe.xoxp- = rotating user access token; xoxp- = non-rotating user
		// token. Reject bot prefixes — a mismatched paste/install must fail
		// here, not on the first agent call (FR-005).
		if !strings.HasPrefix(access, "xoxe.xoxp-") && !strings.HasPrefix(access, "xoxp-") {
			return fmt.Errorf("slack: user_oauth expects a user token (want xoxp- or xoxe.xoxp-)")
		}
	case KindToken:
		if c.BotToken == "" {
			return fmt.Errorf("slack: token config missing bot_token")
		}
		if !strings.HasPrefix(c.BotToken, "xoxb-") {
			return fmt.Errorf("slack: bot_token must start with xoxb- (Slack bot token format)")
		}
	default:
		return fmt.Errorf("slack: unknown auth_kind %q (want %q or %q)", c.AuthKind, KindOAuth, KindToken)
	}
	return nil
}

// accessToken returns the bearer token to send on Slack API calls,
// regardless of which auth_kind was used. Centralised so the HTTP
// client doesn't have to branch.
func (c *Config) accessToken() string {
	if c.AuthKind == KindToken {
		return c.BotToken
	}
	// KindOAuth and KindUserOAuth both stash the bearer in oauth_token.
	if c.OAuthToken != nil {
		if s, ok := c.OAuthToken["access_token"].(string); ok {
			return s
		}
	}
	return ""
}

// refreshToken returns the stored OAuth refresh token, if any. Present only
// for KindUserOAuth installs against a Slack app with Token Rotation enabled.
func (c *Config) refreshToken() string {
	if c.OAuthToken == nil {
		return ""
	}
	s, _ := c.OAuthToken["refresh_token"].(string)
	return s
}

// oauth2Token reconstructs the *oauth2.Token from the stored oauth_token map
// so the refreshing token source can track access/refresh/expiry. A zero
// expiry means "never expires" (non-rotating token).
func (c *Config) oauth2Token() *oauth2.Token {
	tok := &oauth2.Token{AccessToken: c.accessToken(), RefreshToken: c.refreshToken()}
	if c.OAuthToken != nil {
		if tt, ok := c.OAuthToken["token_type"].(string); ok {
			tok.TokenType = tt
		}
		if exp, ok := c.OAuthToken["expiry"].(string); ok && exp != "" {
			if t, err := time.Parse(time.RFC3339, exp); err == nil {
				tok.Expiry = t
			}
		}
	}
	return tok
}
