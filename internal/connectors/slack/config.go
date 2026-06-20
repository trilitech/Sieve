// Package slack implements the Slack connector for Sieve.
// Authentication: three peer methods, split across two identities.
//
// Bot identity (acts as the Slack app's bot user, xoxb- token):
//   - "oauth": classic non-rotating Slack bot tokens obtained via the
//     OAuth v2 install flow (classic scopes only; granular-scope token
//     rotation deferred).
//   - "token": admin pastes a pre-existing bot token (xoxb-...) from a
//     Slack app they own.
//
// User identity (acts as the installing human, with that user's full
// permissions, xoxp- token):
//   - "user_token": obtained via the OAuth user-install flow (Slack
//     returns it under authed_user.access_token) or pasted directly.
//     Unlike a bot token it can read every channel/DM the user can see
//     and use search.messages, and posts under the user's name.
//
// Curated operations cover the most common AI-agent workflows
// (channels, users, history, threads, search, post). See ops.go for
// the dispatch table.
package slack

import (
	"fmt"
	"strings"
)

// Auth-kind discriminator. Mirrors the auth_kind field on Linear/Jira
// /Asana configs so the connectors share a vocabulary; agents and docs
// talk about "auth_kind: oauth | token | user_token" everywhere.
//
//   - KindOAuth / KindToken authenticate as the Slack *app's bot user*
//     (xoxb- token).
//   - KindUserToken authenticates as the *installing human user* (xoxp-
//     token). It carries that user's full permissions — every channel,
//     DM, and search index the person can reach — and acts as them. This
//     is the "act as a user, not a bot" path. The xoxp- token is obtained
//     either via the OAuth user-install flow (authed_user.access_token)
//     or pasted directly by the operator.
const (
	KindOAuth     = "oauth"
	KindToken     = "token"
	KindUserToken = "user_token"
)

// Config is the persisted, decrypted connection config for a Slack
// connection. All credential fields are encrypted at rest as part of
// the connections row's `config_ciphertext` blob — never plaintext
// columns.
type Config struct {
	AuthKind  string   `json:"auth_kind"`           // KindOAuth | KindToken
	TeamID    string   `json:"team_id"`             // Slack workspace ID, e.g. "T012ABCDEF"
	TeamName  string   `json:"team_name,omitempty"` // Display-only
	BotUserID string   `json:"bot_user_id,omitempty"`
	Scopes    []string `json:"scopes,omitempty"` // Granted scope set

	// AuthKind == KindOAuth: populated by the OAuth callback after
	// oauth.v2.access. Slack classic bot tokens don't expire and don't
	// have refresh_token.
	OAuthToken map[string]any `json:"oauth_token,omitempty"`

	// AuthKind == KindToken: pasted directly by the admin.
	BotToken string `json:"bot_token,omitempty"`

	// AuthKind == KindUserToken: the Slack user token (xoxp-...). Set
	// either by the OAuth user-install callback (copied out of
	// authed_user.access_token) or pasted directly by the operator. Like
	// the classic bot token it is non-rotating, so there is no refresh
	// wiring. This is the credential that makes the connector act as the
	// human rather than the app's bot.
	UserToken string `json:"user_token,omitempty"`
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
	c.BotToken, _ = raw["bot_token"].(string)
	c.UserToken, _ = raw["user_token"].(string)
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
		if !strings.HasPrefix(access, "xoxb-") && !strings.HasPrefix(access, "xoxe.") {
			// xoxb- = classic bot token; xoxe.* = enterprise bot. Reject
			// xoxp- (user) and xoxa- (legacy) — those need different
			// scopes and call paths we don't implement in v1.
			return fmt.Errorf("slack: unsupported access_token prefix (want xoxb- or xoxe.)")
		}
	case KindToken:
		if c.BotToken == "" {
			return fmt.Errorf("slack: token config missing bot_token")
		}
		if !strings.HasPrefix(c.BotToken, "xoxb-") {
			return fmt.Errorf("slack: bot_token must start with xoxb- (Slack bot token format)")
		}
	case KindUserToken:
		if c.UserToken == "" {
			return fmt.Errorf("slack: user_token config missing user_token")
		}
		// xoxp- = classic user token; xoxe.* = enterprise user token
		// (Slack prefixes Enterprise Grid tokens xoxe.xoxp-...). Reject
		// xoxb- here so an operator can't silently downgrade a "user"
		// connection to a bot identity by pasting the wrong token.
		if !strings.HasPrefix(c.UserToken, "xoxp-") && !strings.HasPrefix(c.UserToken, "xoxe.") {
			return fmt.Errorf("slack: user_token must start with xoxp- (Slack user token format)")
		}
	default:
		return fmt.Errorf("slack: unknown auth_kind %q (want %q, %q, or %q)", c.AuthKind, KindOAuth, KindToken, KindUserToken)
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
	if c.AuthKind == KindUserToken {
		return c.UserToken
	}
	if c.OAuthToken != nil {
		if s, ok := c.OAuthToken["access_token"].(string); ok {
			return s
		}
	}
	return ""
}
