package slack

import (
	"context"
	"fmt"
	"net/url"
)

// validate calls Slack's auth.test method to confirm the token works
// against the live workspace. Used at connection-creation time (the
// admin pastes a token; we refuse to persist until auth.test passes)
// and as the connector.Connector.Validate implementation for periodic
// health checks.
//
// On success the connector promotes the workspace metadata Slack
// returns into the Config (TeamID, BotUserID) so subsequent calls can
// reference them without an extra round trip.
func (c *Connector) validate(ctx context.Context) error {
	resp, err := c.client.get(ctx, "auth.test", url.Values{})
	if err != nil {
		return fmt.Errorf("slack auth.test: %w", err)
	}
	if id, ok := resp["team_id"].(string); ok && id != "" {
		c.cfg.TeamID = id
	}
	if name, ok := resp["team"].(string); ok && name != "" {
		c.cfg.TeamName = name
	}
	if botID, ok := resp["user_id"].(string); ok && botID != "" {
		c.cfg.BotUserID = botID
		// For a user-token install, auth.test's user_id is the authorizing
		// operator (the acting identity), not a bot user. Record it for UI
		// labeling and audit attribution.
		if c.cfg.AuthKind == KindUserOAuth {
			c.cfg.ActingUserID = botID
		}
	}
	return nil
}
