package slack

// Terminal-auth error classifier per research R10.
//
// Slack signals revocation via a small set of well-known error codes in
// the response body's `error` field (Slack always returns HTTP 200 even
// on "logical" auth failures — the body's `ok: false` and `error: ...`
// fields are authoritative).
//
// On a hit, the connector calls connections.Service.SetStatus(id,
// "reauth_required") so subsequent calls short-circuit at GetConnector
// (mapped to HTTP 403 by the API and to IsError by MCP — both
// translations covered in T015 / T017).
//
// The classifier is deliberately conservative: false positives flip
// status unnecessarily (correctable), false negatives leave a stale
// credential `active` until the next call.

// Slack response body shape for "logical" errors (HTTP 200, ok=false).
// Only the fields we care about — full envelope is documented at
// https://docs.slack.dev/reference/methods.
type errorEnvelope struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// terminalAuthErrors are the Slack error codes that indicate the bot
// token is no longer valid: revoked, scoped to a deleted user/team,
// or never properly authenticated.
//
// See https://docs.slack.dev/authentication/tokens — these codes are
// stable across API versions and apply to every Web API method.
var terminalAuthErrors = map[string]bool{
	"invalid_auth":     true, // token is bad or malformed
	"token_revoked":    true, // operator uninstalled the app
	"token_expired":    true, // rotation pair expired (granular scopes only)
	"account_inactive": true, // workspace owner deactivated the team
	"not_authed":       true, // no token presented
	"missing_auth":     true, // synonym used by some endpoints
	"team_added_to_org": false, // workspace migrated; not a terminal-auth — keep transient
}

// isTerminalAuthError reports whether the Slack response body indicates
// the credential is no longer usable. statusCode is included for the
// rare HTTP-401 path Slack uses on token-rotation refresh failures
// (granular scopes). Other 4xx/5xx are treated as transient.
func isTerminalAuthError(statusCode int, body errorEnvelope) bool {
	if statusCode == 401 {
		return true
	}
	if body.OK {
		return false
	}
	return terminalAuthErrors[body.Error]
}
