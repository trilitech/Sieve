package slack

import "testing"

// TestIsTerminalAuthError covers the classifier table. False positives
// flip status to reauth_required unnecessarily, so a "transient" code
// must NOT be classified as terminal. False negatives leak a stale
// credential past one more call — measurable but bounded.
func TestIsTerminalAuthError(t *testing.T) {
	cases := []struct {
		name string
		code int
		body errorEnvelope
		want bool
	}{
		// Terminal codes — connection is done.
		{"invalid_auth", 200, errorEnvelope{OK: false, Error: "invalid_auth"}, true},
		{"token_revoked", 200, errorEnvelope{OK: false, Error: "token_revoked"}, true},
		{"token_expired", 200, errorEnvelope{OK: false, Error: "token_expired"}, true},
		{"account_inactive", 200, errorEnvelope{OK: false, Error: "account_inactive"}, true},
		{"not_authed", 200, errorEnvelope{OK: false, Error: "not_authed"}, true},
		{"missing_auth", 200, errorEnvelope{OK: false, Error: "missing_auth"}, true},
		{"http 401", 401, errorEnvelope{}, true},

		// Transient codes — retry, do not flip status.
		{"rate_limited", 429, errorEnvelope{OK: false, Error: "rate_limited"}, false},
		{"server_error", 500, errorEnvelope{OK: false, Error: "internal_error"}, false},
		{"bad_request", 400, errorEnvelope{OK: false, Error: "bad_request"}, false},
		{"http 503", 503, errorEnvelope{OK: false, Error: "fatal_error"}, false},

		// Successful response — no terminal-auth signal.
		{"ok", 200, errorEnvelope{OK: true}, false},

		// Unknown logical error code — treat as transient (false negative
		// is preferred over false positive for unknowns).
		{"unknown_code", 200, errorEnvelope{OK: false, Error: "weird_new_code"}, false},

		// Workspace migration — Slack docs explicitly mark this as
		// recoverable, not terminal.
		{"team_added_to_org", 200, errorEnvelope{OK: false, Error: "team_added_to_org"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isTerminalAuthError(tc.code, tc.body)
			if got != tc.want {
				t.Fatalf("isTerminalAuthError(%d, %+v) = %v, want %v", tc.code, tc.body, got, tc.want)
			}
		})
	}
}
