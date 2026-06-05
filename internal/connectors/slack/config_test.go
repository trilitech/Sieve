package slack

import "testing"

func TestParseConfig_AllFields(t *testing.T) {
	raw := map[string]any{
		"auth_kind":   "oauth",
		"team_id":     "T012ABCDEF",
		"team_name":   "Acme",
		"bot_user_id": "U0KRQLJ9H",
		"scopes":      []any{"channels:read", "chat:write"},
		"oauth_token": map[string]any{
			"access_token": "xoxb-test-1234",
			"token_type":   "bot",
		},
	}
	c, err := parseConfig(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.AuthKind != "oauth" || c.TeamID != "T012ABCDEF" || c.TeamName != "Acme" || c.BotUserID != "U0KRQLJ9H" {
		t.Fatalf("decoded fields wrong: %+v", c)
	}
	if len(c.Scopes) != 2 || c.Scopes[0] != "channels:read" || c.Scopes[1] != "chat:write" {
		t.Fatalf("scopes wrong: %v", c.Scopes)
	}
	if c.OAuthToken["access_token"] != "xoxb-test-1234" {
		t.Fatalf("oauth_token not preserved: %v", c.OAuthToken)
	}
}

func TestParseConfig_NilRejected(t *testing.T) {
	if _, err := parseConfig(nil); err == nil {
		t.Fatal("expected error on nil config")
	}
}

func TestValidate_OAuth(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			"happy path xoxb",
			Config{
				AuthKind:   KindOAuth,
				OAuthToken: map[string]any{"access_token": "xoxb-T-1234-5678"},
			},
			false,
		},
		{
			"happy path enterprise xoxe",
			Config{
				AuthKind:   KindOAuth,
				OAuthToken: map[string]any{"access_token": "xoxe.xoxb-1-..."},
			},
			false,
		},
		{
			"missing oauth_token map",
			Config{AuthKind: KindOAuth},
			true,
		},
		{
			"empty access_token",
			Config{
				AuthKind:   KindOAuth,
				OAuthToken: map[string]any{"access_token": ""},
			},
			true,
		},
		{
			"unsupported xoxp prefix (user token)",
			Config{
				AuthKind:   KindOAuth,
				OAuthToken: map[string]any{"access_token": "xoxp-T-1234-5678"},
			},
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate(%+v) err=%v, wantErr=%v", tc.cfg, err, tc.wantErr)
			}
		})
	}
}

func TestValidate_Token(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"happy path xoxb", Config{AuthKind: KindToken, BotToken: "xoxb-T-1234-5678"}, false},
		{"missing bot_token", Config{AuthKind: KindToken}, true},
		{"non-bot prefix rejected", Config{AuthKind: KindToken, BotToken: "xoxp-T-1234"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate(%+v) err=%v, wantErr=%v", tc.cfg, err, tc.wantErr)
			}
		})
	}
}

func TestValidate_UnknownAuthKind(t *testing.T) {
	c := Config{AuthKind: "totp"}
	if err := c.validate(); err == nil {
		t.Fatal("expected error on unknown auth_kind")
	}
}

func TestAccessToken(t *testing.T) {
	oauth := Config{
		AuthKind:   KindOAuth,
		OAuthToken: map[string]any{"access_token": "xoxb-from-oauth"},
	}
	if oauth.accessToken() != "xoxb-from-oauth" {
		t.Fatalf("oauth accessToken: %q", oauth.accessToken())
	}

	token := Config{AuthKind: KindToken, BotToken: "xoxb-from-paste"}
	if token.accessToken() != "xoxb-from-paste" {
		t.Fatalf("token accessToken: %q", token.accessToken())
	}

	empty := Config{AuthKind: KindOAuth}
	if empty.accessToken() != "" {
		t.Fatalf("empty config accessToken should be empty, got %q", empty.accessToken())
	}
}
