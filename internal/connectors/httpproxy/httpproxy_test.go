package httpproxy

import "testing"

func TestFactory_AuthValueBearerAutoPrefix(t *testing.T) {
	cases := []struct {
		name       string
		authHeader string
		authValue  string
		wantValue  string
	}{
		{
			name:       "raw token + Authorization → prefix added",
			authHeader: "Authorization",
			authValue:  "pa-2TLWFkt8F5fUpacpDlUEgmoRnaPtOOcfqY6TwIfLXRu",
			wantValue:  "Bearer pa-2TLWFkt8F5fUpacpDlUEgmoRnaPtOOcfqY6TwIfLXRu",
		},
		{
			name:       "Bearer-prefixed value left untouched",
			authHeader: "Authorization",
			authValue:  "Bearer pa-existing",
			wantValue:  "Bearer pa-existing",
		},
		{
			name:       "Basic-prefixed value left untouched",
			authHeader: "Authorization",
			authValue:  "Basic dXNlcjpwYXNz",
			wantValue:  "Basic dXNlcjpwYXNz",
		},
		{
			name:       "non-Authorization header left untouched",
			authHeader: "x-api-key",
			authValue:  "sk-ant-api03-abc",
			wantValue:  "sk-ant-api03-abc",
		},
		{
			name:       "case-insensitive header match",
			authHeader: "AUTHORIZATION",
			authValue:  "ghp_xxx",
			wantValue:  "Bearer ghp_xxx",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c2, err := Factory(map[string]any{
				"target_url":  "https://api.example.com",
				"auth_header": c.authHeader,
				"auth_value":  c.authValue,
			})
			if err != nil {
				t.Fatal(err)
			}
			pc := c2.(*ProxyConnector)
			if pc.authValue != c.wantValue {
				t.Errorf("authValue = %q, want %q", pc.authValue, c.wantValue)
			}
		})
	}
}
