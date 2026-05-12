package web

import "testing"

func TestInferPolicyScope(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]any
		want string
	}{
		{
			name: "method match → http_proxy",
			cfg: map[string]any{
				"rules": []any{
					map[string]any{"match": map[string]any{"method": []any{"GET"}}, "action": "allow"},
				},
			},
			want: "http_proxy",
		},
		{
			name: "path match → http_proxy",
			cfg: map[string]any{
				"rules": []any{
					map[string]any{"match": map[string]any{"path": "/data/2.5/*"}, "action": "allow"},
				},
			},
			want: "http_proxy",
		},
		{
			name: "proxy_request operation → http_proxy",
			cfg: map[string]any{
				"rules": []any{
					map[string]any{"match": map[string]any{"operations": []any{"proxy_request"}}, "action": "allow"},
				},
			},
			want: "http_proxy",
		},
		{
			name: "providers match → llm",
			cfg: map[string]any{
				"rules": []any{
					map[string]any{"match": map[string]any{"providers": []any{"anthropic"}}, "action": "allow"},
				},
			},
			want: "llm",
		},
		{
			name: "max_tokens match → llm",
			cfg: map[string]any{
				"rules": []any{
					map[string]any{"match": map[string]any{"max_tokens": float64(8000)}, "action": "allow"},
				},
			},
			want: "llm",
		},
		{
			name: "gmail-style ops yields no inference",
			cfg: map[string]any{
				"rules": []any{
					map[string]any{"match": map[string]any{"operations": []any{"list_emails", "read_email"}}, "action": "allow"},
				},
			},
			want: "",
		},
		{
			name: "no rules yields empty",
			cfg:  map[string]any{},
			want: "",
		},
		{
			name: "first matching rule wins",
			cfg: map[string]any{
				"rules": []any{
					map[string]any{"match": map[string]any{"operations": []any{"list_emails"}}, "action": "allow"},
					map[string]any{"match": map[string]any{"method": []any{"GET"}}, "action": "allow"},
				},
			},
			want: "http_proxy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inferPolicyScope(tc.cfg)
			if got != tc.want {
				t.Errorf("inferPolicyScope = %q, want %q", got, tc.want)
			}
		})
	}
}
