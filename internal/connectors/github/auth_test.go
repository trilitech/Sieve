package github

import (
	"errors"
	"testing"
)

func TestExtractOwner(t *testing.T) {
	cases := []struct {
		path  string
		owner string
	}{
		{"/repos/murbard/Sieve/issues", "murbard"},
		{"/repos/trilitech/Sieve/pulls/12", "trilitech"},
		{"/orgs/trilitech/members", "trilitech"},
		{"/users/murbard/repos", "murbard"},
		{"/user", ""},
		{"/user/repos", ""},
		{"/search/code", ""},
		{"/graphql", ""},
		{"/notifications", ""},
		{"/gists/abc", ""},
		{"", ""},
		{"no-leading-slash", ""},
		{"/repos", ""},
	}
	for _, c := range cases {
		got := extractOwner(c.path)
		if got != c.owner {
			t.Errorf("extractOwner(%q) = %q, want %q", c.path, got, c.owner)
		}
	}
}

func TestPickCredential(t *testing.T) {
	defaultIdx := 0
	cfg := &Config{
		Credentials: []Credential{
			{Kind: KindFPAT, Scope: Scope{Type: ScopeUser, Name: "murbard"}, Token: "u-tok"},
			{Kind: KindFPAT, Scope: Scope{Type: ScopeOrg, Name: "trilitech"}, Token: "o-tok"},
		},
		DefaultIndex: &defaultIdx,
	}

	t.Run("matches user", func(t *testing.T) {
		got, err := cfg.pickCredential("murbard")
		if err != nil {
			t.Fatal(err)
		}
		if got.Token != "u-tok" {
			t.Errorf("got token %q", got.Token)
		}
	})

	t.Run("matches org case-insensitive", func(t *testing.T) {
		got, err := cfg.pickCredential("TriliTech")
		if err != nil {
			t.Fatal(err)
		}
		if got.Token != "o-tok" {
			t.Errorf("got token %q", got.Token)
		}
	})

	t.Run("falls back to default when ownerless", func(t *testing.T) {
		got, err := cfg.pickCredential("")
		if err != nil {
			t.Fatal(err)
		}
		if got.Token != "u-tok" {
			t.Errorf("got token %q, want default (index 0)", got.Token)
		}
	})

	t.Run("errors when owner given but no scope matches", func(t *testing.T) {
		// The default must not mask a mismatched-owner request; otherwise we'd
		// send a doomed request to GitHub with the wrong token.
		_, err := cfg.pickCredential("anthropic")
		if !errors.Is(err, ErrNoCredential) {
			t.Errorf("got err=%v, want ErrNoCredential", err)
		}
	})

	t.Run("no default + no match → error", func(t *testing.T) {
		c := &Config{Credentials: []Credential{
			{Kind: KindFPAT, Scope: Scope{Type: ScopeOrg, Name: "trilitech"}, Token: "o-tok"},
		}}
		_, err := c.pickCredential("anthropic")
		if !errors.Is(err, ErrNoCredential) {
			t.Errorf("got err=%v, want ErrNoCredential", err)
		}
	})

	t.Run("no default + ownerless → error", func(t *testing.T) {
		c := &Config{Credentials: []Credential{
			{Kind: KindFPAT, Scope: Scope{Type: ScopeOrg, Name: "trilitech"}, Token: "o-tok"},
		}}
		_, err := c.pickCredential("")
		if !errors.Is(err, ErrNoCredential) {
			t.Errorf("got err=%v, want ErrNoCredential", err)
		}
	})
}

func TestParseConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		raw     map[string]any
		wantErr bool
	}{
		{
			name: "valid pat",
			raw: map[string]any{
				"credentials": []any{
					map[string]any{"kind": "fpat", "scope": map[string]any{"type": "user", "name": "murbard"}, "token": "ghp_x"},
				},
			},
		},
		{
			name: "empty credentials list",
			raw: map[string]any{
				"credentials": []any{},
			},
			wantErr: true,
		},
		{
			name: "bad scope type",
			raw: map[string]any{
				"credentials": []any{
					map[string]any{"kind": "fpat", "scope": map[string]any{"type": "team", "name": "x"}, "token": "ghp_x"},
				},
			},
			wantErr: true,
		},
		{
			name: "pat without token",
			raw: map[string]any{
				"credentials": []any{
					map[string]any{"kind": "fpat", "scope": map[string]any{"type": "user", "name": "murbard"}},
				},
			},
			wantErr: true,
		},
		{
			name: "default index out of range",
			raw: map[string]any{
				"credentials": []any{
					map[string]any{"kind": "fpat", "scope": map[string]any{"type": "user", "name": "murbard"}, "token": "ghp_x"},
				},
				"default_credential_index": 5,
			},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseConfig(c.raw)
			if (err != nil) != c.wantErr {
				t.Errorf("parseConfig err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestValidateRelativePath(t *testing.T) {
	bad := []string{
		`/repos/o/r/..`,
		`/repos/o/r/%2e%2e`,
		`/repos/%2fevil`,
		`\repos\o\r`,
		`/repos/o/r/sub\file`,
		`/repos/o/r/%5cetc`,
		`/repos//victim/private`, // empty segment collapses owner to ""
		`//user`,
	}
	for _, p := range bad {
		if err := validateRelativePath(p); err == nil {
			t.Errorf("validateRelativePath(%q) returned nil, want error", p)
		}
	}
	good := []string{`/repos/o/r/issues`, `/user`, `/orgs/o/repos`, `/search/code`}
	for _, p := range good {
		if err := validateRelativePath(p); err != nil {
			t.Errorf("validateRelativePath(%q) = %v, want nil", p, err)
		}
	}
}
