package github

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestConnector wires the connector against an httptest mock GitHub.
func newTestConnector(t *testing.T, handler http.Handler) (*Connector, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	cfg, err := parseConfig(map[string]any{
		"credentials": []any{
			map[string]any{"kind": "fpat", "scope": map[string]any{"type": "user", "name": "murbard"}, "token": "ghp_user"},
			map[string]any{"kind": "fpat", "scope": map[string]any{"type": "org", "name": "trilitech"}, "token": "ghp_org"},
		},
		"default_credential_index": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &Connector{
		config:     cfg,
		apiBase:    srv.URL,
		httpClient: srv.Client(),
		appTokens:  newAppTokenCache(srv.Client()),
	}
	return c, srv
}

func TestExecute_AuthRouting(t *testing.T) {
	type recorded struct {
		path string
		auth string
	}
	var got recorded

	c, _ := newTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path = r.URL.Path
		got.auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok": true}`))
	}))

	t.Run("trilitech repo → org token", func(t *testing.T) {
		_, err := c.Execute(context.Background(), "github_get_pr", map[string]any{
			"owner": "trilitech", "repo": "Sieve", "number": 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if got.auth != "Bearer ghp_org" {
			t.Errorf("auth=%q, want Bearer ghp_org", got.auth)
		}
		if got.path != "/repos/trilitech/Sieve/pulls/1" {
			t.Errorf("path=%q", got.path)
		}
	})

	t.Run("murbard repo → user token", func(t *testing.T) {
		_, err := c.Execute(context.Background(), "github_get_pr", map[string]any{
			"owner": "murbard", "repo": "dotfiles", "number": 7,
		})
		if err != nil {
			t.Fatal(err)
		}
		if got.auth != "Bearer ghp_user" {
			t.Errorf("auth=%q, want Bearer ghp_user", got.auth)
		}
	})

	t.Run("ownerless /search/code → default (user) token", func(t *testing.T) {
		_, err := c.Execute(context.Background(), "github_search_code", map[string]any{"q": "foo"})
		if err != nil {
			t.Fatal(err)
		}
		if got.auth != "Bearer ghp_user" {
			t.Errorf("auth=%q, want default Bearer ghp_user", got.auth)
		}
		if got.path != "/search/code" {
			t.Errorf("path=%q", got.path)
		}
	})
}

func TestExecute_CreateIssue(t *testing.T) {
	var seen struct {
		method, path, ctype string
		body                map[string]any
	}
	c, _ := newTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.method = r.Method
		seen.path = r.URL.Path
		seen.ctype = r.Header.Get("Content-Type")
		buf, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(buf, &seen.body)
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"number": 42, "html_url": "https://example/issues/42"}`))
	}))

	out, err := c.Execute(context.Background(), "github_create_issue", map[string]any{
		"owner":  "trilitech",
		"repo":   "Sieve",
		"title":  "test issue",
		"body":   "details",
		"labels": []any{"bug", "p1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen.method != http.MethodPost || seen.path != "/repos/trilitech/Sieve/issues" {
		t.Errorf("got %s %s", seen.method, seen.path)
	}
	if seen.ctype != "application/json" {
		t.Errorf("content-type=%q", seen.ctype)
	}
	if seen.body["title"] != "test issue" || seen.body["body"] != "details" {
		t.Errorf("body=%v", seen.body)
	}
	if labels, ok := seen.body["labels"].([]any); !ok || len(labels) != 2 {
		t.Errorf("labels not forwarded: %v", seen.body["labels"])
	}

	resp, ok := out.(*httpResponse)
	if !ok {
		t.Fatalf("expected *httpResponse, got %T", out)
	}
	if resp.Status != http.StatusCreated {
		t.Errorf("status=%d", resp.Status)
	}
}

func TestExecute_RawRequestEscapeHatch(t *testing.T) {
	var seen struct {
		method, path, query string
		body                json.RawMessage
	}
	c, _ := newTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.method = r.Method
		seen.path = r.URL.Path
		seen.query = r.URL.RawQuery
		seen.body, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"ok": 1}`))
	}))

	_, err := c.Execute(context.Background(), "github_request", map[string]any{
		"method": "PATCH",
		"path":   "/repos/trilitech/Sieve/issues/9",
		"query":  "lock=true",
		"body":   `{"state":"closed"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen.method != "PATCH" || seen.path != "/repos/trilitech/Sieve/issues/9" {
		t.Errorf("got %s %s", seen.method, seen.path)
	}
	if seen.query != "lock=true" {
		t.Errorf("query=%q", seen.query)
	}
	if !strings.Contains(string(seen.body), `"state":"closed"`) {
		t.Errorf("body=%s", string(seen.body))
	}
}

func TestExecute_RejectsBadPath(t *testing.T) {
	c, _ := newTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not have been called for path %q", r.URL.Path)
	}))

	cases := []map[string]any{
		{"method": "GET", "path": "/repos/o/r/.."},
		{"method": "GET", "path": "/repos/o/r/%2e%2e"},
		{"method": "GET", "path": `/repos/o/r/sub\file`},
		{"method": "DELETE", "path": "no-leading-slash"},
	}
	for _, p := range cases {
		_, err := c.Execute(context.Background(), "github_request", p)
		if err == nil {
			t.Errorf("path %q: expected error, got nil", p["path"])
		}
	}
}

func TestExecute_RejectsSlashInOwnerOrRepo(t *testing.T) {
	c, _ := newTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not have been called for path %q", r.URL.Path)
	}))

	// owner or repo containing '/' must be rejected to prevent endpoint hijacking.
	cases := []struct {
		op     string
		params map[string]any
	}{
		{"github_list_issues", map[string]any{"owner": "org/evil", "repo": "Sieve"}},
		{"github_list_issues", map[string]any{"owner": "trilitech", "repo": "Sieve/evil"}},
		{"github_get_file", map[string]any{"owner": "org/evil", "repo": "Sieve", "path": "README.md"}},
		{"github_create_issue", map[string]any{"owner": "org/evil", "repo": "Sieve", "title": "x"}},
		{"github_list_repos", map[string]any{"owner": "org/evil"}},
	}
	for _, tc := range cases {
		_, err := c.Execute(context.Background(), tc.op, tc.params)
		if err == nil {
			t.Errorf("op %q with owner/repo slash: expected error, got nil", tc.op)
		}
	}
}

func TestExecute_RejectsBadMethod(t *testing.T) {
	c, _ := newTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not have been called")
	}))
	_, err := c.Execute(context.Background(), "github_request", map[string]any{
		"method": "TRACE", "path": "/user",
	})
	if err == nil {
		t.Fatal("expected error for TRACE method")
	}
}

func TestExecute_NoMatchingCredentialErrors(t *testing.T) {
	c, _ := newTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// will be called with default credential, but for this test we replace
		// the config with one that has no default.
	}))
	c.config.DefaultIndex = nil
	_, err := c.Execute(context.Background(), "github_get_pr", map[string]any{
		"owner": "anthropic", "repo": "claude", "number": 1,
	})
	if !errors.Is(err, ErrNoCredential) {
		t.Errorf("got err=%v, want ErrNoCredential", err)
	}
}

func TestExecute_GetFileEscapesPath(t *testing.T) {
	var seenPath, seenRequestURI string
	c, _ := newTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenRequestURI = r.RequestURI
		w.Write([]byte(`{}`))
	}))

	_, err := c.Execute(context.Background(), "github_get_file", map[string]any{
		"owner": "murbard",
		"repo":  "dotfiles",
		"path":  "docs/My File.md",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Decoded path restores the space.
	if seenPath != "/repos/murbard/dotfiles/contents/docs/My File.md" {
		t.Errorf("decoded path=%q", seenPath)
	}
	// The raw request line on the wire must show %20, not a literal space
	// (spaces break HTTP request-line parsing).
	if !strings.Contains(seenRequestURI, "My%20File.md") {
		t.Errorf("request URI=%q, expected %%20 escaping", seenRequestURI)
	}
}

func TestExecute_CreatePRForwardsDraftBool(t *testing.T) {
	var seenBody map[string]any
	c, _ := newTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(buf, &seenBody)
		w.Write([]byte(`{"number": 99}`))
	}))

	_, err := c.Execute(context.Background(), "github_create_pr", map[string]any{
		"owner": "trilitech", "repo": "Sieve",
		"title": "draft pr", "head": "branch", "base": "main",
		"draft": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := seenBody["draft"].(bool); !ok || !got {
		t.Errorf("draft not forwarded: %v", seenBody["draft"])
	}
}

func TestValidate_PATCredential(t *testing.T) {
	var probed string
	c, _ := newTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probed = r.URL.Path
		w.Write([]byte(`{"login": "murbard"}`))
	}))
	if err := c.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probed != "/user" {
		t.Errorf("probed=%q, want /user", probed)
	}
}

func TestValidate_PATReturns5xx(t *testing.T) {
	c, _ := newTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	if err := c.Validate(context.Background()); err == nil {
		t.Error("expected error on 401, got nil")
	}
}

func TestParseConfig_AppCredentialRoundTrip(t *testing.T) {
	// minimal valid-looking PEM; parseConfig only checks presence, not shape.
	rawPEM := "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"
	cfg, err := parseConfig(map[string]any{
		"credentials": []any{
			map[string]any{
				"kind":            "app_installation",
				"scope":           map[string]any{"type": "org", "name": "trilitech"},
				"app_id":          float64(12345),
				"installation_id": float64(99999),
				"private_key_pem": rawPEM,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Credentials) != 1 {
		t.Fatalf("got %d credentials", len(cfg.Credentials))
	}
	c := cfg.Credentials[0]
	if c.Kind != KindAppInstallation || c.AppID != 12345 || c.InstallationID != 99999 {
		t.Errorf("bad credential: %+v", c)
	}
	if c.PrivateKeyPEM != rawPEM {
		t.Errorf("PEM not preserved")
	}
}

func TestOperationsCatalogConsistency(t *testing.T) {
	// Every op listed in operations[] must be dispatchable in Execute.
	c, _ := newTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	for _, op := range operations {
		// Pass empty params; we expect either success or a parameter-required
		// error, NOT "unknown operation".
		_, err := c.Execute(context.Background(), op.Name, map[string]any{})
		if err != nil && strings.Contains(err.Error(), "unknown operation") {
			t.Errorf("op %q is in catalog but Execute reports unknown", op.Name)
		}
	}
}

// --- W1.4: github cross-fork PR head allow-list ---

// crossForkConnector returns a Connector configured against the supplied mock
// upstream and the supplied cross-fork allow-list. The default-allow-list is
// nil (deny all cross-fork heads).
func crossForkConnector(t *testing.T, allowlist []string, upstreamHit *bool) *Connector {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if upstreamHit != nil {
			*upstreamHit = true
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"number":1}`))
	}))
	t.Cleanup(srv.Close)

	rawCfg := map[string]any{
		"credentials": []any{
			map[string]any{"kind": "fpat", "scope": map[string]any{"type": "org", "name": "acme"}, "token": "ghp_acme"},
		},
	}
	if allowlist != nil {
		al := make([]any, len(allowlist))
		for i, u := range allowlist {
			al[i] = u
		}
		rawCfg["cross_fork_pr_allowlist"] = al
	}
	cfg, err := parseConfig(rawCfg)
	if err != nil {
		t.Fatal(err)
	}
	return &Connector{
		config:     cfg,
		apiBase:    srv.URL,
		httpClient: srv.Client(),
		appTokens:  newAppTokenCache(srv.Client()),
	}
}

func TestOpCreatePRRejectsCrossForkOutsideAllowlist(t *testing.T) {
	hit := false
	c := crossForkConnector(t, nil, &hit) // empty allow-list = deny-all
	_, err := c.opCreatePR(context.Background(), map[string]any{
		"owner": "acme",
		"repo":  "widgets",
		"title": "evil PR",
		"head":  "evil-user:malicious-branch",
		"base":  "main",
	})
	if !errors.Is(err, ErrCrossForkHeadDenied) {
		t.Fatalf("expected ErrCrossForkHeadDenied, got %v", err)
	}
	if !strings.Contains(err.Error(), "evil-user") {
		t.Errorf("error must name the offending user, got %q", err.Error())
	}
	if hit {
		t.Errorf("upstream MUST NOT be contacted on cross-fork deny")
	}
}

func TestOpCreatePRAllowsAllowlistedCrossFork(t *testing.T) {
	hit := false
	c := crossForkConnector(t, []string{"alice"}, &hit)
	_, err := c.opCreatePR(context.Background(), map[string]any{
		"owner": "acme",
		"repo":  "widgets",
		"title": "trusted contribution",
		"head":  "alice:feature",
		"base":  "main",
	})
	if err != nil {
		t.Fatalf("allowlisted cross-fork must succeed; got %v", err)
	}
	if !hit {
		t.Errorf("upstream was not contacted; allowlisted cross-fork should reach GitHub")
	}
}

func TestOpCreatePRRejectsNonAllowlistedCrossFork(t *testing.T) {
	hit := false
	c := crossForkConnector(t, []string{"alice"}, &hit)
	_, err := c.opCreatePR(context.Background(), map[string]any{
		"owner": "acme",
		"repo":  "widgets",
		"title": "untrusted PR",
		"head":  "bob:feature",
		"base":  "main",
	})
	if !errors.Is(err, ErrCrossForkHeadDenied) {
		t.Errorf("non-allowlisted cross-fork must deny; got %v", err)
	}
	if hit {
		t.Errorf("upstream MUST NOT be contacted")
	}
}

func TestOpCreatePRSameRepoUnaffected(t *testing.T) {
	hit := false
	c := crossForkConnector(t, nil, &hit) // empty allow-list, but same-repo head bypasses
	_, err := c.opCreatePR(context.Background(), map[string]any{
		"owner": "acme",
		"repo":  "widgets",
		"title": "feature",
		"head":  "feature-branch", // no colon = same-repo head
		"base":  "main",
	})
	if err != nil {
		t.Fatalf("same-repo head must succeed regardless of allow-list; got %v", err)
	}
	if !hit {
		t.Errorf("upstream not contacted for same-repo head")
	}
}

func TestOpCreatePRBranchNameWithColons(t *testing.T) {
	hit := false
	c := crossForkConnector(t, []string{"alice"}, &hit)
	// "alice:feature:sub-feature" — split-on-first-colon yields user "alice",
	// branch "feature:sub-feature". Allow-list contains alice → succeed.
	_, err := c.opCreatePR(context.Background(), map[string]any{
		"owner": "acme",
		"repo":  "widgets",
		"title": "branch with colons",
		"head":  "alice:feature:sub-feature",
		"base":  "main",
	})
	if err != nil {
		t.Fatalf("split-on-first-colon should grant allowlisted user; got %v", err)
	}
	if !hit {
		t.Errorf("upstream not contacted on legitimate cross-fork with colon-bearing branch")
	}
}

func TestAllowsCrossForkUserCaseInsensitive(t *testing.T) {
	cfg := &Config{CrossForkPRAllowlist: []string{"Alice"}}
	if !cfg.allowsCrossForkUser("alice") {
		t.Errorf("allow-list match should be case-insensitive (Alice ↔ alice)")
	}
	if !cfg.allowsCrossForkUser("ALICE") {
		t.Errorf("allow-list match should be case-insensitive (Alice ↔ ALICE)")
	}
	if cfg.allowsCrossForkUser("alicE-other") {
		t.Errorf("allow-list match must be exact-string (after case-fold), not substring")
	}
	if cfg.allowsCrossForkUser("") {
		t.Errorf("empty user must never match")
	}
}

func TestEmptyAllowlistEntryRejected(t *testing.T) {
	_, err := parseConfig(map[string]any{
		"credentials": []any{
			map[string]any{"kind": "fpat", "scope": map[string]any{"type": "org", "name": "acme"}, "token": "ghp_x"},
		},
		"cross_fork_pr_allowlist": []any{"", "alice"},
	})
	if err == nil {
		t.Fatal("parseConfig must reject empty allow-list entries")
	}
	if !strings.Contains(err.Error(), "cross_fork_pr_allowlist") {
		t.Errorf("error must clearly point at the offending field; got %q", err.Error())
	}
}

func TestOpCreatePRWildcardLiteral(t *testing.T) {
	// "*" must be treated as a literal user, not a wildcard.
	hit := false
	c := crossForkConnector(t, []string{"*"}, &hit)
	_, err := c.opCreatePR(context.Background(), map[string]any{
		"owner": "acme", "repo": "widgets", "title": "x",
		"head": "evil:branch",
		"base": "main",
	})
	if !errors.Is(err, ErrCrossForkHeadDenied) {
		t.Errorf("'*' allow-list entry must NOT be a wildcard; expected deny, got %v", err)
	}
	if hit {
		t.Errorf("upstream contacted despite wildcard literal interpretation")
	}
}
