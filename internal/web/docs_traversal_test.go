package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// TestDocsRejectsPathTraversal proves that the /docs/{name} route cannot
// be coaxed into reading a file outside the docs/ directory by stuffing
// `..` segments into the slug — either literally (which Go's mux rejects
// at the routing layer) or percent-encoded as %2F%2E%2E (which Go decodes
// before delivering the value to handleDocs via r.PathValue). Without
// validateDocSlug, an unauthenticated request to e.g.
// `/docs/..%2F..%2Fetc%2Fpasswd` would resolve to `os.ReadFile("docs/../../etc/passwd.md")`
// — and /docs is in authExemptPrefixes, so this would be unauthenticated.
func TestDocsRejectsPathTraversal(t *testing.T) {
	env := testenv.New(t).WithOperator("test-pass", "test-op")
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := NewServer(
		env.Tokens, env.Connections, env.Policies, env.Roles,
		env.Registry, env.Approval, env.Audit,
		"", env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "127.0.0.1:0",
	)
	srv.SetAuth(env.Operator, env.Session)
	t.Cleanup(srv.Close)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	cases := []struct {
		name string
		path string
	}{
		{"encoded-slash-and-dotdot", "/docs/..%2Fetc%2Fpasswd"},
		{"double-encoded-traversal", "/docs/..%2F..%2Fetc%2Fpasswd"},
		{"slug-with-encoded-slash", "/docs/foo%2Fbar"},
		{"leading-dot", "/docs/.env"},
		// /docs/.. is normalized by http.ServeMux to /docs/ and routed
		// to handleDocsIndex (which doesn't read by slug), so it isn't
		// a traversal — the only-dotdot case is exercised via the
		// percent-encoded variant above.
		{"backslash-segment", "/docs/..%5Cetc%5Cpasswd"},
		{"unicode-letter-shenanigans", "/docs/etc%2Fpasswd"},
		{"contains-dot-dot-substring", "/docs/foo..bar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(ts.URL + tc.path)
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s: status=%d, want 404 (traversal must be rejected)",
					tc.path, resp.StatusCode)
			}
		})
	}
}

// TestValidateDocSlug pins the slug allowlist directly.
func TestValidateDocSlug(t *testing.T) {
	ok := []string{"agent-error-contract", "credential_encryption", "abc123", "x"}
	for _, s := range ok {
		if msg := validateDocSlug(s); msg != "" {
			t.Errorf("validateDocSlug(%q) = %q, want empty (slug should be allowed)", s, msg)
		}
	}
	bad := []string{
		"", ".", "..", ".env", "../passwd", "foo/bar",
		"foo\\bar", "foo..bar", "foo bar", "foo.md", "foo$bar",
	}
	for _, s := range bad {
		if msg := validateDocSlug(s); msg == "" {
			t.Errorf("validateDocSlug(%q) returned empty, expected rejection", s)
		}
	}
}
