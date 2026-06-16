package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
)

// newTestConnector spins up an httptest.Server with the given handler
// and returns a Connector wired to it via the base_url override. The
// returned httptest.Server is automatically closed at test end via
// t.Cleanup so individual tests don't need to manage it.
func newTestConnector(t *testing.T, handler http.HandlerFunc) *Connector {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	c, err := Factory()(map[string]any{
		"token":    "glpat-test-not-real",
		"base_url": srv.URL,
	})
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	return c.(*Connector)
}

// --- parseConfig ---

func TestParseConfig_RequiresToken(t *testing.T) {
	_, err := parseConfig(map[string]any{"base_url": "https://gitlab.com"})
	if err == nil {
		t.Fatal("expected error for missing token")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error should mention token; got %v", err)
	}
}

func TestParseConfig_TrimsTokenWhitespace(t *testing.T) {
	// Pasted PATs commonly arrive with a trailing newline. Without the
	// trim, the connector would send the untrimmed token upstream and
	// get a confusing 401.
	for _, sample := range []string{
		"  glpat-abc  ",
		"glpat-abc\n",
		"\tglpat-abc",
	} {
		t.Run(sample, func(t *testing.T) {
			cfg, err := parseConfig(map[string]any{"token": sample})
			if err != nil {
				t.Fatalf("parseConfig: %v", err)
			}
			if cfg.Token != "glpat-abc" {
				t.Errorf("token should be trimmed; got %q", cfg.Token)
			}
		})
	}
}

func TestParseConfig_DefaultsBaseURL(t *testing.T) {
	cfg, err := parseConfig(map[string]any{"token": "glpat-abc"})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.BaseURL != defaultBaseURL {
		t.Errorf("base_url should default; got %q want %q", cfg.BaseURL, defaultBaseURL)
	}
}

func TestParseConfig_RejectsBaseURLWithoutScheme(t *testing.T) {
	_, err := parseConfig(map[string]any{
		"token":    "glpat-abc",
		"base_url": "gitlab.example.com",
	})
	if err == nil {
		t.Fatal("expected error for schemeless base_url")
	}
}

func TestParseConfig_StripsTrailingSlash(t *testing.T) {
	// Without this, doRequest would produce double slashes
	// (gitlab.com//api/v4/...) which most reverse proxies handle but
	// some self-hosted gateways reject.
	cfg, err := parseConfig(map[string]any{
		"token":    "glpat-abc",
		"base_url": "https://gitlab.example.com/",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.BaseURL != "https://gitlab.example.com" {
		t.Errorf("trailing slash should be stripped; got %q", cfg.BaseURL)
	}
}

// --- auth header ---

func TestDoRequest_AttachesPrivateTokenHeader(t *testing.T) {
	var seenPrivateToken, seenAuth string
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		seenPrivateToken = r.Header.Get("PRIVATE-TOKEN")
		seenAuth = r.Header.Get("Authorization")
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"id":42}`))
	})

	_, err := conn.doRequest(context.Background(), "GET", "/user", nil, nil)
	if err != nil {
		t.Fatalf("doRequest: %v", err)
	}
	if seenPrivateToken != "glpat-test-not-real" {
		t.Errorf("PRIVATE-TOKEN header = %q, want glpat-test-not-real", seenPrivateToken)
	}
	// We deliberately don't set Authorization: Bearer — GitLab accepts
	// either, but PRIVATE-TOKEN is the canonical PAT header and using
	// both would leak the token to two logging surfaces.
	if seenAuth != "" {
		t.Errorf("Authorization header should not be set when using PRIVATE-TOKEN; got %q", seenAuth)
	}
}

// --- response size cap ---

func TestDoRequest_OversizedResponseRejected(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		// Write 6 MiB > 5 MiB cap. 64 KiB chunks keep this fast.
		chunk := make([]byte, 64*1024)
		for i := 0; i < 96; i++ {
			_, _ = w.Write(chunk)
		}
	})
	_, err := conn.doRequest(context.Background(), "GET", "/projects", nil, nil)
	if err == nil {
		t.Fatal("expected error on oversized response")
	}
	if !strings.Contains(err.Error(), "byte cap") {
		t.Errorf("error should mention cap; got %v", err)
	}
}

// --- path validation ---

func TestDoRequest_RejectsPathTraversal(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for invalid path")
	})
	for _, bad := range []string{
		"/projects/../admin",
		"/projects/%2e%2e/admin",
		"/projects\\admin",
		"projects/foo",     // missing leading slash
		"/projects//foo",   // empty segment
	} {
		t.Run(bad, func(t *testing.T) {
			_, err := conn.doRequest(context.Background(), "GET", bad, nil, nil)
			if err == nil {
				t.Errorf("path %q should be rejected", bad)
			}
		})
	}
}

// --- Validate ---

func TestValidate_TokenRejectedMapsToReauth(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"401 Unauthorized"}`))
	})
	err := conn.Validate(context.Background())
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf("401 should wrap ErrNeedsReauth; got %v", err)
	}
}

func TestValidate_403MapsToReauth(t *testing.T) {
	// GitLab returns 403 on token-scope mismatches (e.g. a read_api
	// token trying to write). That's an auth-level problem the
	// operator must resolve by issuing a new token; treat as reauth.
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"insufficient_scope"}`))
	})
	err := conn.Validate(context.Background())
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf("403 should wrap ErrNeedsReauth; got %v", err)
	}
}

func TestValidate_5xxDoesNotBlockSave(t *testing.T) {
	// Same semantics as the anthropic connector: a transient 5xx
	// must not refuse to save the connection — operators would be
	// stuck during outages. Error surfaces on first agent call.
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	if err := conn.Validate(context.Background()); err != nil {
		t.Errorf("transient 5xx must not block save; got %v", err)
	}
}

func TestValidate_TransportErrorDoesNotBlockSave(t *testing.T) {
	// Build a config pointing at a closed server, then Validate.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	c, err := Factory()(map[string]any{"token": "glpat-x", "base_url": srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	srv.Close() // make the URL unreachable
	if err := c.Validate(context.Background()); err != nil {
		t.Errorf("transport failure must not block save; got %v", err)
	}
}

func TestValidate_OkResponseSucceeds(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"id":42,"username":"sieve-test"}`))
	})
	if err := conn.Validate(context.Background()); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// --- ops: shape + URL construction ---

// TestOpListProjects_DefaultsMembershipTrue pins the default-narrowing
// behaviour: agents that don't pass `membership` get the user's own
// project list, NOT every project visible to the token (which on a
// public-instance GitLab includes millions of projects).
func TestOpListProjects_DefaultsMembershipTrue(t *testing.T) {
	var gotQuery url.Values
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})
	_, err := conn.Execute(context.Background(), "gitlab_list_projects", map[string]any{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotQuery.Get("membership") != "true" {
		t.Errorf("membership should default to true; got query %v", gotQuery)
	}
}

func TestOpListProjects_ExplicitMembershipFalseRespected(t *testing.T) {
	var gotQuery url.Values
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})
	_, err := conn.Execute(context.Background(), "gitlab_list_projects", map[string]any{
		"membership": false,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotQuery.Get("membership") != "" {
		t.Errorf("explicit membership=false should omit the query param; got %q", gotQuery.Get("membership"))
	}
}

// TestOpGetFile_EncodesProjectAndPath confirms the URL construction
// for the most-bug-prone op: project="group/sub/project" must become
// "group%2Fsub%2Fproject" so the API sees one path segment, and the
// file path equally so. Without correct encoding, GitLab returns a
// confusing 404.
//
// We assert against r.URL.RawPath (not r.URL.Path) because Go's URL
// parser stores Path in decoded form — the %2F bytes literally flatten
// to '/' there. RawPath preserves the on-wire shape, which is what
// GitLab actually receives and parses.
func TestOpGetFile_EncodesProjectAndPath(t *testing.T) {
	var seenRawPath, seenQuery string
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		seenRawPath = r.URL.RawPath
		seenQuery = r.URL.RawQuery
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"file_name":"README.md"}`))
	})
	_, err := conn.Execute(context.Background(), "gitlab_get_file", map[string]any{
		"project": "acme/subgroup/widget",
		"path":    "docs/setup.md",
		"ref":     "main",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	wantPath := "/api/v4/projects/acme%2Fsubgroup%2Fwidget/repository/files/docs%2Fsetup.md"
	if seenRawPath != wantPath {
		t.Errorf("URL RawPath = %q, want %q", seenRawPath, wantPath)
	}
	if !strings.Contains(seenQuery, "ref=main") {
		t.Errorf("query should include ref=main; got %q", seenQuery)
	}
}

func TestOpPutFile_DefaultsToPOSTUnlessUpdateTrue(t *testing.T) {
	var seenMethod string
	handler := func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"file_path":"x"}`))
	}

	conn := newTestConnector(t, handler)
	_, err := conn.Execute(context.Background(), "gitlab_put_file", map[string]any{
		"project":        "ns/proj",
		"path":           "f.txt",
		"branch":         "main",
		"content":        "hi",
		"commit_message": "add f",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if seenMethod != http.MethodPost {
		t.Errorf("default should be POST (create); got %s", seenMethod)
	}

	conn2 := newTestConnector(t, handler)
	_, err = conn2.Execute(context.Background(), "gitlab_put_file", map[string]any{
		"project":        "ns/proj",
		"path":           "f.txt",
		"branch":         "main",
		"content":        "hi",
		"commit_message": "edit f",
		"update":         true,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if seenMethod != http.MethodPut {
		t.Errorf("update=true should be PUT; got %s", seenMethod)
	}
}

func TestOpCreateIssue_BuildsBody(t *testing.T) {
	var receivedBody map[string]any
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"iid":7}`))
	})
	_, err := conn.Execute(context.Background(), "gitlab_create_issue", map[string]any{
		"project":     "ns/proj",
		"title":       "Bug",
		"description": "It broke.",
		"labels":      "bug,urgent",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if receivedBody["title"] != "Bug" {
		t.Errorf("title not sent; body=%v", receivedBody)
	}
	if receivedBody["description"] != "It broke." {
		t.Errorf("description not sent; body=%v", receivedBody)
	}
	if receivedBody["labels"] != "bug,urgent" {
		t.Errorf("labels not sent; body=%v", receivedBody)
	}
}

func TestOpCommentIssue_RequiresIid(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called when iid=0")
	})
	_, err := conn.Execute(context.Background(), "gitlab_comment_issue", map[string]any{
		"project": "ns/proj",
		"body":    "hi",
	})
	if err == nil {
		t.Fatal("expected error for missing issue_iid")
	}
}

func TestOpRequest_PassesThroughMethodPathAndBody(t *testing.T) {
	var seenMethod, seenPath, seenQuery string
	var receivedBody map[string]any
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		seenQuery = r.URL.RawQuery
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &receivedBody)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	_, err := conn.Execute(context.Background(), "gitlab_request", map[string]any{
		"method": "post",
		"path":   "/projects/42/repository/branches",
		"query":  "branch=topic&ref=main",
		"body":   `{"foo":"bar"}`,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if seenMethod != "POST" {
		t.Errorf("method should be uppercased; got %s", seenMethod)
	}
	if seenPath != "/api/v4/projects/42/repository/branches" {
		t.Errorf("path = %q", seenPath)
	}
	if !strings.Contains(seenQuery, "branch=topic") {
		t.Errorf("query = %q", seenQuery)
	}
	if receivedBody["foo"] != "bar" {
		t.Errorf("body not forwarded; got %v", receivedBody)
	}
}

func TestOpRequest_RejectsBadMethod(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for bad method")
	})
	_, err := conn.Execute(context.Background(), "gitlab_request", map[string]any{
		"method": "TRACE",
		"path":   "/x",
	})
	if err == nil {
		t.Fatal("expected error for bad method")
	}
}

// TestOpRequest_PreservesJSONNullBody pins the fix for the
// unmarshal+remarshal round-trip bug. An agent passing the literal
// JSON `null` body must produce an upstream request whose body bytes
// are exactly "null" with Content-Type: application/json set. The
// previous shape (json.Unmarshal into any → Go nil → doRequest's
// nil-check skips body marshaling entirely) silently changed the
// request to "no body, no Content-Type", which is observably
// different to GitLab.
func TestOpRequest_PreservesJSONNullBody(t *testing.T) {
	var seenBody []byte
	var seenContentType string
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenContentType = r.Header.Get("Content-Type")
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	_, err := conn.Execute(context.Background(), "gitlab_request", map[string]any{
		"method": "POST",
		"path":   "/test",
		"body":   "null",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if string(seenBody) != "null" {
		t.Errorf("body bytes = %q, want \"null\"", string(seenBody))
	}
	if seenContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", seenContentType)
	}
}

// TestOpRequest_PreservesJSONBodyByteForByte covers the broader
// contract: json.RawMessage round-trips without losing precision,
// key ordering, or whitespace. Without this, an agent that crafts a
// specific JSON payload (say, a large integer that exceeds float64
// precision) would get a different upstream request than it intended.
func TestOpRequest_PreservesJSONBodyByteForByte(t *testing.T) {
	original := `{"description":"hello","numeric":9007199254740993,"nested":{"z":1,"a":2}}`
	var seenBody []byte
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	_, err := conn.Execute(context.Background(), "gitlab_request", map[string]any{
		"method": "POST",
		"path":   "/projects/1/issues",
		"body":   original,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if string(seenBody) != original {
		t.Errorf("body modified in transit:\n  got  %q\n  want %q", string(seenBody), original)
	}
}

func TestOpRequest_RejectsRelativePath(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for non-absolute path")
	})
	_, err := conn.Execute(context.Background(), "gitlab_request", map[string]any{
		"method": "GET",
		"path":   "projects",
	})
	if err == nil {
		t.Fatal("expected error for relative path")
	}
}

// TestOpRequest_StripsLeadingAPIPrefix pins the friendly-input
// behaviour: agents that read the GitLab docs naturally type
// /api/v4/projects but doRequest always prepends apiPrefix. Without
// normalisation that would land at /api/v4/api/v4/projects and 404.
// Both `/projects` and `/api/v4/projects` must route to the same
// endpoint.
func TestOpRequest_StripsLeadingAPIPrefix(t *testing.T) {
	var seenPath string
	handler := func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}

	for _, supplied := range []string{"/projects", "/api/v4/projects"} {
		t.Run(supplied, func(t *testing.T) {
			conn := newTestConnector(t, handler)
			_, err := conn.Execute(context.Background(), "gitlab_request", map[string]any{
				"method": "GET",
				"path":   supplied,
			})
			if err != nil {
				t.Fatalf("Execute(path=%q): %v", supplied, err)
			}
			if seenPath != "/api/v4/projects" {
				t.Errorf("path %q produced upstream URL %q, want /api/v4/projects",
					supplied, seenPath)
			}
		})
	}
}

// TestOpRequest_RejectsBareAPIPrefix guards against a corner case of
// the strip-prefix normalisation: "make a request to the API prefix
// itself" isn't meaningful, and silently turning it into a request to
// "" would produce a confusing upstream response. Reject loudly.
func TestOpRequest_RejectsBareAPIPrefix(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called when path is just the prefix")
	})
	for _, bad := range []string{"/api/v4", "/api/v4/"} {
		t.Run(bad, func(t *testing.T) {
			_, err := conn.Execute(context.Background(), "gitlab_request", map[string]any{
				"method": "GET",
				"path":   bad,
			})
			if err == nil {
				t.Errorf("path %q should be rejected", bad)
			}
		})
	}
}

// TestValidateRelativePath_RejectsSurvivingEncodedSlash pins the
// extra %2f check added alongside %2e and %5c. Legitimate paths
// (encoded once via url.PathEscape) decode in a single pass and don't
// trigger this branch; only inputs whose encoding survives 5 passes
// reach it. Matches the github connector's hardening.
func TestValidateRelativePath_RejectsSurvivingEncodedSlash(t *testing.T) {
	// %25252525252f is %2f wrapped in five %25 layers. The validator
	// runs five PathUnescape passes which peel layers but leave the
	// final %2f intact — the post-decoded `decoded` string still
	// contains %2f and the rejection check fires.
	//
	// (Single- or double-encoded %2f decodes fully inside the loop
	// and reaches the check as a literal '/', which is allowed —
	// that's the legitimate single-pass shape used by encodeProject
	// and encodeRefOrPath.)
	if err := validateRelativePath("/projects/foo%25252525252fbar"); err == nil {
		t.Errorf("over-encoded %%2f should be rejected after 5 passes still leave it intact")
	}
}

// TestValidateRelativePath_AllowsSinglePassEncodedSlash pins the
// inverse: a path whose embedded slashes are encoded ONCE (the
// legitimate output of url.PathEscape used by encodeProject /
// encodeRefOrPath) must NOT be rejected by the %2f hardening. If it
// were, every gitlab_get_file call would fail.
func TestValidateRelativePath_AllowsSinglePassEncodedSlash(t *testing.T) {
	if err := validateRelativePath("/projects/group%2Fsubgroup/repository/files/docs%2Fsetup.md"); err != nil {
		t.Errorf("legitimately single-encoded path was rejected: %v", err)
	}
}

// TestOperations_CatalogShape catches accidental rename / removal of
// the v1 operations. Drift here would break every bound policy at
// execute time.
func TestOperations_CatalogShape(t *testing.T) {
	c, err := Factory()(map[string]any{"token": "glpat-test"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"gitlab_request":       false,
		"gitlab_list_projects": true,
		"gitlab_get_file":      true,
		"gitlab_put_file":      false,
		"gitlab_list_issues":   true,
		"gitlab_create_issue":  false,
		"gitlab_comment_issue": false,
		"gitlab_list_mrs":      true,
		"gitlab_get_mr":        true,
		"gitlab_create_mr":     false,
		"gitlab_search_blobs":  true,
	}
	got := make(map[string]bool)
	for _, op := range c.Operations() {
		got[op.Name] = op.ReadOnly
	}
	for name, ro := range want {
		actual, present := got[name]
		if !present {
			t.Errorf("operation %q missing from catalog", name)
			continue
		}
		if actual != ro {
			t.Errorf("operation %q: ReadOnly = %v, want %v", name, actual, ro)
		}
	}
	for name := range got {
		if _, expected := want[name]; !expected {
			t.Errorf("unexpected operation %q in catalog", name)
		}
	}
}

func TestExecute_UnknownOperationFailsCleanly(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for unknown op")
	})
	_, err := conn.Execute(context.Background(), "gitlab_nuke_repo", nil)
	if err == nil {
		t.Fatal("expected error for unknown op")
	}
	if !strings.Contains(err.Error(), "unknown operation") {
		t.Errorf("expected 'unknown operation' in error; got %v", err)
	}
}
