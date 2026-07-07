package policy

import (
	"strings"
	"testing"
)

// TestApplyResponseFilters_ExcludeGenericListKey proves exclusion is no longer
// tied to a hardcoded key allowlist: a list under a key the old code didn't know
// (`pull_requests`) is filtered. This is the fail-open class the PR closes — the
// next connector returning a list under a new key won't silently no-op.
func TestApplyResponseFilters_ExcludeGenericListKey(t *testing.T) {
	body := []byte(`{"pull_requests":[{"title":"secret PR"},{"title":"ok PR"}]}`)
	out, _, err := ApplyResponseFilters(body,
		[]ResponseFilter{{ExcludePatterns: []string{"secret"}, Match: "contains"}},
		[]string{"title"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "secret PR") {
		t.Errorf("matching item under a non-allowlisted key must be excluded: %s", s)
	}
	if !strings.Contains(s, "ok PR") {
		t.Errorf("non-matching item must remain: %s", s)
	}
}

// TestApplyResponseFilters_ExcludeOpaqueRawFailsClosed proves that when the
// connector wraps a NON-JSON upstream as body:{"raw":"…"}, a field-aware exclude
// fails CLOSED (withhold) instead of silently no-op'ing on unfilterable content.
func TestApplyResponseFilters_ExcludeOpaqueRawFailsClosed(t *testing.T) {
	body := []byte(`{"status":200,"headers":{},"body":{"raw":"a secret in an unparseable blob"}}`)
	_, _, err := ApplyResponseFilters(body,
		[]ResponseFilter{{ExcludePatterns: []string{"secret"}, Match: "contains"}},
		[]string{"title"})
	if err == nil {
		t.Error("exclude on an opaque body:{raw} envelope must fail closed (error), not pass through")
	}
}

// TestApplyResponseFilters_SingleObjectBodyNotWithheld proves the opaque-raw
// guard is narrow: a normal single-object get (body:{id,title,…}) is NOT falsely
// withheld, and its nested structural arrays (labels/assignees) are NOT
// over-dropped even by a WHOLE-RESPONSE exclude (a single object has no list
// signal, so it isn't treated as a collection).
func TestApplyResponseFilters_SingleObjectBodyNotWithheld(t *testing.T) {
	body := []byte(`{"status":200,"headers":{},"body":{"number":1,"title":"an ordinary issue",` +
		`"labels":[{"name":"secret-label"}],"assignees":[{"login":"secretuser"}]}}`)

	// Whole-response exclude (fields nil): must NOT withhold and must NOT drop the
	// object's labels/assignees.
	out, _, err := ApplyResponseFilters(body,
		[]ResponseFilter{{ExcludePatterns: []string{"secret"}, Match: "contains"}},
		nil)
	if err != nil {
		t.Fatalf("single-object body must not be withheld: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, `"secret-label"`) || !strings.Contains(s, `"secretuser"`) {
		t.Errorf("single-object body's nested arrays must be preserved (no over-drop): %s", s)
	}
}

// TestApplyResponseFilters_ExcludeScrubsEnvelopeLink proves that after items are
// withheld from a github/gitlab REST envelope, the `Link` pagination header (which
// the envelope surfaces to the agent) is removed — closing the "more pages exist"
// side-channel.
func TestApplyResponseFilters_ExcludeScrubsEnvelopeLink(t *testing.T) {
	body := []byte(`{"status":200,"headers":{"Link":"<https://api/next>; rel=\"next\"","Content-Type":"application/json"},` +
		`"body":[{"title":"secret one"},{"title":"ok two"}]}`)
	out, _, err := ApplyResponseFilters(body,
		[]ResponseFilter{{ExcludePatterns: []string{"secret"}, Match: "contains"}},
		[]string{"title"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "secret one") {
		t.Errorf("matching item must be excluded: %s", s)
	}
	if strings.Contains(s, "rel=") || strings.Contains(s, `"Link"`) || strings.Contains(s, `"link"`) {
		t.Errorf("envelope Link header must be scrubbed after exclusion: %s", s)
	}
	if !strings.Contains(s, "Content-Type") {
		t.Errorf("non-pagination headers must remain: %s", s)
	}
}

// TestApplyResponseFilters_ExcludeLinearNodes guards the GraphQL nodes path
// (Linear/GitHub-v4 connection) after the refactor: items under data.<conn>.nodes
// are filtered and the totalCount + pageInfo side-channels are closed.
func TestApplyResponseFilters_ExcludeLinearNodes(t *testing.T) {
	body := []byte(`{"data":{"issues":{"nodes":[{"title":"secret issue"},{"title":"ok issue"}],` +
		`"totalCount":2,"pageInfo":{"hasNextPage":true,"endCursor":"CURSOR"}}}}`)
	out, _, err := ApplyResponseFilters(body,
		[]ResponseFilter{{ExcludePatterns: []string{"secret"}, Match: "contains"}},
		[]string{"title"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "secret issue") {
		t.Errorf("matching node must be excluded: %s", s)
	}
	if !strings.Contains(s, `"totalCount":1`) {
		t.Errorf("totalCount must decrement: %s", s)
	}
	if strings.Contains(s, "CURSOR") || strings.Contains(s, `"hasNextPage":true`) {
		t.Errorf("pageInfo must be reset after exclusion: %s", s)
	}
}
