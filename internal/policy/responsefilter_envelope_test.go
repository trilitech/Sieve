package policy

import (
	"strings"
	"testing"
)

// TestApplyResponseFilters_ExcludeEnvelopeBodyArray proves exclude works on the
// github/gitlab connector envelope {status,headers,body} where a list op's body
// is a top-level JSON array. Before the fix, exclude silently no-op'd (the item
// array is under "body", not a recognized top-level list key) — a fail-open leak.
func TestApplyResponseFilters_ExcludeEnvelopeBodyArray(t *testing.T) {
	body := []byte(`{"status":200,"headers":{"Content-Type":"application/json"},` +
		`"body":[{"title":"secret roadmap"},{"title":"public plan"}]}`)

	out, actions, err := ApplyResponseFilters(body,
		[]ResponseFilter{{ExcludePatterns: []string{"secret"}, Match: "contains"}},
		[]string{"title"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "secret roadmap") {
		t.Errorf("matching item in envelope body array must be excluded: %s", s)
	}
	if !strings.Contains(s, "public plan") {
		t.Errorf("non-matching item must remain: %s", s)
	}
	if len(actions) == 0 {
		t.Error("expected an exclusion action")
	}
}

// TestApplyResponseFilters_ExcludeEnvelopeBodyObject proves exclude works on the
// github-search shape {status,headers,body:{total_count,items:[...]}} and closes
// the total_count side-channel.
func TestApplyResponseFilters_ExcludeEnvelopeBodyObject(t *testing.T) {
	body := []byte(`{"status":200,"headers":{},` +
		`"body":{"total_count":2,"incomplete_results":false,` +
		`"items":[{"title":"the secret issue"},{"title":"ok issue"}]}}`)

	out, _, err := ApplyResponseFilters(body,
		[]ResponseFilter{{ExcludePatterns: []string{"secret"}, Match: "contains"}},
		[]string{"title"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "the secret issue") {
		t.Errorf("matching item under body.items must be excluded: %s", s)
	}
	if !strings.Contains(s, "ok issue") {
		t.Errorf("non-matching item must remain: %s", s)
	}
	if !strings.Contains(s, `"total_count":1`) {
		t.Errorf("total_count must decrement to 1 (side-channel closed): %s", s)
	}
}

// TestApplyResponseFilters_ExcludeNoOverDropNestedArray proves the fix does NOT
// recurse into an item's own nested arrays: a KEPT item whose labels array
// contains the pattern must be left intact (only recognized list roots are
// filtered, never arbitrary nested arrays like labels/assignees/comments).
func TestApplyResponseFilters_ExcludeNoOverDropNestedArray(t *testing.T) {
	body := []byte(`{"status":200,"headers":{},"body":[` +
		`{"title":"ok issue","labels":["secret-label","bug"]},` +
		`{"title":"secret issue","labels":["x"]}]}`)

	out, _, err := ApplyResponseFilters(body,
		[]ResponseFilter{{ExcludePatterns: []string{"secret"}, Match: "contains"}},
		[]string{"title"}) // field-aware on title only
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// The second item's title matches → dropped.
	if strings.Contains(s, "secret issue") {
		t.Errorf("item matching in a content field must be excluded: %s", s)
	}
	// The first item is kept (title doesn't match); its labels array — which
	// contains the pattern — must be preserved untouched, not filtered.
	if !strings.Contains(s, "ok issue") {
		t.Errorf("kept item must remain: %s", s)
	}
	if !strings.Contains(s, `"secret-label"`) {
		t.Errorf("kept item's nested labels array must NOT be over-dropped: %s", s)
	}
}

// TestApplyResponseFilters_ExcludeGmailStillWorks guards the pre-existing
// top-level-list-key behavior (gmail {messages:[...]}) after the envelope refactor.
func TestApplyResponseFilters_ExcludeGmailStillWorks(t *testing.T) {
	body := []byte(`{"messages":[{"snippet":"secret note"},{"snippet":"hello"}],"resultSizeEstimate":2}`)
	out, _, err := ApplyResponseFilters(body,
		[]ResponseFilter{{ExcludePatterns: []string{"secret"}, Match: "contains"}},
		[]string{"snippet"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "secret note") {
		t.Errorf("matching message must be excluded: %s", s)
	}
	if !strings.Contains(s, "hello") {
		t.Errorf("non-matching message must remain: %s", s)
	}
	if !strings.Contains(s, `"resultSizeEstimate":1`) {
		t.Errorf("resultSizeEstimate must decrement: %s", s)
	}
}

// TestApplyResponseFilters_FieldAwareFailsClosedOnNonJSON proves a field-aware
// filter withholds (errors) rather than passing through when the body can't be
// parsed as JSON — previously a silent fail-open.
func TestApplyResponseFilters_FieldAwareFailsClosedOnNonJSON(t *testing.T) {
	body := []byte("this is not JSON at all, but contains a secret")

	// Redact, field-aware (contentFields make fieldSet non-nil).
	_, _, rerr := ApplyResponseFilters(body,
		[]ResponseFilter{{RedactPatterns: []string{"secret"}, Match: "contains"}},
		[]string{"title"})
	if rerr == nil {
		t.Error("field-aware redact on a non-JSON body must fail closed (error), not pass through")
	}

	// Exclude, field-aware.
	_, _, eerr := ApplyResponseFilters(body,
		[]ResponseFilter{{ExcludePatterns: []string{"secret"}, Match: "contains"}},
		[]string{"title"})
	if eerr == nil {
		t.Error("field-aware exclude on a non-JSON body must fail closed (error), not pass through")
	}
}
