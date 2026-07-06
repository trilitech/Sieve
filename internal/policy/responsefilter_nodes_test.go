package policy

import (
	"strings"
	"testing"
)

// TestApplyResponseFilters_ExcludeGraphQLNodes is the regression test for the P2
// finding that exclude_items only examined top-level list keys and so left Linear's
// nested GraphQL `data.<conn>.nodes` arrays unfiltered. A matching node must now be
// dropped, and the containing connection's count (totalCount) + pagination
// (pageInfo) adjusted so the drop isn't inferable.
func TestApplyResponseFilters_ExcludeGraphQLNodes(t *testing.T) {
	body := []byte(`{"data":{"issues":{` +
		`"nodes":[{"id":"1","title":"public plan"},{"id":"2","title":"the secret roadmap"}],` +
		`"pageInfo":{"endCursor":"cur","hasNextPage":true},` +
		`"totalCount":2}}}`)

	out, actions, err := ApplyResponseFilters(body,
		[]ResponseFilter{{ExcludePatterns: []string{"secret"}, Match: "contains"}},
		[]string{"title"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "the secret roadmap") {
		t.Errorf("matching GraphQL node should be excluded: %s", s)
	}
	if !strings.Contains(s, "public plan") {
		t.Errorf("non-matching node should remain: %s", s)
	}
	if strings.Contains(s, `"endCursor":"cur"`) || strings.Contains(s, `"hasNextPage":true`) {
		t.Errorf("pagination should be cleared after a nested-node exclusion: %s", s)
	}
	if !strings.Contains(s, `"totalCount":1`) {
		t.Errorf("totalCount should decrement to 1: %s", s)
	}
	if len(actions) == 0 {
		t.Error("expected an exclusion action to be reported")
	}
}

// TestApplyResponseFilters_ExcludeNestedNodesFieldAware confirms the nested-node
// path stays field-aware: a match only in a non-content field (id) must NOT drop.
func TestApplyResponseFilters_ExcludeNestedNodesFieldAware(t *testing.T) {
	body := []byte(`{"data":{"users":{"nodes":[` +
		`{"id":"secret","name":"alice"},` +
		`{"id":"2","name":"bob"}]}}}`)
	out, _, err := ApplyResponseFilters(body,
		[]ResponseFilter{{ExcludePatterns: []string{"secret"}, Match: "contains"}},
		[]string{"name"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "alice") || !strings.Contains(s, "bob") {
		t.Errorf("a match only in id (non-content) must not drop any node: %s", s)
	}
}
