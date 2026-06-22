package policy

import (
	"strings"
	"testing"
)

// TestApplyResponseFilters_ExcludeMatchModes proves exclude_items supports BOTH
// a literal "contains" match and a "regex" match — the same matching model as
// redact (no more "exclude is exact, redact is regex" asymmetry).
func TestApplyResponseFilters_ExcludeMatchModes(t *testing.T) {
	body := []byte(`{"emails":[{"from":"a@vendor.com"},{"from":"b@trilitech.com"}],"total":2}`)

	// contains: literal substring, case-insensitive.
	out, _, err := ApplyResponseFilters(body, []ResponseFilter{{ExcludePatterns: []string{"VENDOR.com"}, Match: "contains"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "vendor.com") {
		t.Errorf("contains exclude should drop the vendor item: %s", out)
	}
	if !strings.Contains(string(out), "trilitech.com") {
		t.Errorf("non-matching item should remain: %s", out)
	}

	// regex: same field, regex mode.
	out2, _, err := ApplyResponseFilters(body, []ResponseFilter{{ExcludePatterns: []string{`@v\w+\.com`}, Match: "regex"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out2), "vendor.com") {
		t.Errorf("regex exclude should drop the vendor item: %s", out2)
	}
	if !strings.Contains(string(out2), "trilitech.com") {
		t.Errorf("regex exclude should keep the non-matching item: %s", out2)
	}
}

// TestApplyResponseFilters_RedactMatchModes proves redact supports BOTH regex
// and literal "contains" — the symmetric counterpart to exclude.
func TestApplyResponseFilters_RedactMatchModes(t *testing.T) {
	body := []byte(`{"body":"card 4111111111111111 and the word SECRET"}`)

	// regex.
	out, _, err := ApplyResponseFilters(body, []ResponseFilter{{RedactPatterns: []string{`\d{16}`}, Match: "regex"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "4111111111111111") {
		t.Errorf("regex redact should mask the card number: %s", out)
	}
	if !strings.Contains(string(out), "[REDACTED]") {
		t.Errorf("expected [REDACTED] marker: %s", out)
	}

	// contains: literal, case-insensitive (masks SECRET though the pattern is lower-case).
	out2, _, err := ApplyResponseFilters(body, []ResponseFilter{{RedactPatterns: []string{"secret"}, Match: "contains"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out2), "SECRET") {
		t.Errorf("contains redact should mask SECRET case-insensitively: %s", out2)
	}
}

// TestApplyResponseFilters_FieldAware proves redact/exclude apply ONLY within the
// connector's content fields: a digit run inside a base64 attachment or in
// metadata is never touched, and an item drops on a content-field match, not a
// metadata match.
func TestApplyResponseFilters_FieldAware(t *testing.T) {
	contentFields := []string{"body", "from"}

	// Redact: SSN in `body` is masked; an identical run inside attachments[].data
	// (base64, NOT a content field) and in `id` (metadata) is left intact.
	body := []byte(`{"emails":[{"id":"123-45-6789","body":"ssn 123-45-6789","attachments":[{"data":"AAA123-45-6789AAA"}]}]}`)
	out, _, err := ApplyResponseFilters(body, []ResponseFilter{{RedactPatterns: []string{`\d{3}-\d{2}-\d{4}`}, Match: "regex"}}, contentFields)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, `ssn 123-45-6789`) {
		t.Errorf("SSN in body should be redacted: %s", s)
	}
	if !strings.Contains(s, "AAA123-45-6789AAA") {
		t.Errorf("SSN-like run inside a base64 attachment must NOT be redacted: %s", s)
	}
	if !strings.Contains(s, `"id":"123-45-6789"`) {
		t.Errorf("id (metadata, not a content field) must NOT be redacted: %s", s)
	}

	// Exclude: drop the item whose `from` (content) matches; an identical string
	// only in `id` (metadata) must NOT cause a drop.
	list := []byte(`{"emails":[{"id":"1","from":"x@vendor.com"},{"id":"vendor.com","from":"y@ok.com"}],"total":2}`)
	out2, _, err := ApplyResponseFilters(list, []ResponseFilter{{ExcludePatterns: []string{"vendor.com"}, Match: "contains"}}, contentFields)
	if err != nil {
		t.Fatal(err)
	}
	s2 := string(out2)
	if strings.Contains(s2, "x@vendor.com") {
		t.Errorf("item with vendor.com in `from` (content) should be dropped: %s", s2)
	}
	if !strings.Contains(s2, "y@ok.com") {
		t.Errorf("item with vendor.com only in `id` (metadata) must be kept: %s", s2)
	}
}

// TestApplyResponseFilters_OverlappingRedactionOrderFree is the regression test
// for the order-dependence bug: with OVERLAPPING patterns, applying redact
// filters sequentially (replace one filter at a time) is NOT commutative — in
// "x12345y", filter A="123" then B="345" yields "x[REDACTED]45y", but B then A
// yields "x12[REDACTED]y". Span-union (compute every match on the ORIGINAL,
// merge overlapping/adjacent spans, mask in place) makes the output identical
// regardless of order: the merged span 1..6 collapses to a single [REDACTED].
func TestApplyResponseFilters_OverlappingRedactionOrderFree(t *testing.T) {
	body := []byte(`{"body":"x12345y"}`)
	a := ResponseFilter{RedactPatterns: []string{"123"}, Match: "contains"}
	b := ResponseFilter{RedactPatterns: []string{"345"}, Match: "contains"}

	var outs []string
	for _, order := range [][]ResponseFilter{{a, b}, {b, a}} {
		out, _, err := ApplyResponseFilters(body, order, []string{"body"})
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, string(out))
	}
	if outs[0] != outs[1] {
		t.Fatalf("redaction must be order-independent:\n [a,b]=%s\n [b,a]=%s", outs[0], outs[1])
	}
	if !strings.Contains(outs[0], `"x[REDACTED]y"`) {
		t.Errorf("overlapping spans should merge into a single [REDACTED]: %s", outs[0])
	}
}

// TestApplyResponseFilters_TwoRedactionsCompose proves two different redactions
// (e.g. from two matching rules) both apply — every filter's spans are masked.
func TestApplyResponseFilters_TwoRedactionsCompose(t *testing.T) {
	body := []byte(`{"body":"ssn 123-45-6789 and card 4111111111111111"}`)
	ssn := ResponseFilter{RedactPatterns: []string{`\d{3}-\d{2}-\d{4}`}, Match: "regex"}
	card := ResponseFilter{RedactPatterns: []string{`\d{16}`}, Match: "regex"}

	out, _, err := ApplyResponseFilters(body, []ResponseFilter{ssn, card}, []string{"body"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "123-45-6789") {
		t.Errorf("SSN should be masked: %s", s)
	}
	if strings.Contains(s, "4111111111111111") {
		t.Errorf("card should be masked: %s", s)
	}
}

// TestApplyResponseFilters_ExcludeRedactOrderFree proves exclude + redact give
// the same result regardless of order: exclusions always run first (union of
// drops), then redaction masks only the survivors.
func TestApplyResponseFilters_ExcludeRedactOrderFree(t *testing.T) {
	body := []byte(`{"emails":[{"from":"a@vendor.com","body":"ssn 123-45-6789"},{"from":"b@ok.com","body":"ssn 999-88-7777"}],"total":2}`)
	drop := ResponseFilter{ExcludePatterns: []string{"vendor.com"}, Match: "contains"}
	red := ResponseFilter{RedactPatterns: []string{`\d{3}-\d{2}-\d{4}`}, Match: "regex"}

	var outs []string
	for _, order := range [][]ResponseFilter{{drop, red}, {red, drop}} {
		out, _, err := ApplyResponseFilters(body, order, []string{"from", "body"})
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, string(out))
	}
	if outs[0] != outs[1] {
		t.Fatalf("exclude+redact must be order-independent:\n %s\n %s", outs[0], outs[1])
	}
	if strings.Contains(outs[0], "vendor.com") {
		t.Errorf("vendor item should be excluded: %s", outs[0])
	}
	if strings.Contains(outs[0], "999-88-7777") {
		t.Errorf("surviving item's SSN should be redacted: %s", outs[0])
	}
}
