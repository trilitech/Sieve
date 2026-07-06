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

// TestApplyResponseFilters_OverlappingRedactionOrderRespected proves transforms
// run SEQUENTIALLY in the order given (the engine hands them in operator-set rank
// order), so overlapping redactions are order-DEPENDENT and deterministic. In
// "x12345y": [a="123", b="345"] → a masks "123" leaving "...45...", so b's "345"
// no longer matches → "x[REDACTED]45y"; the reverse order → "x12[REDACTED]y".
// (The old span-union collapsed both to one merged "[REDACTED]" — this test would
// fail on it; it passes now that order is honored.)
func TestApplyResponseFilters_OverlappingRedactionOrderRespected(t *testing.T) {
	body := []byte(`{"body":"x12345y"}`)
	a := ResponseFilter{RedactPatterns: []string{"123"}, Match: "contains"}
	b := ResponseFilter{RedactPatterns: []string{"345"}, Match: "contains"}

	ab, _, err := ApplyResponseFilters(body, []ResponseFilter{a, b}, []string{"body"})
	if err != nil {
		t.Fatal(err)
	}
	ba, _, err := ApplyResponseFilters(body, []ResponseFilter{b, a}, []string{"body"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ab), `"x[REDACTED]45y"`) {
		t.Errorf("[a,b] should mask 123 first: want x[REDACTED]45y, got %s", ab)
	}
	if !strings.Contains(string(ba), `"x12[REDACTED]y"`) {
		t.Errorf("[b,a] should mask 345 first: want x12[REDACTED]y, got %s", ba)
	}
	if string(ab) == string(ba) {
		t.Errorf("overlapping redactions must now depend on order, got identical: %s", ab)
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

// TestApplyResponseFilters_ExcludeRedactOrderMatters proves exclude vs redact is
// order-DEPENDENT and operator-controllable: a redaction ranked BEFORE an
// exclusion can mask the very text the exclusion keys on, so the item survives
// (masked) instead of being dropped. Reverse the order and the item is dropped.
func TestApplyResponseFilters_ExcludeRedactOrderMatters(t *testing.T) {
	body := []byte(`{"emails":[{"id":"1","from":"x@vendor.com"}],"total":1}`)
	redact := ResponseFilter{RedactPatterns: []string{"vendor.com"}, Match: "contains"}
	exclude := ResponseFilter{ExcludePatterns: []string{"vendor.com"}, Match: "contains"}
	cf := []string{"from"}

	// exclude THEN redact: the item is dropped before redaction sees it.
	dropFirst, _, err := ApplyResponseFilters(body, []ResponseFilter{exclude, redact}, cf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(dropFirst), "vendor") || strings.Contains(string(dropFirst), "[REDACTED]") {
		t.Errorf("exclude-then-redact should drop the item entirely: %s", dropFirst)
	}

	// redact THEN exclude: redaction masks the text the exclude keys on, so the
	// item survives (masked). Order is honored, not erased.
	redactFirst, _, err := ApplyResponseFilters(body, []ResponseFilter{redact, exclude}, cf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(redactFirst), "[REDACTED]") {
		t.Errorf("redact-then-exclude should keep the item with `from` masked: %s", redactFirst)
	}
	if string(dropFirst) == string(redactFirst) {
		t.Errorf("exclude/redact order must matter now (not order-free): %s", dropFirst)
	}
}
