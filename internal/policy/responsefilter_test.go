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
