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
	out, _, err := ApplyResponseFilters(body, []ResponseFilter{{ExcludePatterns: []string{"VENDOR.com"}, Match: "contains"}})
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
	out2, _, err := ApplyResponseFilters(body, []ResponseFilter{{ExcludePatterns: []string{`@v\w+\.com`}, Match: "regex"}})
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
	out, _, err := ApplyResponseFilters(body, []ResponseFilter{{RedactPatterns: []string{`\d{16}`}, Match: "regex"}})
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
	out2, _, err := ApplyResponseFilters(body, []ResponseFilter{{RedactPatterns: []string{"secret"}, Match: "contains"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out2), "SECRET") {
		t.Errorf("contains redact should mask SECRET case-insensitively: %s", out2)
	}
}
