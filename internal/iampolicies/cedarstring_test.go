package iampolicies

import "testing"

// TestCedarString_EscapesControlChars proves cedarString escapes backslash,
// quote, and control chars (newline/CR/tab) so a crafted condition value can't
// break out of the Cedar string literal.
func TestCedarString_EscapesControlChars(t *testing.T) {
	cases := map[string]string{
		`plain`:            `"plain"`,
		`a"b`:              `"a\"b"`,
		`a\b`:              `"a\\b"`,
		"line1\nline2":     `"line1\nline2"`,
		"tab\there":        `"tab\there"`,
		"cr\rhere":         `"cr\rhere"`,
		"\"; permit(...);": `"\"; permit(...);"`,
	}
	for in, want := range cases {
		if got := cedarString(in); got != want {
			t.Errorf("cedarString(%q) = %s, want %s", in, got, want)
		}
	}
}
