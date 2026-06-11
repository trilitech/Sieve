package web

import (
	"strings"
	"testing"
)

// filename parameter must be a single safe filename — no path separators,
// no ".." segments, no leading ".", no disallowed characters.

func TestValidateScriptFilename(t *testing.T) {
	cases := []struct {
		name        string
		shouldFail  bool
		reasonChunk string
	}{
		{"safe.py", false, ""},
		{"my_policy.py", false, ""},
		{"my-policy-v2.py", false, ""},
		{"My.Policy.py", false, ""},

		// Path separators
		{"a/b.py", true, "separator"},
		{"a\\b.py", true, "separator"},
		{"/etc/passwd", true, "separator"},
		{"subdir/x.py", true, "separator"},

		// Traversal
		{"../../etc/passwd", true, ""},
		{"..", true, ""},
		{".", true, "start with"},
		{"..py", true, ""},  // caught by leading-"." rule before "'..'"
		{"a..b", true, "'..'"},

		// Hidden files
		{".hidden", true, "start with"},
		{".bashrc", true, "start with"},

		// Disallowed characters
		{"name with spaces.py", true, "disallowed"},
		{"weird;name.py", true, "disallowed"},
		{"name|pipe.py", true, "disallowed"},
		{"name\x00null.py", true, "disallowed"},

		// Empty
		{"", true, "empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason := validateScriptFilename(tc.name)
			if tc.shouldFail && reason == "" {
				t.Errorf("expected rejection for %q, got accepted", tc.name)
			}
			if !tc.shouldFail && reason != "" {
				t.Errorf("expected accept for %q, got rejection: %s", tc.name, reason)
			}
			if tc.reasonChunk != "" && !strings.Contains(reason, tc.reasonChunk) {
				t.Errorf("for %q: reason %q does not contain %q", tc.name, reason, tc.reasonChunk)
			}
		})
	}
}
