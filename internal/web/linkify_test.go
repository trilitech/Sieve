package web

import (
	"strings"
	"testing"
)

func TestLinkify(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		contains    []string
		notContains []string
	}{
		{
			name:     "bare host with path",
			in:       "Create an internal integration at notion.so/my-integrations, copy its token.",
			contains: []string{`<a href="https://notion.so/my-integrations"`, `>notion.so/my-integrations</a>`},
		},
		{
			name:     "bare host trailing period stays outside link",
			in:       "Generated at console.anthropic.com.",
			contains: []string{`href="https://console.anthropic.com"`, `</a>.`},
		},
		{
			name:     "explicit https url with trailing paren",
			in:       "Override (e.g. https://gitlab.example.com). Leave blank.",
			contains: []string{`<a href="https://gitlab.example.com"`, `</a>)`},
		},
		{
			name:        "ip/cidr is not linkified",
			in:          "Set to 127.0.0.0/8 for a local mock.",
			notContains: []string{"<a "},
		},
		{
			name:        "abbreviation is not linkified",
			in:          "One entry per line, e.g. a CIDR.",
			notContains: []string{"<a "},
		},
		{
			name:     "html is escaped",
			in:       "danger <script> at evil.com",
			contains: []string{"&lt;script&gt;", `href="https://evil.com"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(linkifyText(tc.in))
			for _, w := range tc.contains {
				if !strings.Contains(got, w) {
					t.Errorf("output missing %q\ngot: %s", w, got)
				}
			}
			for _, w := range tc.notContains {
				if strings.Contains(got, w) {
					t.Errorf("output should not contain %q\ngot: %s", w, got)
				}
			}
			if strings.Contains(got, "<script>") {
				t.Errorf("unescaped <script> in output: %s", got)
			}
		})
	}
}
