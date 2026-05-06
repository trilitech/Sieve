package web

import (
	"strings"
	"testing"
)

func TestExtractHeadings_Basic(t *testing.T) {
	in := `# Title

Lead paragraph.

## First Section

content one

## Second Section

content two

### Sub

content sub
`
	h := ExtractHeadings(in)
	if got, want := len(h), 3; got != want {
		t.Fatalf("got %d headings, want %d (%v)", got, want, h)
	}
	if h[0].Anchor != "first-section" || h[0].Level != 2 {
		t.Errorf("h[0] = %+v", h[0])
	}
	if h[1].Anchor != "second-section" {
		t.Errorf("h[1].Anchor = %q", h[1].Anchor)
	}
	if h[2].Anchor != "sub" || h[2].Level != 3 {
		t.Errorf("h[2] = %+v", h[2])
	}
}

func TestExtractHeadings_AnchorsUnique(t *testing.T) {
	in := `## Setup

a

## Setup

b

## Setup

c
`
	h := ExtractHeadings(in)
	if h[0].Anchor != "setup" || h[1].Anchor != "setup-2" || h[2].Anchor != "setup-3" {
		t.Fatalf("anchors = %v", []string{h[0].Anchor, h[1].Anchor, h[2].Anchor})
	}
}

func TestExtractHeadings_Deterministic(t *testing.T) {
	in := `## A

x

## B

y
`
	a := ExtractHeadings(in)
	b := ExtractHeadings(in)
	if len(a) != len(b) {
		t.Fatalf("len mismatch")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("differ at %d: %v vs %v", i, a[i], b[i])
		}
	}
}

func TestExtractHeadings_SkipsFencedCode(t *testing.T) {
	in := "## Real\n\nreal content\n\n```\n## Fake H2\n```\n\nback to real\n\n## Also Real\n"
	h := ExtractHeadings(in)
	if len(h) != 2 {
		t.Fatalf("got %d headings, want 2 (%v)", len(h), h)
	}
	for _, head := range h {
		if strings.Contains(head.Text, "Fake") {
			t.Errorf("heading inside fenced code was extracted: %v", head)
		}
	}
}

func TestExtractHeadings_PunctuationSlugify(t *testing.T) {
	cases := []struct {
		text   string
		anchor string
	}{
		{"Plain Heading", "plain-heading"},
		{"With: punctuation, here!", "with-punctuation-here"},
		{"  Whitespace  ", "whitespace"},
		{"OAuth2 / OIDC", "oauth2-oidc"},
		{"a -- b", "a-b"},
		{"123 numbers ok", "123-numbers-ok"},
	}
	for _, c := range cases {
		got := slugify(c.text)
		if got != c.anchor {
			t.Errorf("slugify(%q) = %q; want %q", c.text, got, c.anchor)
		}
	}
}

func TestExtractHeadings_BodyIsBetweenHeadings(t *testing.T) {
	in := `## A

alpha-paragraph

## B

beta-paragraph
`
	h := ExtractHeadings(in)
	if !strings.Contains(h[0].Body, "alpha-paragraph") || strings.Contains(h[0].Body, "beta-paragraph") {
		t.Errorf("h[0].Body = %q (should contain alpha but not beta)", h[0].Body)
	}
	if !strings.Contains(h[1].Body, "beta-paragraph") {
		t.Errorf("h[1].Body = %q (should contain beta)", h[1].Body)
	}
}

func TestLeadBody(t *testing.T) {
	in := `# Title

intro paragraph

## First

other content
`
	got := LeadBody(in)
	if !strings.Contains(got, "intro paragraph") {
		t.Errorf("lead body missing intro: %q", got)
	}
	if strings.Contains(got, "other content") {
		t.Errorf("lead body bled into first section: %q", got)
	}
}

func TestLeadBody_NoH2Returns_All(t *testing.T) {
	in := "# Title\n\nonly intro, no sections.\n"
	got := LeadBody(in)
	if !strings.Contains(got, "only intro") {
		t.Errorf("LeadBody dropped content: %q", got)
	}
}
