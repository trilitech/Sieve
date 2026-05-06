package web

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSearchPlainText_DropsCodeFence(t *testing.T) {
	in := "before\n\n```\ncode that should not be searched\n```\n\nafter"
	got := SearchPlainText(in)
	if strings.Contains(got, "code that") {
		t.Errorf("plaintext contained fenced code: %q", got)
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Errorf("plaintext missing surrounding paragraphs: %q", got)
	}
}

func TestSearchPlainText_KeepsLinkText(t *testing.T) {
	in := "see [policy scripts](./policy-scripts.md) for details"
	got := SearchPlainText(in)
	if !strings.Contains(got, "policy scripts") {
		t.Errorf("link text dropped: %q", got)
	}
	if strings.Contains(got, "policy-scripts.md") {
		t.Errorf("link URL leaked into plaintext: %q", got)
	}
}

func TestSearchPlainText_KeepsImageAlt(t *testing.T) {
	in := "![architecture diagram](/img/arch.png)"
	got := SearchPlainText(in)
	if !strings.Contains(got, "architecture diagram") {
		t.Errorf("image alt dropped: %q", got)
	}
	if strings.Contains(got, "/img/arch.png") {
		t.Errorf("image URL leaked: %q", got)
	}
}

func TestSearchPlainText_StripsEmphasis(t *testing.T) {
	cases := []struct{ in, want string }{
		{"**bold word**", "bold word"},
		{"*italic word*", "italic word"},
		{"__bolder__", "bolder"},
		{"_emph_", "emph"},
	}
	for _, c := range cases {
		got := SearchPlainText(c.in)
		if got != c.want {
			t.Errorf("SearchPlainText(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestSearchPlainText_StripsHeadingsAndBullets(t *testing.T) {
	in := "# Title\n\n## Section\n\n- one\n- two\n- three\n\n> a quoted line"
	got := SearchPlainText(in)
	if strings.Contains(got, "##") || strings.Contains(got, "- ") || strings.Contains(got, "> ") {
		t.Errorf("structural markers leaked: %q", got)
	}
	for _, w := range []string{"Title", "Section", "one", "two", "three", "a quoted line"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing word %q in %q", w, got)
		}
	}
}

func TestSearchPlainText_CollapsesWhitespace(t *testing.T) {
	in := "a\n\n\nb\t\tc"
	got := SearchPlainText(in)
	if got != "a b c" {
		t.Errorf("expected single-spaced output, got %q", got)
	}
}

func TestBuildSearchIndex_Shape(t *testing.T) {
	idx := DocNavIndex{
		Categories: []DocCategoryView{
			{
				Category: DocCategory{ID: "cat", Title: "Cat", Order: 1},
				Pages: []DocPage{
					{Slug: "alpha", Title: "Alpha", CategoryID: "cat"},
				},
			},
		},
	}
	m := DocManifest{
		Descriptions:  map[string]string{"alpha": "alpha description"},
		FallbackID:    "ref",
		FallbackOrder: 99,
	}
	read := func(slug string) (string, error) {
		return "# Alpha\n\nintro paragraph.\n\n## First Heading\n\nbody under first.\n\n## Second\n\nbody under second.", nil
	}
	raw, err := BuildSearchIndex(idx, m, read)
	if err != nil {
		t.Fatalf("BuildSearchIndex: %v", err)
	}
	var parsed SearchCorpus
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Version != 1 {
		t.Errorf("version = %d; want 1", parsed.Version)
	}
	if len(parsed.Pages) != 1 {
		t.Fatalf("expected 1 page entry, got %d", len(parsed.Pages))
	}
	p := parsed.Pages[0]
	if p.Slug != "alpha" || p.Title != "Alpha" || p.Description != "alpha description" || p.Category != "Cat" || p.CategoryID != "cat" {
		t.Errorf("page metadata wrong: %+v", p)
	}
	// Sections: implicit lead + 2 H2.
	if len(p.Sections) != 3 {
		t.Fatalf("expected 3 sections (1 lead + 2 H2), got %d (%+v)", len(p.Sections), p.Sections)
	}
	if p.Sections[0].Anchor != "" || p.Sections[0].Heading != "" {
		t.Errorf("lead section should have empty anchor/heading: %+v", p.Sections[0])
	}
	if !strings.Contains(p.Sections[0].Body, "intro paragraph") {
		t.Errorf("lead body wrong: %q", p.Sections[0].Body)
	}
	if p.Sections[1].Anchor != "first-heading" || p.Sections[1].Heading != "First Heading" {
		t.Errorf("section 1 wrong: %+v", p.Sections[1])
	}
	if !strings.Contains(p.Sections[1].Body, "body under first") {
		t.Errorf("section 1 body wrong: %q", p.Sections[1].Body)
	}
}

func TestBuildSearchIndex_HiddenPagesExcluded(t *testing.T) {
	idx := DocNavIndex{
		Categories: []DocCategoryView{
			{
				Category: DocCategory{ID: "cat", Title: "Cat"},
				Pages: []DocPage{
					{Slug: "shown", Title: "Shown"},
					{Slug: "hush", Title: "Hush", Hidden: true},
				},
			},
		},
	}
	m := DocManifest{}
	read := func(slug string) (string, error) { return "# H\n\nbody", nil }
	raw, _ := BuildSearchIndex(idx, m, read)
	var c SearchCorpus
	_ = json.Unmarshal(raw, &c)
	for _, p := range c.Pages {
		if p.Slug == "hush" {
			t.Fatalf("hidden page leaked into search corpus")
		}
	}
}
