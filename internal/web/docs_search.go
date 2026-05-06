package web

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// SearchPlainText converts markdown body to whitespace-collapsed plaintext
// suitable for substring search. Drops fenced code blocks, image syntax,
// link syntax (keeping the visible text), inline code backticks, emphasis
// markers, list bullets, blockquote markers, and heading markers.
func SearchPlainText(md string) string {
	// Strip fenced code blocks first (anywhere from ``` to ``` on its own line).
	var b strings.Builder
	inFence := false
	for _, line := range strings.Split(md, "\n") {
		trim := strings.TrimSpace(line)
		if isFenceMarker(trim) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	s := b.String()

	// Image syntax: ![alt](url) → alt
	s = reImage.ReplaceAllString(s, "$1")
	// Link syntax: [text](url) → text
	s = reLink.ReplaceAllString(s, "$1")
	// Inline code: `code` → code
	s = reInlineCode.ReplaceAllString(s, "$1")
	// Bold/italic markers: **bold**, *italic*, __bold__, _italic_
	s = reEmphasis.ReplaceAllString(s, "$1")
	// Heading markers at line start: ## foo → foo
	s = reHeadingMarker.ReplaceAllString(s, "$1")
	// List bullets / blockquote markers at line start.
	s = reListBullet.ReplaceAllString(s, "$1")
	s = reBlockQuote.ReplaceAllString(s, "$1")

	// Collapse whitespace runs to a single space.
	s = strings.TrimSpace(reWhitespace.ReplaceAllString(s, " "))
	return s
}

var (
	reImage         = regexp.MustCompile(`!\[([^\]]*)\]\([^)]*\)`)
	reLink          = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
	reInlineCode    = regexp.MustCompile("`([^`]+)`")
	reEmphasis      = regexp.MustCompile(`(?:\*\*|__|\*|_)([^*_\n]+)(?:\*\*|__|\*|_)`)
	reHeadingMarker = regexp.MustCompile(`(?m)^#{1,6}\s+(.*)$`)
	reListBullet    = regexp.MustCompile(`(?m)^[ \t]*(?:[-*+]|\d+\.)\s+(.*)$`)
	reBlockQuote    = regexp.MustCompile(`(?m)^[ \t]*>\s?(.*)$`)
	reWhitespace    = regexp.MustCompile(`\s+`)
)

// SearchSection is one entry in the search corpus per heading.
type SearchSection struct {
	Anchor  string `json:"anchor"`
	Heading string `json:"heading"`
	Body    string `json:"body"`
}

// SearchEntry is the per-page record exposed to the client matcher.
type SearchEntry struct {
	Slug        string          `json:"slug"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Category    string          `json:"category"`
	CategoryID  string          `json:"categoryId"`
	Sections    []SearchSection `json:"sections"`
}

// SearchCorpus is the top-level JSON shape — see contracts/search-index.json.md.
type SearchCorpus struct {
	Version     int           `json:"version"`
	GeneratedAt string        `json:"generatedAt"`
	Pages       []SearchEntry `json:"pages"`
}

// BuildSearchIndex builds the search corpus by walking every visible page in
// idx, fetching its body via readBody, and slicing by H2/H3 boundaries. The
// returned bytes are JSON safe to embed inside a <script type="application/json">.
func BuildSearchIndex(idx DocNavIndex, m DocManifest, readBody func(slug string) (string, error)) ([]byte, error) {
	corpus := SearchCorpus{
		Version:     1,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Pages:       make([]SearchEntry, 0),
	}

	for _, view := range idx.Categories {
		for _, p := range view.Pages {
			if p.Hidden {
				continue
			}
			body, err := readBody(p.Slug)
			if err != nil {
				continue
			}
			sections := []SearchSection{
				{
					Anchor:  "",
					Heading: "",
					Body:    SearchPlainText(LeadBody(body)),
				},
			}
			for _, h := range ExtractHeadings(body) {
				sections = append(sections, SearchSection{
					Anchor:  h.Anchor,
					Heading: h.Text,
					Body:    SearchPlainText(h.Body),
				})
			}
			corpus.Pages = append(corpus.Pages, SearchEntry{
				Slug:        p.Slug,
				Title:       p.Title,
				Description: m.Descriptions[p.Slug],
				Category:    view.Category.Title,
				CategoryID:  view.Category.ID,
				Sections:    sections,
			})
		}
	}

	return json.Marshal(corpus)
}
