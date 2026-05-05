package web

import (
	"fmt"
	"strings"
	"unicode"
)

// ExtractHeadings parses markdown body and returns its H2/H3 headings in
// document order, with stable anchor IDs and the plain-text body of each
// section. Headings inside fenced code blocks are skipped.
//
// The slugification rule MUST stay in sync with the client-side script in
// docs.html. Tests cross-check this in docs_toc_test.go.
func ExtractHeadings(body string) []DocHeading {
	lines := strings.Split(body, "\n")

	type rawHead struct {
		level    int
		text     string
		startIdx int // index into `lines` where the heading appears
	}

	var raw []rawHead
	inFence := false
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		// Toggle on triple-backtick fences (matches ``` and ~~~).
		if isFenceMarker(trim) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if strings.HasPrefix(trim, "### ") {
			raw = append(raw, rawHead{level: 3, text: strings.TrimSpace(trim[4:]), startIdx: i})
		} else if strings.HasPrefix(trim, "## ") {
			raw = append(raw, rawHead{level: 2, text: strings.TrimSpace(trim[3:]), startIdx: i})
		}
	}

	// Build anchors with deduplication.
	seen := make(map[string]int)
	out := make([]DocHeading, 0, len(raw))
	for idx, h := range raw {
		anchor := slugify(h.text)
		if anchor == "" {
			anchor = fmt.Sprintf("section-%d", idx+1)
		}
		if seen[anchor] > 0 {
			seen[anchor]++
			anchor = fmt.Sprintf("%s-%d", anchor, seen[anchor])
		} else {
			seen[anchor] = 1
		}
		// Body of this section = lines from after this heading until the next
		// heading (any level >=2). Inline code fences inside the section are
		// preserved as text; SearchPlainText will strip them later.
		end := len(lines)
		for j := idx + 1; j < len(raw); j++ {
			end = raw[j].startIdx
			break
		}
		section := strings.Join(lines[h.startIdx+1:end], "\n")
		out = append(out, DocHeading{
			Level:  h.level,
			Text:   stripTrailingHash(h.text),
			Anchor: anchor,
			Body:   section,
		})
	}
	return out
}

// LeadBody returns the markdown content from the start of body up to (but not
// including) the first H2/H3 heading. This is the "lead section" that has no
// anchor of its own — search results that match it link to /docs/{slug}.
func LeadBody(body string) string {
	lines := strings.Split(body, "\n")
	inFence := false
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if isFenceMarker(trim) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if strings.HasPrefix(trim, "## ") || strings.HasPrefix(trim, "### ") {
			return strings.Join(lines[:i], "\n")
		}
	}
	return body
}

// slugify lowercases text, replaces non-[a-z0-9] runs with "-", trims leading
// and trailing dashes. The client-side slugifier in docs.html is the
// authoritative reference; this Go version mirrors it exactly.
func slugify(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevDash := true // collapse leading non-alphanumerics
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			prevDash = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(unicode.ToLower(r))
			prevDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := b.String()
	return strings.Trim(out, "-")
}

func isFenceMarker(line string) bool {
	if strings.HasPrefix(line, "```") {
		return true
	}
	if strings.HasPrefix(line, "~~~") {
		return true
	}
	return false
}

// stripTrailingHash removes a trailing `#` style heading-anchor that some
// markdown styles include (`## Section ##`). Cosmetic only.
func stripTrailingHash(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasSuffix(s, "#") {
		s = strings.TrimSpace(strings.TrimSuffix(s, "#"))
	}
	return s
}
