package web

import (
	"html/template"
	"regexp"
	"strings"
)

// linkifyRe matches URLs in operator-facing help text: explicit http(s)://
// and www. URLs, plus bare hostnames like "notion.so/my-integrations" or
// "console.anthropic.com". The bare-host arm requires at least one dotted
// label and a ≥2-letter TLD, so IP/CIDR fragments ("127.0.0.0/8") and
// abbreviations ("e.g.") are NOT matched.
var linkifyRe = regexp.MustCompile(
	`https?://[^\s<>"]+` +
		`|www\.[^\s<>"]+` +
		`|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:/[^\s<>"]*)?`,
)

// linkTrailing is trailing punctuation that is almost always sentence
// punctuation rather than part of the URL, so it's moved outside the anchor.
const linkTrailing = ".,;:!?)]}'\""

// linkifyText renders help text with URLs/bare hostnames turned into clickable
// links. Every non-link span and the visible link text are HTML-escaped, so
// the result is safe to emit as template.HTML. Input is developer-authored
// connector help text (not user input), but the escaping keeps it robust.
func linkifyText(s string) template.HTML {
	var b strings.Builder
	last := 0
	for _, m := range linkifyRe.FindAllStringIndex(s, -1) {
		start, end := m[0], m[1]
		b.WriteString(template.HTMLEscapeString(s[last:start]))

		match := s[start:end]
		trailing := ""
		for len(match) > 0 && strings.ContainsRune(linkTrailing, rune(match[len(match)-1])) {
			trailing = match[len(match)-1:] + trailing
			match = match[:len(match)-1]
		}
		if match == "" {
			b.WriteString(template.HTMLEscapeString(s[start:end]))
			last = end
			continue
		}

		href := match
		if !strings.HasPrefix(href, "http://") && !strings.HasPrefix(href, "https://") {
			href = "https://" + href
		}
		b.WriteString(`<a href="`)
		b.WriteString(template.HTMLEscapeString(href))
		b.WriteString(`" target="_blank" rel="noopener noreferrer" class="text-indigo-400 hover:text-indigo-300 underline">`)
		b.WriteString(template.HTMLEscapeString(match))
		b.WriteString(`</a>`)
		b.WriteString(template.HTMLEscapeString(trailing))
		last = end
	}
	b.WriteString(template.HTMLEscapeString(s[last:]))
	return template.HTML(b.String())
}
