package web

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTemplatesNoUnsafeInnerHTML enforces a static lint over the admin
// templates: server-derived strings must not be concatenated into
// innerHTML without an explicit per-sink escaper.
// The guard recognizes these safe patterns:
// - Empty-string clears: `el.innerHTML = "";` / `el.innerHTML = ”;`
// - Pure string literals (template-author-controlled): `el.innerHTML = '<div>...</div>';`
// - Lines containing an explicit per-sink escaper invocation:
// `escHtml(`, `escapeHTML(`, or `DOMPurify.sanitize(`
// - Lines (or multi-line expressions) carrying an explicit lint exemption
// comment: `// xss-safe: <reason>` on the same line as the innerHTML assignment.
// Anything else is flagged. The classic attack pattern is
// `el.innerHTML = '<tag>' + serverValue + '</tag>'` with serverValue unescaped
// — a single-line concatenation with no escaper. This guard catches that.
// Multi-line `el.innerHTML = rules.map(function(r) {... }).join("");` patterns
// in policies.html / policy_edit.html have every interpolation escHtml-wrapped
// inside the map; they're annotated with `// xss-safe: escHtml-wrapped` so the
// guard skips them.
func TestTemplatesNoUnsafeInnerHTML(t *testing.T) {
	dir := "templates"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read templates dir: %v", err)
	}

	assignRE := regexp.MustCompile(`\.innerHTML\s*\+?=`)

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Text()
			if !assignRE.MatchString(line) {
				continue
			}
			if innerHTMLLineIsSafe(line) {
				continue
			}
			t.Errorf("%s:%d unsafe innerHTML assignment (add `// xss-safe: <reason>` if intentional): %s",
				path, lineNo, strings.TrimSpace(line))
		}
		f.Close()
		if err := scanner.Err(); err != nil {
			t.Fatalf("scan %s: %v", path, err)
		}
	}
}

// innerHTMLLineIsSafe returns true if a line containing an `innerHTML =` (or
// `+=`) assignment falls into one of the documented safe patterns.
func innerHTMLLineIsSafe(line string) bool {
	// Explicit lint exemption — the template author has attested the line is
	// safe by audit and supplied a reason.
	if strings.Contains(line, "// xss-safe:") {
		return true
	}
	// Per-sink escaper invocation anywhere on the line.
	if strings.Contains(line, "escHtml(") ||
		strings.Contains(line, "escapeHTML(") ||
		strings.Contains(line, "DOMPurify.sanitize(") {
		return true
	}
	// Strip the part up to and including `=` to inspect the RHS.
	idx := strings.Index(line, "innerHTML")
	if idx < 0 {
		return false
	}
	after := line[idx:]
	eqIdx := strings.Index(after, "=")
	if eqIdx < 0 {
		return false
	}
	rhs := strings.TrimSpace(after[eqIdx+1:])
	// Trim inline comments and trailing semicolons.
	if c := strings.Index(rhs, "//"); c >= 0 {
		rhs = strings.TrimSpace(rhs[:c])
	}
	rhs = strings.TrimSuffix(rhs, ";")
	rhs = strings.TrimSpace(rhs)
	// Empty-string clear.
	if rhs == `""` || rhs == `''` {
		return true
	}
	// Pure string literal (no concatenation operators outside the literal).
	if isPureStringLiteral(rhs) {
		return true
	}
	return false
}

// isPureStringLiteral returns true if rhs is a single quoted string literal
// (single or double quotes) with no top-level '+' concatenation.
func isPureStringLiteral(rhs string) bool {
	rhs = strings.TrimSpace(rhs)
	if len(rhs) < 2 {
		return false
	}
	q := rhs[0]
	if q != '\'' && q != '"' {
		return false
	}
	// Walk forward; if we exit the literal before end-of-string, it's not pure.
	for i := 1; i < len(rhs); i++ {
		if rhs[i] == q && rhs[i-1] != '\\' {
			return i == len(rhs)-1
		}
	}
	return false
}
