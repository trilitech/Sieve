package web

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Spec 001-fix-security-vulns US5 (Shannon INJ-VULN-06): the json template
// helper used to return template.JS — Go's "this is already-safe JavaScript"
// marker — even though its argument is request-body / DB-column data. That
// pattern is fragile: single quotes pass through unescaped today, and any
// future change to json.MarshalIndent (e.g., SetEscapeHTML(false)) would
// make </script> injection live immediately.
//
// The remediation: the json helper now returns a plain string with
// aggressive HTML/JS-context escaping; templates wrap it in
// <script type="application/json"> and read it via JSON.parse on
// .textContent. template.JS is reserved for static, code-author-written
// JavaScript only.

// TestNoTemplateJSAroundDynamicData fails if any internal/web/*.go file
// still wraps a dynamic value in template.JS(). Static, literal-string
// template.JS wrappers (none today; reserved for code-author snippets)
// would be marked with an explicit `// xss-safe:` annotation.
func TestNoTemplateJSAroundDynamicData(t *testing.T) {
	wrapRE := regexp.MustCompile(`template\.JS\(`)
	literalRE := regexp.MustCompile(`template\.JS\("[^"]*"\)`) // string literal arg only

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		scanner := bufio.NewScanner(strings.NewReader(string(raw)))
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Text()
			if !wrapRE.MatchString(line) {
				continue
			}
			if strings.Contains(line, "// xss-safe:") {
				continue
			}
			if literalRE.MatchString(line) {
				continue
			}
			t.Errorf("%s:%d: template.JS() wraps a non-literal value (use plain string + <script type=\"application/json\">); line: %s",
				f, lineNo, strings.TrimSpace(line))
		}
		if err := scanner.Err(); err != nil {
			t.Fatalf("scan %s: %v", f, err)
		}
	}
}

// TestJSONHelperEscapesScriptTerminator confirms the json template helper
// emits the documented Shannon payload safely. Even if a policy_config
// contains </script>, the rendered output must not let the HTML parser
// terminate the surrounding <script type="application/json"> block.
func TestJSONHelperEscapesScriptTerminator(t *testing.T) {
	fn := funcMap()["json"]
	if fn == nil {
		t.Fatal("json helper missing from funcMap")
	}
	v := map[string]any{
		"payload": "</script><script>alert(1)</script>",
	}
	out := invokeJSONHelper(t, fn, v)
	if strings.Contains(out, "</script>") {
		t.Errorf("json output leaks raw </script>: %s", out)
	}
}

// TestJSONHelperEscapesLineTerminators confirms U+2028 / U+2029 are
// escaped. Embedded via \u escapes — raw codepoints in a single-line
// Go string literal break the lexer.
func TestJSONHelperEscapesLineTerminators(t *testing.T) {
	fn := funcMap()["json"]
	v := map[string]any{
		"payload": "line1\u2028line2\u2029line3",
	}
	out := invokeJSONHelper(t, fn, v)
	if strings.ContainsRune(out, '\u2028') || strings.ContainsRune(out, '\u2029') {
		t.Errorf("json output leaks raw U+2028/U+2029: %q", out)
	}
}

// invokeJSONHelper handles either signature — template.JS (pre-fix) or
// string (post-fix) — so the test compiles against both.
func invokeJSONHelper(t *testing.T, fn any, v any) string {
	t.Helper()
	switch f := fn.(type) {
	case func(any) string:
		return f(v)
	default:
		t.Fatalf("json helper has unexpected signature %T", fn)
		return ""
	}
}
