package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeScript writes an executable-agnostic /bin/sh script under dir and returns
// its path. The scripts are run as `/bin/sh <path>`, so they don't need +x.
func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestApplyResponseFilters_ScriptTransformFailsClosed is the regression test for
// B1: a script-transform that crashes / exits non-zero / returns no rewrite must
// FAIL CLOSED (return a *ResponseFilterError and the ORIGINAL response), never
// hand back the un-rewritten content. Before the fix, Evaluate surfaced process
// failures as a deny PolicyDecision with a nil error and applyScript fell through
// to "return result unchanged" — a silent fail-open.
func TestApplyResponseFilters_ScriptTransformFailsClosed(t *testing.T) {
	t.Cleanup(func() { SetCommandAllowlist(nil); SetScriptDirs(nil) })
	dir := t.TempDir()
	SetCommandAllowlist([]string{"/bin/sh"})
	SetScriptDirs([]string{dir})

	orig := []byte(`{"body":"ssn 123-45-6789"}`)

	cases := []struct {
		name string
		body string
	}{
		{"nonzero-exit", "exit 3\n"},                          // process failure
		{"deny", `printf '{"action":"deny"}'` + "\n"},         // explicit deny, no rewrite
		{"garbage-stdout", `printf 'not json'` + "\n"},        // unparseable → deny
		{"empty-no-rewrite", `printf '{"action":""}'` + "\n"}, // no decision, no rewrite → deny
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := writeScript(t, dir, tc.name+".sh", tc.body)
			f := ResponseFilter{ScriptCommand: "/bin/sh", ScriptPath: script}
			out, _, err := ApplyResponseFilters(orig, []ResponseFilter{f}, nil)
			var rfe *ResponseFilterError
			if !errors.As(err, &rfe) {
				t.Fatalf("want *ResponseFilterError (fail closed), got err=%v", err)
			}
			if string(out) != string(orig) {
				t.Errorf("on failure the ORIGINAL response must be returned, got %s", out)
			}
		})
	}
}

// TestApplyResponseFilters_ScriptTransformAllowNoRewrite proves a genuine
// {"action":"allow"} with no rewrite is a legit no-op (the script inspected the
// response and chose not to change it) — passthrough unchanged, no error.
func TestApplyResponseFilters_ScriptTransformAllowNoRewrite(t *testing.T) {
	t.Cleanup(func() { SetCommandAllowlist(nil); SetScriptDirs(nil) })
	dir := t.TempDir()
	SetCommandAllowlist([]string{"/bin/sh"})
	SetScriptDirs([]string{dir})

	orig := []byte(`{"body":"nothing secret here"}`)
	script := writeScript(t, dir, "allow.sh", `printf '{"action":"allow"}'`+"\n")
	f := ResponseFilter{ScriptCommand: "/bin/sh", ScriptPath: script}
	out, _, err := ApplyResponseFilters(orig, []ResponseFilter{f}, nil)
	if err != nil {
		t.Fatalf("allow-no-rewrite is a legit no-op, got err=%v", err)
	}
	if string(out) != string(orig) {
		t.Errorf("passthrough should be unchanged, got %s", out)
	}
}

// TestApplyResponseFilters_ScriptTransformRewriteApplied proves a rewrite is
// applied to the response.
func TestApplyResponseFilters_ScriptTransformRewriteApplied(t *testing.T) {
	t.Cleanup(func() { SetCommandAllowlist(nil); SetScriptDirs(nil) })
	dir := t.TempDir()
	SetCommandAllowlist([]string{"/bin/sh"})
	SetScriptDirs([]string{dir})

	script := writeScript(t, dir, "rewrite.sh", `printf '{"rewrite":"{\"body\":\"[scrubbed]\"}"}'`+"\n")
	f := ResponseFilter{ScriptCommand: "/bin/sh", ScriptPath: script}
	out, _, err := ApplyResponseFilters([]byte(`{"body":"ssn 123-45-6789"}`), []ResponseFilter{f}, nil)
	if err != nil {
		t.Fatalf("rewrite should succeed, got %v", err)
	}
	if !strings.Contains(string(out), "[scrubbed]") || strings.Contains(string(out), "123-45-6789") {
		t.Errorf("rewrite not applied: %s", out)
	}
}

// TestApplyResponseFilters_ScriptPathReValidatedAtExec is the regression test for
// M2: a script-transform whose path is NOT under the allowlisted scripts dir must
// fail closed at execution time (defense-in-depth), even if it was somehow saved.
func TestApplyResponseFilters_ScriptPathReValidatedAtExec(t *testing.T) {
	t.Cleanup(func() { SetCommandAllowlist(nil); SetScriptDirs(nil) })
	allowed := t.TempDir()
	elsewhere := t.TempDir()
	SetCommandAllowlist([]string{"/bin/sh"})
	SetScriptDirs([]string{allowed}) // script lives elsewhere, not here

	script := writeScript(t, elsewhere, "evil.sh", `printf '{"rewrite":"pwned"}'`+"\n")
	f := ResponseFilter{ScriptCommand: "/bin/sh", ScriptPath: script}
	orig := []byte(`{"body":"secret"}`)
	out, _, err := ApplyResponseFilters(orig, []ResponseFilter{f}, nil)
	var rfe *ResponseFilterError
	if !errors.As(err, &rfe) {
		t.Fatalf("out-of-allowlist script path must fail closed, got err=%v", err)
	}
	if string(out) != string(orig) {
		t.Errorf("original response must be returned on fail-closed, got %s", out)
	}
	if strings.Contains(string(out), "pwned") {
		t.Errorf("out-of-allowlist script must not have executed")
	}
}

// TestApplyResponseFilters_UncompilableRegexFailsClosed is the regression test
// for M1: a redact pattern that won't compile must FAIL CLOSED (withhold the
// response), not silently skip the pattern and leak the content it targeted.
func TestApplyResponseFilters_UncompilableRegexFailsClosed(t *testing.T) {
	orig := []byte(`{"body":"card 4111111111111111"}`)

	// redact
	out, _, err := ApplyResponseFilters(orig, []ResponseFilter{
		{RedactPatterns: []string{`(unterminated`}, Match: "regex"},
	}, []string{"body"})
	var rfe *ResponseFilterError
	if !errors.As(err, &rfe) {
		t.Fatalf("uncompilable redact regex must fail closed, got err=%v", err)
	}
	if string(out) != string(orig) {
		t.Errorf("failed redact must return the original (caller withholds it), got %s", out)
	}

	// exclude
	_, _, err = ApplyResponseFilters([]byte(`{"messages":[{"body":"x"}]}`), []ResponseFilter{
		{ExcludePatterns: []string{`[`}, Match: "regex"},
	}, []string{"body"})
	if !errors.As(err, &rfe) {
		t.Fatalf("uncompilable exclude regex must fail closed, got err=%v", err)
	}
}

// TestApplyResponseFilters_ExcludeClosesCountAndCursorSideChannels is the
// regression test for M5: excluding items from a Gmail-shaped response must
// decrement resultSizeEstimate and clear the pagination cursor, so an agent
// can't infer the withheld count or page around the exclusion.
func TestApplyResponseFilters_ExcludeClosesCountAndCursorSideChannels(t *testing.T) {
	body := []byte(`{"messages":[{"from":"a@vendor.com"},{"from":"b@ok.com"}],"resultSizeEstimate":2,"nextPageToken":"abc"}`)
	out, _, err := ApplyResponseFilters(body, []ResponseFilter{
		{ExcludePatterns: []string{"vendor.com"}, Match: "contains"},
	}, []string{"from"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "vendor.com") {
		t.Errorf("matching item should be dropped: %s", s)
	}
	if strings.Contains(s, `"resultSizeEstimate":2`) {
		t.Errorf("resultSizeEstimate must be decremented (leaks withheld count): %s", s)
	}
	if !strings.Contains(s, `"resultSizeEstimate":1`) {
		t.Errorf("resultSizeEstimate should be 1 after dropping 1 of 2: %s", s)
	}
	if strings.Contains(s, "nextPageToken") {
		t.Errorf("pagination cursor must be cleared: %s", s)
	}
}

// TestApplyResponseFilters_ExcludeAllSerializesEmptyArray is minor (a): removing
// every item yields [] not null (so array-expecting clients don't break).
func TestApplyResponseFilters_ExcludeAllSerializesEmptyArray(t *testing.T) {
	body := []byte(`{"messages":[{"from":"a@vendor.com"},{"from":"b@vendor.com"}]}`)
	out, _, err := ApplyResponseFilters(body, []ResponseFilter{
		{ExcludePatterns: []string{"vendor.com"}, Match: "contains"},
	}, []string{"from"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"messages":[]`) {
		t.Errorf("all-removed list should serialise as [], got %s", out)
	}
}

// TestApplyResponseFilters_WholeResponseExcludeTopLevelArray is minor (b): a
// whole-response exclude drops matching items from a top-level JSON array root,
// rather than treating it as an opaque blob (no-op) or nuking the whole body.
func TestApplyResponseFilters_WholeResponseExcludeTopLevelArray(t *testing.T) {
	body := []byte(`[{"from":"a@vendor.com"},{"from":"b@ok.com"}]`)
	out, _, err := ApplyResponseFilters(body, []ResponseFilter{
		{ExcludePatterns: []string{"vendor.com"}, Match: "contains"},
	}, nil) // nil ⇒ whole-response path
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "vendor.com") {
		t.Errorf("matching element should be dropped from top-level array: %s", s)
	}
	if !strings.Contains(s, "b@ok.com") {
		t.Errorf("non-matching element should remain: %s", s)
	}
}
