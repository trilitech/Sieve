package web

import (
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/policy"
)

// TestParseFilterConfig_ScriptFilter proves the filter form accepts the
// script_filter kind (a post-execution response rewrite) — the kind the
// engine/applier already supported but the authoring UI was missing. It mirrors
// the script_guard parse, so the two can't diverge.
func TestParseFilterConfig_ScriptFilter(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	policy.SetCommandAllowlist([]string{py})
	defer policy.SetCommandAllowlist(nil)

	dir := t.TempDir()
	path := filepath.Join(dir, "scrub.py")
	if err := os.WriteFile(path, []byte("print('{}')"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy.SetScriptDirs([]string{dir})
	defer policy.SetScriptDirs(nil)

	// parseFilterConfig uses no Server fields, so a zero-value receiver is fine.
	s := &Server{}
	form := url.Values{
		"kind":        {"script_filter"},
		"language":    {"python"},
		"script_path": {path},
	}
	r := httptest.NewRequest("POST", "/iam/filters", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}

	kind, config, perr := s.parseFilterConfig(r)
	if perr != nil {
		t.Fatalf("parseFilterConfig rejected script_filter: %s", perr.msg)
	}
	if kind != iam.KindScriptFilter {
		t.Errorf("kind = %q, want script_filter", kind)
	}
	if config["command"] != py {
		t.Errorf("command = %v, want %s", config["command"], py)
	}
	if config["path"] != path {
		t.Errorf("path = %v, want %s", config["path"], path)
	}
	// script_filter falls into the default script rank band (30).
	if got := parseFilterOrder(r, kind); got != 30 {
		t.Errorf("default order for script_filter = %d, want 30", got)
	}
}
