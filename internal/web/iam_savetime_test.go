package web

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestParseFilterConfig_RejectsBadRegex proves a redact/exclude definition with
// an uncompilable regex pattern is rejected at save time, so a malformed
// protective pattern can't be stored (complements the apply-time fail-closed).
func TestParseFilterConfig_RejectsBadRegex(t *testing.T) {
	s := &Server{} // parseFilterConfig uses no Server fields
	form := url.Values{
		"kind":     {"redact"},
		"patterns": {"(unclosed"}, // invalid regexp
		"match":    {"regex"},
	}
	r := httptest.NewRequest("POST", "/iam/filters", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if _, _, perr := s.parseFilterConfig(r); perr == nil {
		t.Fatal("an uncompilable regex pattern must be rejected at save time")
	}

	// A valid regex is accepted.
	form.Set("patterns", `\d{3}-\d{2}-\d{4}`)
	r2 := httptest.NewRequest("POST", "/iam/filters", strings.NewReader(form.Encode()))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r2.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if _, _, perr := s.parseFilterConfig(r2); perr != nil {
		t.Fatalf("a valid regex pattern must be accepted, got: %s", perr.msg)
	}
}

// TestReferencesRoleGroup guards the raw-Cedar role-group reject: a policy scoped
// to a RoleGroup principal never matches at runtime (the PIP populates no group
// edges), so the save path rejects it rather than storing a silently-dead policy.
func TestReferencesRoleGroup(t *testing.T) {
	if !referencesRoleGroup(`permit(principal in Sieve::RoleGroup::"admins", action, resource);`) {
		t.Error("a RoleGroup-scoped policy must be flagged")
	}
	if referencesRoleGroup(`permit(principal in Sieve::Role::"r1", action, resource);`) {
		t.Error("a Role-scoped policy must NOT be flagged")
	}
}
