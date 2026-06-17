package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCSPAllowsTemplateCDNs guards against tightening the CSP in a way
// that breaks the admin UI's design. The bundled templates pull Tailwind,
// htmx, marked + DOMPurify, and Google Fonts from external CDNs; the CSP
// MUST allowlist these hosts in the right directives or the browser
// silently drops the resources and the page renders unstyled.
//
// If you intentionally vendor an asset locally (so it no longer needs the
// external host), drop the corresponding line from this test in the same
// commit that vendors it.
func TestCSPAllowsTemplateCDNs(t *testing.T) {
	w := httptest.NewRecorder()
	writeSecurityHeaders(w)
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("CSP header empty")
	}

	// directive name → host that MUST appear under it
	wants := []struct {
		directive, host string
	}{
		{"script-src", "https://cdn.tailwindcss.com"},
		{"script-src", "https://cdn.jsdelivr.net"},
		{"script-src", "https://unpkg.com"},
		{"style-src", "https://fonts.googleapis.com"},
		{"font-src", "https://fonts.gstatic.com"},
		// Tailwind CDN fetches its CSS at runtime; without connect-src
		// the page loads but stays unstyled.
		{"connect-src", "https://cdn.tailwindcss.com"},
	}
	for _, want := range wants {
		if !cspDirectiveContains(csp, want.directive, want.host) {
			t.Errorf("CSP %q is missing %s in %q", want.host, want.host, want.directive)
		}
	}

	// Sanity: the strict invariants we don't want to lose.
	for _, must := range []string{"object-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, must) {
			t.Errorf("CSP missing required directive %q; got: %s", must, csp)
		}
	}
}

// cspDirectiveContains returns true when the CSP string carries the
// given directive and the directive's source list contains the host.
func cspDirectiveContains(csp, directive, host string) bool {
	for _, part := range strings.Split(csp, ";") {
		p := strings.TrimSpace(part)
		if !strings.HasPrefix(p, directive+" ") && p != directive {
			continue
		}
		sources := strings.TrimPrefix(p, directive)
		for _, src := range strings.Fields(sources) {
			if src == host {
				return true
			}
		}
	}
	return false
}
