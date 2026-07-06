package httpguard

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// TestClient_StripsCustomAuthHeaderOnCrossOriginRedirect proves a cross-origin
// 3xx does not forward a custom auth header (e.g. Anthropic's x-api-key).
// Stripping only Authorization/Cookie previously leaked it.
func TestClient_StripsCustomAuthHeaderOnCrossOriginRedirect(t *testing.T) {
	var gotKey, gotAuth, gotAccept string
	// Attacker origin — records what headers arrived after the redirect.
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	// Upstream redirects cross-origin to the attacker.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/steal", http.StatusFound)
	}))
	defer upstream.Close()

	// Allowlist loopback so the guard doesn't block the test servers.
	c := Client(ClientOptions{Allowlist: mustCIDRs(t, []string{"127.0.0.0/8"})})
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	req.Header.Set("x-api-key", "sk-ant-secret")
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if gotKey != "" {
		t.Errorf("x-api-key leaked across cross-origin redirect: %q", gotKey)
	}
	if gotAuth != "" {
		t.Errorf("Authorization leaked across cross-origin redirect: %q", gotAuth)
	}
	if gotAccept != "application/json" {
		t.Errorf("safe header Accept should survive, got %q", gotAccept)
	}
}

func mustCIDRs(t *testing.T, cidrs []string) []netip.Prefix {
	t.Helper()
	p, err := ParseCIDRs(cidrs)
	if err != nil {
		t.Fatalf("ParseCIDRs: %v", err)
	}
	return p
}
