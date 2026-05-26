package httpguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"
)

// withResolver temporarily replaces the package-level resolver for one test.
// Used to drive table cases without making real DNS calls.
func withResolver(t *testing.T, fn func(context.Context, string) ([]netip.Addr, error)) {
	t.Helper()
	old := resolveIPs
	resolveIPs = fn
	t.Cleanup(func() { resolveIPs = old })
}

// resolveTo returns a stub resolver that always returns the supplied IPs for
// the named host. Other hosts return ErrUnresolvable.
func resolveTo(host string, ips ...string) func(context.Context, string) ([]netip.Addr, error) {
	return func(_ context.Context, h string) ([]netip.Addr, error) {
		if h != host {
			return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
		}
		out := make([]netip.Addr, 0, len(ips))
		for _, s := range ips {
			out = append(out, netip.MustParseAddr(s))
		}
		return out, nil
	}
}

// must wraps a netip.ParsePrefix; tests use this to keep table rows terse.
func must(p string) netip.Prefix { return netip.MustParsePrefix(p) }

// ---- ValidateURL ----------------------------------------------------------

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		ips       []string
		allowlist []netip.Prefix
		wantErr   error // expected sentinel, nil = success
	}{
		// Scheme deny
		{"file scheme", "file:///etc/passwd", nil, nil, ErrSchemeDisallowed},
		{"gopher scheme", "gopher://example.test/foo", nil, nil, ErrSchemeDisallowed},
		{"data scheme", "data:text/plain;base64,QUFB", nil, nil, ErrSchemeDisallowed},
		{"ftp scheme", "ftp://example.test/x", nil, nil, ErrSchemeDisallowed},

		// Absolute deny (cloud metadata)
		{"IPv4 metadata", "http://example.test/foo", []string{"169.254.169.254"}, nil, ErrMetadataAbsoluteDeny},
		{"IPv6 metadata", "http://example.test/foo", []string{"fd00:ec2::254"}, nil, ErrMetadataAbsoluteDeny},
		{"metadata not overridable", "http://example.test/foo", []string{"169.254.169.254"},
			[]netip.Prefix{must("169.254.169.254/32")}, ErrMetadataAbsoluteDeny},

		// Default deny without allowlist
		{"loopback IPv4", "http://example.test/foo", []string{"127.0.0.1"}, nil, ErrPrivateRangeDenied},
		{"RFC1918 10/8", "http://example.test/foo", []string{"10.0.0.5"}, nil, ErrPrivateRangeDenied},
		{"RFC1918 172.16/12", "http://example.test/foo", []string{"172.16.1.1"}, nil, ErrPrivateRangeDenied},
		{"RFC1918 192.168/16", "http://example.test/foo", []string{"192.168.1.1"}, nil, ErrPrivateRangeDenied},
		{"link-local IPv4", "http://example.test/foo", []string{"169.254.1.5"}, nil, ErrPrivateRangeDenied},
		{"multicast IPv4", "http://example.test/foo", []string{"224.0.0.1"}, nil, ErrPrivateRangeDenied},
		{"unspecified IPv4", "http://example.test/foo", []string{"0.0.0.0"}, nil, ErrPrivateRangeDenied},
		{"loopback IPv6", "http://example.test/foo", []string{"::1"}, nil, ErrPrivateRangeDenied},
		{"unique-local IPv6", "http://example.test/foo", []string{"fc00::1"}, nil, ErrPrivateRangeDenied},
		{"link-local IPv6", "http://example.test/foo", []string{"fe80::1"}, nil, ErrPrivateRangeDenied},
		{"IPv4-mapped IPv6 private", "http://example.test/foo", []string{"::ffff:10.0.0.5"}, nil, ErrPrivateRangeDenied},

		// Default deny WITH allowlist
		{"loopback allowed by allowlist", "http://example.test/foo", []string{"127.0.0.1"},
			[]netip.Prefix{must("127.0.0.0/8")}, nil},
		{"intranet allowed by allowlist /32", "http://example.test/foo", []string{"10.0.0.5"},
			[]netip.Prefix{must("10.0.0.5/32")}, nil},
		{"intranet allowed by allowlist /16", "http://example.test/foo", []string{"10.0.0.5"},
			[]netip.Prefix{must("10.0.0.0/16")}, nil},
		{"intranet NOT allowed by sibling /32", "http://example.test/foo", []string{"10.0.0.6"},
			[]netip.Prefix{must("10.0.0.5/32")}, ErrPrivateRangeDenied},

		// Public IPs always allowed
		{"public IPv4", "http://example.test/foo", []string{"93.184.216.34"}, nil, nil},
		{"public IPv6", "http://example.test/foo", []string{"2606:2800:220:1::1"}, nil, nil},

		// HTTPS works too
		{"public IPv4 https", "https://example.test/foo", []string{"93.184.216.34"}, nil, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.ips) > 0 {
				withResolver(t, resolveTo("example.test", tc.ips...))
			}
			u, _ := url.Parse(tc.raw)
			err := ValidateURL(context.Background(), u, tc.allowlist)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateURL(%s) = %v, want nil", tc.raw, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateURL(%s) = %v, want %v", tc.raw, err, tc.wantErr)
			}
		})
	}
}

func TestValidateURLEmptyHost(t *testing.T) {
	u, _ := url.Parse("http:///nopath")
	if err := ValidateURL(context.Background(), u, nil); err == nil {
		t.Fatal("expected error on empty host")
	}
}

func TestValidateURLResolverFailure(t *testing.T) {
	withResolver(t, func(_ context.Context, _ string) ([]netip.Addr, error) {
		return nil, errors.New("dns broken")
	})
	u, _ := url.Parse("http://example.test/foo")
	if err := ValidateURL(context.Background(), u, nil); err == nil {
		t.Fatal("expected resolver failure to surface as error")
	}
}

// ---- Client construction + DialContext -----------------------------------

func TestClientRefusesLiteralPrivateIP(t *testing.T) {
	c := Client(ClientOptions{Timeout: 2 * time.Second})
	req, _ := http.NewRequest("GET", "http://10.0.0.5/", nil)
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected refusal for literal private IP, got success")
	}
	if !errors.Is(unwrapURLError(err), ErrPrivateRangeDenied) {
		t.Errorf("got %v, want ErrPrivateRangeDenied", err)
	}
}

func TestClientAllowsLiteralPrivateIPWhenAllowlisted(t *testing.T) {
	// Spin up a local listener on loopback; dial via allowlist for 127/8.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()
	c := Client(ClientOptions{
		Timeout:   2 * time.Second,
		Allowlist: []netip.Prefix{must("127.0.0.0/8")},
	})
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected success with loopback allowlist: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Errorf("status=%d, want 204", resp.StatusCode)
	}
}

// ---- CheckRedirect — chain cap, deny-list, credential strip --------------

func TestCheckRedirectChainCap(t *testing.T) {
	// Build a server that always redirects to itself.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/next", http.StatusFound)
	}))
	defer srv.Close()

	c := Client(ClientOptions{
		Timeout:     2 * time.Second,
		RedirectCap: 3,
		Allowlist:   []netip.Prefix{must("127.0.0.0/8")},
	})
	_, err := c.Get(srv.URL)
	if err == nil {
		t.Fatal("expected redirect-chain-exceeded error")
	}
	if !errors.Is(unwrapURLError(err), ErrRedirectChainExceeded) {
		t.Errorf("got %v, want ErrRedirectChainExceeded", err)
	}
}

func TestCheckRedirectMetadataDenied(t *testing.T) {
	// Server that redirects to the cloud-metadata IP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	// Allowlist 169.254.169.254/32 to confirm even that doesn't unlock it.
	c := Client(ClientOptions{
		Timeout: 2 * time.Second,
		Allowlist: []netip.Prefix{
			must("127.0.0.0/8"),
			must("169.254.169.254/32"),
		},
	})
	_, err := c.Get(srv.URL)
	if err == nil {
		t.Fatal("expected metadata-deny on redirect")
	}
	if !errors.Is(unwrapURLError(err), ErrMetadataAbsoluteDeny) {
		t.Errorf("got %v, want ErrMetadataAbsoluteDeny", err)
	}
}

func TestCheckRedirectStripsCredentialsCrossOrigin(t *testing.T) {
	// Two servers; the second records the headers it sees. The first
	// redirects to the second's URL.
	var seenAuth, seenCookie string
	var mu sync.Mutex
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seenAuth = r.Header.Get("Authorization")
		seenCookie = r.Header.Get("Cookie")
		w.WriteHeader(204)
	}))
	defer dest.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL+"/", http.StatusFound)
	}))
	defer src.Close()

	c := Client(ClientOptions{
		Timeout:   2 * time.Second,
		Allowlist: []netip.Prefix{must("127.0.0.0/8")},
	})
	req, _ := http.NewRequest("GET", src.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "sieve_session=abc")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	// src and dest are both 127.0.0.1 but on different ports — different
	// origins by httpguard's definition. Headers should have been stripped.
	mu.Lock()
	defer mu.Unlock()
	if seenAuth != "" {
		t.Errorf("Authorization leaked across origin: %q", seenAuth)
	}
	if seenCookie != "" {
		t.Errorf("Cookie leaked across origin: %q", seenCookie)
	}
}

func TestCheckRedirectKeepsCredentialsSameOrigin(t *testing.T) {
	var seenAuth string
	var mu sync.Mutex
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, srv.URL+"/end", http.StatusFound)
			return
		}
		mu.Lock()
		seenAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(204)
	}))
	defer srv.Close()

	c := Client(ClientOptions{
		Timeout:   2 * time.Second,
		Allowlist: []netip.Prefix{must("127.0.0.0/8")},
	})
	req, _ := http.NewRequest("GET", srv.URL+"/start", nil)
	req.Header.Set("Authorization", "Bearer same-origin-ok")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if seenAuth != "Bearer same-origin-ok" {
		t.Errorf("Authorization dropped on same-origin redirect (got %q)", seenAuth)
	}
}

// ---- DNS rebinding -------------------------------------------------------

func TestDNSRebindingProtection(t *testing.T) {
	// Stub resolver returns a private IP. The DialContext should refuse
	// before the dial fires.
	withResolver(t, resolveTo("attacker.test", "10.0.0.5"))

	c := Client(ClientOptions{Timeout: 1 * time.Second})
	req, _ := http.NewRequest("GET", "http://attacker.test/", nil)
	_, err := c.Do(req)
	if err == nil {
		t.Fatal("expected DNS rebinding refusal")
	}
	if !errors.Is(unwrapURLError(err), ErrPrivateRangeDenied) {
		t.Errorf("got %v, want ErrPrivateRangeDenied", err)
	}
}

func TestDNSRebindingHonoredByAllowlist(t *testing.T) {
	// Set up a real loopback listener. Stub resolver returns 127.0.0.1
	// for an arbitrary hostname; allowlist covers 127/8.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()
	// Extract the port from srv.URL so we can dial the same listener via a
	// different hostname.
	u, _ := url.Parse(srv.URL)
	withResolver(t, resolveTo("loopback.test", "127.0.0.1"))

	c := Client(ClientOptions{
		Timeout:   2 * time.Second,
		Allowlist: []netip.Prefix{must("127.0.0.0/8")},
	})
	resp, err := c.Get("http://loopback.test:" + u.Port() + "/")
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Errorf("status=%d", resp.StatusCode)
	}
}

// ---- LogRefusal -----------------------------------------------------------

func TestLogRefusalCallback(t *testing.T) {
	var refused []string
	var mu sync.Mutex
	c := Client(ClientOptions{
		Timeout: 1 * time.Second,
		LogRefusal: func(reason, dest string) {
			mu.Lock()
			defer mu.Unlock()
			refused = append(refused, reason+"|"+dest)
		},
	})
	req, _ := http.NewRequest("GET", "http://10.0.0.5/", nil)
	_, _ = c.Do(req)
	mu.Lock()
	defer mu.Unlock()
	if len(refused) == 0 {
		t.Fatal("LogRefusal was never invoked")
	}
}

// ---- ParseCIDRs ----------------------------------------------------------

func TestParseCIDRs(t *testing.T) {
	got, err := ParseCIDRs([]string{"10.0.0.5/32", "192.168.0.0/16", "  ", ""})
	if err != nil {
		t.Fatalf("ParseCIDRs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2", len(got))
	}
	if _, err := ParseCIDRs([]string{"not-a-cidr"}); err == nil {
		t.Fatal("expected error on invalid CIDR")
	}
}

// ---- helpers --------------------------------------------------------------

// unwrapURLError peels off the *url.Error wrapper that net/http returns from
// Do() so tests can assert on the underlying sentinel.
func unwrapURLError(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}
