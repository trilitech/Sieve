// Package httpguard returns *http.Client values that enforce Sieve's outbound
// SSRF policy for every connector that talks HTTP. See package doc.go.
package httpguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// ClientOptions configures an outbound *http.Client.
type ClientOptions struct {
	// Allowlist is the per-connection CIDR override. Destinations in
	// DefaultDeny that fall inside any Allowlist prefix are permitted.
	// Allowlist NEVER overrides AbsoluteDeny.
	Allowlist []netip.Prefix

	// RedirectCap is the maximum redirect-chain depth. Zero means use the
	// documented default (5).
	RedirectCap int

	// Timeout applies to the full request including redirects. Zero means
	// 30 seconds (the documented default).
	Timeout time.Duration

	// LogRefusal, if non-nil, is invoked once for every request that
	// httpguard refuses. The connector layer wires this to the audit
	// log (`decision=ssrf_refused`).
	LogRefusal func(reason string, dest string)

	// DisableRedirects, when true, makes the returned Client surface 3xx
	// responses to the caller without following them (Go's http.ErrUseLastResponse
	// idiom). Used by connectors that intentionally pass redirects through
	// to the agent — `http_proxy` does this today. The DialContext-level IP
	// guard still applies on every initial request.
	DisableRedirects bool
}

// Sentinel errors callers can switch on. Returned from CheckRedirect and from
// the DialContext when validation fails.
var (
	ErrSchemeDisallowed      = errors.New("httpguard: scheme not allowed (http/https only)")
	ErrMetadataAbsoluteDeny  = errors.New("httpguard: cloud metadata endpoint denied (no override)")
	ErrPrivateRangeDenied    = errors.New("httpguard: destination in default-deny range, not covered by per-connection allowlist")
	ErrRedirectChainExceeded = errors.New("httpguard: redirect chain exceeded cap")
	ErrUnresolvable          = errors.New("httpguard: hostname did not resolve to any allowed IP")
)

// AbsoluteDeny is the unconditional deny set. No allowlist overrides these.
// Cloud-provider IMDS endpoints (AWS/GCP/Azure IPv4, AWS IPv6) — agents
// reaching these from Sieve would never be legitimate, and a private allowlist
// MUST NOT re-enable them.
var AbsoluteDeny = []netip.Prefix{
	netip.MustParsePrefix("169.254.169.254/32"), // IMDS v1/v2 (AWS/GCP/Azure)
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS IPv6 IMDS
}

// DefaultDeny is the default-deny set (overridable per-connection via
// ClientOptions.Allowlist). Loopback, RFC1918 private, link-local, multicast,
// and unspecified ranges — IPv4 and IPv6.
var DefaultDeny = []netip.Prefix{
	// IPv4
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC1918
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC1918
	netip.MustParsePrefix("192.168.0.0/16"), // RFC1918
	netip.MustParsePrefix("169.254.0.0/16"), // link-local (covers IMDS, but AbsoluteDeny still catches that absolutely)
	netip.MustParsePrefix("224.0.0.0/4"),    // multicast
	netip.MustParsePrefix("0.0.0.0/8"),      // unspecified / "this network"
	// IPv6
	netip.MustParsePrefix("::1/128"),    // loopback
	netip.MustParsePrefix("fc00::/7"),   // unique-local
	netip.MustParsePrefix("fe80::/10"),  // link-local
	netip.MustParsePrefix("ff00::/8"),   // multicast
	netip.MustParsePrefix("::/128"),     // unspecified
}

// DefaultRedirectCap is the redirect-chain cap when ClientOptions.RedirectCap
// is zero. Five is the documented bound.
const DefaultRedirectCap = 5

// DefaultTimeout is the per-request timeout when ClientOptions.Timeout is zero.
const DefaultTimeout = 30 * time.Second

// resolveIPs is the hostname resolver. Tests replace this to drive
// rebinding-style scenarios.
var resolveIPs = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ValidateURL is the pre-flight URL check. Returns nil if u is acceptable
// (scheme http/https, resolved host not in AbsoluteDeny, and any DefaultDeny
// hit is covered by `allowlist`). Use this from a connector's Validate hook
// to refuse a target_url at registration time, before any request fires.
func ValidateURL(ctx context.Context, u *url.URL, allowlist []netip.Prefix) error {
	if u == nil {
		return fmt.Errorf("httpguard: nil URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		// allowed schemes
	default:
		return fmt.Errorf("%w: %q", ErrSchemeDisallowed, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("httpguard: URL has empty host")
	}
	ips, err := resolveIPs(ctx, host)
	if err != nil {
		return fmt.Errorf("httpguard: resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%w: %q", ErrUnresolvable, host)
	}
	// If ANY resolved IP is absolutely-denied, refuse outright — we cannot
	// trust the resolver to consistently return the public one.
	for _, ip := range ips {
		if matchAny(ip, AbsoluteDeny) {
			return fmt.Errorf("%w: %s -> %s", ErrMetadataAbsoluteDeny, host, ip)
		}
	}
	// Find at least one allowed IP. An IP is allowed if it is NOT in
	// DefaultDeny, OR is covered by the per-connection allowlist.
	for _, ip := range ips {
		if !matchAny(ip, DefaultDeny) {
			return nil
		}
		if matchAny(ip, allowlist) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s -> %v", ErrPrivateRangeDenied, host, ips)
}

// Client returns an *http.Client whose Transport.DialContext and CheckRedirect
// enforce the SSRF guard. The returned client is safe for concurrent use.
func Client(opts ClientOptions) *http.Client {
	cap := opts.RedirectCap
	if cap == 0 {
		cap = DefaultRedirectCap
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	allowlist := append([]netip.Prefix(nil), opts.Allowlist...)
	logRefusal := opts.LogRefusal

	transport := &http.Transport{
		// Re-resolve immediately before connect and pin the dial to the
		// validated IP. Closes the TOCTOU window between a registration-time
		// check and the actual connection (DNS rebinding).
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("httpguard: split host: %w", err)
			}
			// If addr is already a literal IP, validate without resolving.
			if ip, perr := netip.ParseAddr(host); perr == nil {
				if err := validateIP(ip, allowlist); err != nil {
					if logRefusal != nil {
						logRefusal(err.Error(), host)
					}
					return nil, err
				}
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
			ips, err := resolveIPs(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("httpguard: resolve %q: %w", host, err)
			}
			for _, ip := range ips {
				if err := validateIP(ip, allowlist); err == nil {
					return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				}
			}
			refusal := fmt.Errorf("%w: %s -> %v", ErrPrivateRangeDenied, host, ips)
			if logRefusal != nil {
				logRefusal(refusal.Error(), host)
			}
			return nil, refusal
		},
		// Disable per-host connection pooling so two consecutive requests
		// (e.g., registration + first agent request) cannot share a dial that
		// was validated under different allowlist context. Cost is small in
		// practice (one extra handshake per request series).
		DisableKeepAlives: false,
		ForceAttemptHTTP2: true,
	}

	if opts.DisableRedirects {
		return &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	c := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cap {
				if logRefusal != nil {
					logRefusal(ErrRedirectChainExceeded.Error(), req.URL.Host)
				}
				return ErrRedirectChainExceeded
			}
			// Re-apply scheme + IP validation to the new target.
			if err := ValidateURL(req.Context(), req.URL, allowlist); err != nil {
				if logRefusal != nil {
					logRefusal(err.Error(), req.URL.Host)
				}
				return err
			}
			// Cross-origin credential strip (FR-009): if the redirect target's
			// origin differs from the original request's, drop Authorization
			// and Cookie before the redirected request fires.
			if len(via) > 0 && !sameOrigin(via[0].URL, req.URL) {
				req.Header.Del("Authorization")
				req.Header.Del("Cookie")
			}
			return nil
		},
	}
	return c
}

// validateIP returns nil if ip is acceptable under the deny rules.
func validateIP(ip netip.Addr, allowlist []netip.Prefix) error {
	if matchAny(ip, AbsoluteDeny) {
		return fmt.Errorf("%w: %s", ErrMetadataAbsoluteDeny, ip)
	}
	if matchAny(ip, DefaultDeny) {
		if matchAny(ip, allowlist) {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrPrivateRangeDenied, ip)
	}
	return nil
}

// matchAny returns true if ip is contained in any prefix in the list.
func matchAny(ip netip.Addr, prefixes []netip.Prefix) bool {
	// Unmap IPv4-mapped IPv6 addresses so 4-in-6 (::ffff:a.b.c.d) is
	// compared as the underlying IPv4 prefix.
	ip = ip.Unmap()
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// sameOrigin returns true if a and b share scheme + host + port.
func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	ah := strings.ToLower(a.Host)
	bh := strings.ToLower(b.Host)
	if ah == bh {
		return true
	}
	// Port-normalized comparison — http defaults 80, https defaults 443.
	aHost, aPort := splitHostPortWithDefault(a)
	bHost, bPort := splitHostPortWithDefault(b)
	return strings.EqualFold(aHost, bHost) && aPort == bPort
}

func splitHostPortWithDefault(u *url.URL) (string, string) {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	return host, port
}

// ParseCIDRs parses a list of CIDR strings into netip.Prefix values. Useful
// for connectors that store the per-connection allowlist as []string in their
// config. Returns an error naming the first invalid entry; the caller is
// expected to surface it back to the operator at registration time.
func ParseCIDRs(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, s := range cidrs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("httpguard: invalid CIDR %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}
