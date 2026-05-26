package settings

import (
	"strconv"
	"strings"
	"time"
)

// Setting keys introduced by spec 001-fix-security-vulns. See
// specs/001-fix-security-vulns/data-model.md § settings — new keys.
const (
	// KeyPublicBaseURL is the URL Sieve treats as its own externally-visible
	// base when constructing OAuth callback/redirect/manifest URLs. Replaces
	// the historical r.Host-derived construction (Shannon AUTH-VULN-06).
	KeyPublicBaseURL = "public_base_url"

	// KeyCommandAllowlist is a newline-separated list of absolute interpreter
	// paths a script-type policy is permitted to invoke. Default is the
	// bundled Python venv shipped by the Sieve image. Shannon INJ-VULN-01..03.
	KeyCommandAllowlist = "command_allowlist"

	// KeyAdminTLSCertPath / KeyAdminTLSKeyPath enable TLS on the admin
	// listener (port 19816) when both are set. Shannon AUTH-VULN-01.
	KeyAdminTLSCertPath = "admin.tls_cert_path"
	KeyAdminTLSKeyPath  = "admin.tls_key_path"

	// KeyAPITLSCertPath / KeyAPITLSKeyPath enable TLS on the agent API
	// listener (port 19817) when both are set.
	KeyAPITLSCertPath = "api.tls_cert_path"
	KeyAPITLSKeyPath  = "api.tls_key_path"

	// KeySessionIdleTimeoutMinutes controls when an operator session expires
	// without activity. Default 480 = 8 hours.
	KeySessionIdleTimeoutMinutes = "session.idle_timeout_minutes"

	// KeyRateLimitWindowSeconds / KeyRateLimitFailuresPerWindow tune the
	// per-IP token-bucket on the auth paths. Defaults 60 and 10.
	KeyRateLimitWindowSeconds    = "ratelimit.window_seconds"
	KeyRateLimitFailuresPerWindow = "ratelimit.failures_per_window"
)

// Defaults used when a setting is unset. Documented in data-model.md.
const (
	defaultPublicBaseURL          = "http://127.0.0.1:19816"
	defaultCommandInterpreter     = "/opt/sieve-py/bin/python3"
	defaultSessionIdleMinutes     = 480
	defaultRateLimitWindowSeconds = 60
	defaultRateLimitFailures      = 10
)

// PublicBaseURL returns the configured externally-visible base URL for OAuth
// flows. Defaults to the documented production localhost binding.
//
// The host portion is NEVER derived from inbound request headers — operators
// who run Sieve behind a reverse proxy must set this explicitly so that a
// forged Host header cannot redirect OAuth callbacks to an attacker
// (Shannon AUTH-VULN-06, FR-010..FR-012).
func (s *Service) PublicBaseURL() string {
	v, _ := s.Get(KeyPublicBaseURL)
	if v == "" {
		return defaultPublicBaseURL
	}
	return v
}

// CommandAllowlist returns the absolute interpreter paths a script-type
// policy's command field may take. The list is newline-separated in the
// stored value and trimmed; the default is the bundled Python venv.
//
// Shannon INJ-VULN-01/02/03, FR-013..FR-018.
func (s *Service) CommandAllowlist() []string {
	v, _ := s.Get(KeyCommandAllowlist)
	if strings.TrimSpace(v) == "" {
		return []string{defaultCommandInterpreter}
	}
	var out []string
	for _, line := range strings.Split(v, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return []string{defaultCommandInterpreter}
	}
	return out
}

// AdminTLSCertPath / AdminTLSKeyPath return the TLS material paths for the
// admin listener. Both empty = plaintext HTTP (the default for loopback).
// Exactly one set = startup error.
func (s *Service) AdminTLSCertPath() string {
	v, _ := s.Get(KeyAdminTLSCertPath)
	return strings.TrimSpace(v)
}
func (s *Service) AdminTLSKeyPath() string {
	v, _ := s.Get(KeyAdminTLSKeyPath)
	return strings.TrimSpace(v)
}

// APITLSCertPath / APITLSKeyPath return the TLS material paths for the agent
// API listener.
func (s *Service) APITLSCertPath() string {
	v, _ := s.Get(KeyAPITLSCertPath)
	return strings.TrimSpace(v)
}
func (s *Service) APITLSKeyPath() string {
	v, _ := s.Get(KeyAPITLSKeyPath)
	return strings.TrimSpace(v)
}

// SessionIdleTimeout returns the configured operator-session idle expiry.
// Falls back to the documented default if unset or unparseable.
func (s *Service) SessionIdleTimeout() time.Duration {
	v, _ := s.Get(KeySessionIdleTimeoutMinutes)
	if minutes, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && minutes > 0 {
		return time.Duration(minutes) * time.Minute
	}
	return time.Duration(defaultSessionIdleMinutes) * time.Minute
}

// RateLimitWindow returns the per-IP rate-limit window (default 60s).
func (s *Service) RateLimitWindow() time.Duration {
	v, _ := s.Get(KeyRateLimitWindowSeconds)
	if seconds, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return time.Duration(defaultRateLimitWindowSeconds) * time.Second
}

// RateLimitFailures returns the per-IP bucket capacity (default 10).
func (s *Service) RateLimitFailures() int {
	v, _ := s.Get(KeyRateLimitFailuresPerWindow)
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
		return n
	}
	return defaultRateLimitFailures
}
