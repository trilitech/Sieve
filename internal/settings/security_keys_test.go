package settings_test

import (
	"strings"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/settings"
)

func TestPublicBaseURLDefault(t *testing.T) {
	svc := setup(t)
	if got := svc.PublicBaseURL(); got != "http://127.0.0.1:19816" {
		t.Errorf("PublicBaseURL() = %q, want loopback default", got)
	}
}

func TestPublicBaseURLOverride(t *testing.T) {
	svc := setup(t)
	if err := svc.Set(settings.KeyPublicBaseURL, "https://sieve.internal.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := svc.PublicBaseURL(); got != "https://sieve.internal.example.com" {
		t.Errorf("PublicBaseURL() = %q, want overridden value", got)
	}
}

func TestCommandAllowlistDefault(t *testing.T) {
	svc := setup(t)
	got := svc.CommandAllowlist()
	if len(got) != 1 || got[0] != "/opt/sieve-py/bin/python3" {
		t.Errorf("CommandAllowlist() default = %v, want [/opt/sieve-py/bin/python3]", got)
	}
}

func TestCommandAllowlistMultiEntry(t *testing.T) {
	svc := setup(t)
	if err := svc.Set(settings.KeyCommandAllowlist, "/opt/sieve-py/bin/python3\n/usr/bin/node\n"); err != nil {
		t.Fatal(err)
	}
	got := svc.CommandAllowlist()
	want := []string{"/opt/sieve-py/bin/python3", "/usr/bin/node"}
	if len(got) != len(want) {
		t.Fatalf("CommandAllowlist() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("CommandAllowlist()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCommandAllowlistTrimsWhitespaceAndBlankLines(t *testing.T) {
	svc := setup(t)
	if err := svc.Set(settings.KeyCommandAllowlist, "  /opt/sieve-py/bin/python3  \n\n\n/usr/bin/node\n"); err != nil {
		t.Fatal(err)
	}
	got := svc.CommandAllowlist()
	if len(got) != 2 {
		t.Fatalf("CommandAllowlist() = %v, want 2 entries", got)
	}
}

func TestCommandAllowlistFallsBackOnAllBlank(t *testing.T) {
	svc := setup(t)
	if err := svc.Set(settings.KeyCommandAllowlist, "   \n\n"); err != nil {
		t.Fatal(err)
	}
	got := svc.CommandAllowlist()
	if len(got) != 1 || got[0] != "/opt/sieve-py/bin/python3" {
		t.Errorf("CommandAllowlist() with blank value = %v, want default", got)
	}
}

func TestTLSPaths(t *testing.T) {
	svc := setup(t)
	if got := svc.AdminTLSCertPath(); got != "" {
		t.Errorf("AdminTLSCertPath() default = %q, want empty", got)
	}
	if err := svc.Set(settings.KeyAdminTLSCertPath, "/etc/sieve/admin.crt"); err != nil {
		t.Fatal(err)
	}
	if got := svc.AdminTLSCertPath(); got != "/etc/sieve/admin.crt" {
		t.Errorf("AdminTLSCertPath() = %q", got)
	}
	if got := svc.APITLSCertPath(); got != "" {
		t.Errorf("APITLSCertPath() default = %q, want empty", got)
	}
}

func TestSessionIdleTimeoutDefault(t *testing.T) {
	svc := setup(t)
	if got := svc.SessionIdleTimeout(); got != 8*time.Hour {
		t.Errorf("SessionIdleTimeout() default = %v, want 8h", got)
	}
}

func TestSessionIdleTimeoutOverride(t *testing.T) {
	svc := setup(t)
	if err := svc.Set(settings.KeySessionIdleTimeoutMinutes, "15"); err != nil {
		t.Fatal(err)
	}
	if got := svc.SessionIdleTimeout(); got != 15*time.Minute {
		t.Errorf("SessionIdleTimeout() = %v, want 15m", got)
	}
}

func TestSessionIdleTimeoutFallsBackOnGarbage(t *testing.T) {
	svc := setup(t)
	if err := svc.Set(settings.KeySessionIdleTimeoutMinutes, "not a number"); err != nil {
		t.Fatal(err)
	}
	if got := svc.SessionIdleTimeout(); got != 8*time.Hour {
		t.Errorf("SessionIdleTimeout() on garbage = %v, want default 8h", got)
	}
}

func TestRateLimitDefaults(t *testing.T) {
	svc := setup(t)
	if got := svc.RateLimitWindow(); got != 60*time.Second {
		t.Errorf("RateLimitWindow() default = %v, want 60s", got)
	}
	if got := svc.RateLimitFailures(); got != 10 {
		t.Errorf("RateLimitFailures() default = %d, want 10", got)
	}
}

func TestRateLimitOverrides(t *testing.T) {
	svc := setup(t)
	if err := svc.Set(settings.KeyRateLimitWindowSeconds, "30"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(settings.KeyRateLimitFailuresPerWindow, "5"); err != nil {
		t.Fatal(err)
	}
	if got := svc.RateLimitWindow(); got != 30*time.Second {
		t.Errorf("RateLimitWindow() = %v, want 30s", got)
	}
	if got := svc.RateLimitFailures(); got != 5 {
		t.Errorf("RateLimitFailures() = %d, want 5", got)
	}
}

func TestRateLimitFallsBackOnZeroAndNegative(t *testing.T) {
	svc := setup(t)
	for _, v := range []string{"0", "-1", "  ", "abc"} {
		if err := svc.Set(settings.KeyRateLimitFailuresPerWindow, v); err != nil {
			t.Fatal(err)
		}
		if got := svc.RateLimitFailures(); got != 10 {
			t.Errorf("RateLimitFailures() with %q = %d, want default 10", v, got)
		}
	}
}

// Round-trip smoke test for every new key — write a value, read it back,
// confirm trim semantics behave consistently.
func TestSecurityKeysRoundTrip(t *testing.T) {
	svc := setup(t)
	for _, kv := range []struct{ key, value string }{
		{settings.KeyPublicBaseURL, "https://example.test"},
		{settings.KeyCommandAllowlist, "/opt/sieve-py/bin/python3"},
		{settings.KeyAdminTLSCertPath, "/tmp/c"},
		{settings.KeyAdminTLSKeyPath, "/tmp/k"},
		{settings.KeyAPITLSCertPath, "/tmp/api-c"},
		{settings.KeyAPITLSKeyPath, "/tmp/api-k"},
		{settings.KeySessionIdleTimeoutMinutes, "30"},
		{settings.KeyRateLimitWindowSeconds, "120"},
		{settings.KeyRateLimitFailuresPerWindow, "3"},
	} {
		if err := svc.Set(kv.key, kv.value); err != nil {
			t.Fatalf("set %s: %v", kv.key, err)
		}
		got, err := svc.Get(kv.key)
		if err != nil {
			t.Fatalf("get %s: %v", kv.key, err)
		}
		if !strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(kv.value)) {
			t.Errorf("%s round-trip: got %q, want %q", kv.key, got, kv.value)
		}
	}
}
