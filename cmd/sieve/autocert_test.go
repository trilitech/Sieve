package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/settings"
)

// loadGeneratedCert loads and parses the leaf cert produced by
// ensureSelfSignedCert, failing the test on any error.
func loadGeneratedCert(t *testing.T, certPath, keyPath string) *x509.Certificate {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return leaf
}

func TestEnsureSelfSignedCert_GeneratesUsableLoopbackCert(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	certPath, keyPath, err := ensureSelfSignedCert(dir, "admin")
	if err != nil {
		t.Fatalf("ensureSelfSignedCert: %v", err)
	}
	if certPath != filepath.Join(dir, "admin-cert.pem") || keyPath != filepath.Join(dir, "admin-key.pem") {
		t.Fatalf("unexpected paths: %q %q", certPath, keyPath)
	}

	leaf := loadGeneratedCert(t, certPath, keyPath)

	// SANs must cover every loopback host a browser might use.
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Errorf("cert should be valid for localhost: %v", err)
	}
	for _, ip := range []string{"127.0.0.1", "::1"} {
		found := false
		for _, got := range leaf.IPAddresses {
			if got.Equal(net.ParseIP(ip)) {
				found = true
			}
		}
		if !found {
			t.Errorf("cert missing IP SAN %s (have %v)", ip, leaf.IPAddresses)
		}
	}

	// serverAuth EKU and a long-lived validity window.
	hasServerAuth := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("cert missing ExtKeyUsageServerAuth")
	}
	if leaf.NotAfter.Before(time.Now().Add(365 * 24 * time.Hour)) {
		t.Errorf("cert expires too soon: %v", leaf.NotAfter)
	}
}

func TestEnsureSelfSignedCert_KeyIs0600(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	_, keyPath, err := ensureSelfSignedCert(dir, "admin")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file perm = %o, want 0600", perm)
	}
}

func TestEnsureSelfSignedCert_ReusesExistingPair(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	certPath, _, err := ensureSelfSignedCert(dir, "admin")
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	// A second call with a healthy, non-expiring pair present must reuse it
	// verbatim rather than minting a new cert (which would invalidate the
	// operator's already-accepted browser exception).
	if _, _, err := ensureSelfSignedCert(dir, "admin"); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("second call regenerated the cert instead of reusing it")
	}
}

func TestEnsureSelfSignedCert_RegeneratesWhenKeyMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	certPath, keyPath, err := ensureSelfSignedCert(dir, "admin")
	if err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(certPath)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureSelfSignedCert(dir, "admin"); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(certPath)
	if string(first) == string(second) {
		t.Error("cert should be regenerated when the key file is missing")
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key not regenerated: %v", err)
	}
}

func TestReuseSelfSignedCert_RejectsExpired(t *testing.T) {
	// A cert already inside the renew window must not be reused.
	certPEM, keyPEM := selfSignedPair(t) // valid ~1h, well within autoCertRenewWindow
	dir := t.TempDir()
	certPath := filepath.Join(dir, "admin-cert.pem")
	keyPath := filepath.Join(dir, "admin-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if reuseSelfSignedCert(certPath, keyPath) {
		t.Error("a cert within the renew window should not be reused")
	}
}

func TestOperatorPrefersPlaintextAdmin(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "sieve.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	svc := settings.NewService(db)

	cases := []struct {
		value string
		want  bool
	}{
		{"", false},                        // unset → HTTPS default
		{"https://localhost:19816", false}, // explicit https → HTTPS
		{"http://localhost:19816", true},   // explicit http → opt out
		{"  HTTP://localhost:19816  ", true},
	}
	for _, tc := range cases {
		if err := svc.Set(settings.KeyPublicBaseURL, tc.value); err != nil {
			t.Fatal(err)
		}
		if got := operatorPrefersPlaintextAdmin(svc); got != tc.want {
			t.Errorf("operatorPrefersPlaintextAdmin(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}
