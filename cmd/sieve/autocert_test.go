package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/settings"
)

// caSignedPair issues a localhost leaf certificate signed by a throwaway local
// CA (issuer != subject), expiring at notAfter. It models the mkcert case:
// a CA-signed cert an operator drops at Sieve's auto-cert path.
func caSignedPair(t *testing.T, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Local CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyBytes, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM
}

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

func TestReuseSelfSignedCert_RenewsSelfSignedNearExpiry(t *testing.T) {
	// Our own self-signed cert inside the renew window must be regenerated.
	certPEM, keyPEM := selfSignedPair(t) // valid ~1h, well within autoCertRenewWindow
	dir := t.TempDir()
	certPath := filepath.Join(dir, "admin-cert.pem")
	keyPath := filepath.Join(dir, "admin-key.pem")
	writePair(t, certPath, keyPath, certPEM, keyPEM)
	if reuseSelfSignedCert(certPath, keyPath) {
		t.Error("a self-signed cert within the renew window should not be reused")
	}
}

func TestReuseSelfSignedCert_KeepsCASignedNearExpiry(t *testing.T) {
	// A CA-signed (operator/mkcert) cert near expiry must NOT be clobbered —
	// reuse it so Sieve never overwrites a trusted cert with a self-signed one.
	certPEM, keyPEM := caSignedPair(t, time.Now().Add(10*24*time.Hour)) // inside 30d window
	dir := t.TempDir()
	certPath := filepath.Join(dir, "admin-cert.pem")
	keyPath := filepath.Join(dir, "admin-key.pem")
	writePair(t, certPath, keyPath, certPEM, keyPEM)
	if !reuseSelfSignedCert(certPath, keyPath) {
		t.Error("a CA-signed cert near expiry should be reused, not regenerated")
	}
}

func TestReuseSelfSignedCert_RejectsExpiredCASigned(t *testing.T) {
	certPEM, keyPEM := caSignedPair(t, time.Now().Add(-time.Hour)) // already expired
	dir := t.TempDir()
	certPath := filepath.Join(dir, "admin-cert.pem")
	keyPath := filepath.Join(dir, "admin-key.pem")
	writePair(t, certPath, keyPath, certPEM, keyPEM)
	if reuseSelfSignedCert(certPath, keyPath) {
		t.Error("an expired cert must not be reused")
	}
}

func TestCertIsSelfSigned(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	certPath, _, err := ensureSelfSignedCert(dir, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !certIsSelfSigned(certPath) {
		t.Error("Sieve's own auto-generated cert should be reported self-signed")
	}

	caDir := t.TempDir()
	caCertPath := filepath.Join(caDir, "ca-cert.pem")
	certPEM, keyPEM := caSignedPair(t, time.Now().Add(24*time.Hour))
	writePair(t, caCertPath, filepath.Join(caDir, "ca-key.pem"), certPEM, keyPEM)
	if certIsSelfSigned(caCertPath) {
		t.Error("a CA-signed cert should NOT be reported self-signed")
	}

	if !certIsSelfSigned(filepath.Join(caDir, "does-not-exist.pem")) {
		t.Error("a missing cert should default to self-signed (HSTS-off safe default)")
	}
}

func writePair(t *testing.T, certPath, keyPath string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestQuietTLSHandshakeWriter(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		forwarded bool
	}{
		{"unknown-cert", "2026/07/14 17:03:57 http: TLS handshake error from 127.0.0.1:59027: remote error: tls: unknown certificate\n", false},
		{"http-on-https", "2026/07/14 17:03:50 http: TLS handshake error from 127.0.0.1:59023: client sent an HTTP request to an HTTPS server\n", false},
		{"handshake-timeout", "2026/07/14 17:04:00 http: TLS handshake error from 127.0.0.1:59025: read tcp ...: i/o timeout\n", false},
		{"real-panic", "http: panic serving 127.0.0.1: boom\n", true},
		{"real-accept-error", "http: Accept error: too many open files\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := quietTLSHandshakeWriter{dst: &buf}
			n, err := w.Write([]byte(tc.line))
			if err != nil {
				t.Fatalf("Write err = %v", err)
			}
			if n != len(tc.line) {
				t.Errorf("n = %d, want %d (must always report the full write)", n, len(tc.line))
			}
			if got := buf.Len() > 0; got != tc.forwarded {
				t.Errorf("forwarded = %v, want %v (buf=%q)", got, tc.forwarded, buf.String())
			}
			if tc.forwarded && buf.String() != tc.line {
				t.Errorf("forwarded line altered: got %q, want %q", buf.String(), tc.line)
			}
		})
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
