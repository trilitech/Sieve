package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)


func TestTLSPairEnabled_NeitherSet(t *testing.T) {
	on, err := tlsPair{}.enabled()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if on {
		t.Error("empty pair should report TLS disabled")
	}
}

func TestTLSPairEnabled_BothSet(t *testing.T) {
	on, err := tlsPair{CertPath: "/x", KeyPath: "/y"}.enabled()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !on {
		t.Error("both-set pair should report TLS enabled")
	}
}

func TestTLSPairEnabled_CertOnly(t *testing.T) {
	_, err := tlsPair{CertPath: "/x"}.enabled()
	if err == nil {
		t.Fatal("cert-only configuration should fail")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Errorf("error should name the missing key: %v", err)
	}
}

func TestTLSPairEnabled_KeyOnly(t *testing.T) {
	_, err := tlsPair{KeyPath: "/y"}.enabled()
	if err == nil {
		t.Fatal("key-only configuration should fail")
	}
	if !strings.Contains(err.Error(), "cert") {
		t.Errorf("error should name the missing cert: %v", err)
	}
}

func TestTLSPairValidate_MissingFiles(t *testing.T) {
	err := tlsPair{CertPath: "/nonexistent/cert", KeyPath: "/nonexistent/key"}.validate()
	if err == nil {
		t.Fatal("validate should fail on missing files")
	}
}

func TestTLSPairValidate_DirectoryRejected(t *testing.T) {
	dir := t.TempDir()
	err := tlsPair{CertPath: dir, KeyPath: dir}.validate()
	if err == nil {
		t.Fatal("directory should be rejected as a TLS file path")
	}
}

func TestTLSPairValidate_ExistingFiles(t *testing.T) {
	certPEM, keyPEM := selfSignedPair(t)
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (tlsPair{CertPath: cert, KeyPath: key}).validate(); err != nil {
		t.Errorf("validate of real cert+key pair: %v", err)
	}
}

func TestHSTSMiddleware_SetsHeader(t *testing.T) {
	h := hstsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	w := newRecordingResponseWriter()
	h.ServeHTTP(w, mustNewRequest(t))
	got := w.Header().Get("Strict-Transport-Security")
	if !strings.Contains(got, "max-age=63072000") {
		t.Errorf("HSTS header missing or wrong: %q", got)
	}
	if !strings.Contains(got, "includeSubDomains") {
		t.Errorf("HSTS includeSubDomains missing: %q", got)
	}
}

// TestServeTLSEndToEnd binds a real loopback TLS listener using a
// self-signed pair and confirms an HTTPS GET succeeds with HSTS set.
// Uses an explicit net.Listener to avoid the race of reading
// srv.Addr after ListenAndServeTLS.
func TestServeTLSEndToEnd(t *testing.T) {
	certPEM, keyPEM := selfSignedPair(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	})
	srv := &http.Server{Handler: hstsMiddleware(mux)}
	go srv.ServeTLS(ln, certPath, keyPath)
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Errorf("status=%d", resp.StatusCode)
	}
	if got := resp.Header.Get("Strict-Transport-Security"); !strings.Contains(got, "max-age") {
		t.Errorf("HSTS header missing on TLS response: %q", got)
	}
}
