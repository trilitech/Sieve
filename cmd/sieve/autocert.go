package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// autoCertRenewWindow is how close to expiry a reused cert may be before
// ensureSelfSignedCert regenerates it, so a long-running install rolls over
// its localhost cert well before browsers start rejecting it.
const autoCertRenewWindow = 30 * 24 * time.Hour

// ensureSelfSignedCert returns the cert + key file paths for `name`, generating
// a fresh self-signed loopback certificate at dir/<name>-cert.pem and
// dir/<name>-key.pem when usable files don't already exist. The certificate
// covers localhost / 127.0.0.1 / ::1 so it validates for whichever loopback
// host the operator's browser uses. The private key file is written 0600.
//
// This backs the "admin UI is HTTPS out of the box" default: Slack (and every
// other https-only OAuth redirect) works without the operator hand-rolling a
// cert. The cost is a one-time per-browser trust prompt for the self-signed
// cert — which is why the TLS listener that uses this cert must NOT send HSTS
// (see serveListener): HSTS turns that bypassable interstitial into a
// permanent, un-clickable-through lockout.
func ensureSelfSignedCert(dir, name string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(dir, name+"-cert.pem")
	keyPath = filepath.Join(dir, name+"-key.pem")

	if reuseSelfSignedCert(certPath, keyPath) {
		return certPath, keyPath, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("create tls dir %q: %w", dir, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("generate serial: %w", err)
	}

	// Backdate NotBefore an hour to tolerate small clock skew between the
	// generating host and the browser.
	notBefore := time.Now().Add(-1 * time.Hour)
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost", Organization: []string{"Sieve (self-signed)"}},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("create certificate: %w", err)
	}
	if err := writePEMFile(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return "", "", err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshal key: %w", err)
	}
	if err := writePEMFile(keyPath, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return "", "", err
	}

	return certPath, keyPath, nil
}

// reuseSelfSignedCert reports whether an existing cert/key pair on disk can be
// reused: both files present, the cert parses, and it is not within
// autoCertRenewWindow of expiry. Any failure returns false so the caller
// regenerates — a corrupt or stale pair is silently replaced rather than
// crashing the listener.
func reuseSelfSignedCert(certPath, keyPath string) bool {
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return time.Now().Add(autoCertRenewWindow).Before(cert.NotAfter)
}

// writePEMFile writes a single PEM block to path with the given mode,
// truncating any existing file.
func writePEMFile(path, blockType string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("encode %q: %w", path, err)
	}
	return nil
}
