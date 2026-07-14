package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

// quietTLSHandshakeWriter forwards http.Server ErrorLog output to dst but drops
// the benign, non-actionable per-connection "TLS handshake error" lines. These
// are client-side conditions (untrusted self-signed cert, a plaintext http://
// client hitting the https port, an abandoned preconnect) — never a server
// misconfiguration, which surfaces at ListenAndServeTLS startup instead.
type quietTLSHandshakeWriter struct{ dst io.Writer }

func (q quietTLSHandshakeWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("TLS handshake error")) {
		return len(p), nil // swallow; report success so the logger sees no error
	}
	return q.dst.Write(p)
}

// quietTLSHandshakeLog builds a *log.Logger suitable for http.Server.ErrorLog
// that matches the stdlib log format but filters handshake noise.
func quietTLSHandshakeLog() *log.Logger {
	return log.New(quietTLSHandshakeWriter{dst: os.Stderr}, "", log.LstdFlags)
}

// optional TLS on
// the admin and agent listeners. Both-or-neither per listener; HSTS
// header on every TLS response; default deployment (no cert/key set)
// stays plaintext-on-loopback unchanged.

// tlsPair holds the cert + key paths for one listener.
type tlsPair struct {
	CertPath string
	KeyPath  string
	// SelfSigned marks a cert Sieve auto-generated for loopback (see
	// ensureSelfSignedCert). Such a listener serves TLS but must NOT send
	// HSTS: HSTS makes the browser's cert-error interstitial
	// non-bypassable, which would permanently lock the operator out of an
	// untrusted self-signed localhost cert.
	SelfSigned bool
}

// enabled reports whether both cert and key are configured. Returns
// (false, nil) when neither is set (plaintext, the default). Returns
// (false, err) when exactly one is set — the "both-or-neither" rule.
func (p tlsPair) enabled() (bool, error) {
	hasCert := p.CertPath != ""
	hasKey := p.KeyPath != ""
	switch {
	case !hasCert && !hasKey:
		return false, nil
	case hasCert != hasKey:
		// Exactly one set — that's a misconfiguration.
		if hasCert {
			return false, errors.New("TLS cert configured but key path is missing")
		}
		return false, errors.New("TLS key configured but cert path is missing")
	}
	return true, nil
}

// validate confirms both files exist and are readable. Called at
// startup so the operator gets a clear error instead of a confusing
// ListenAndServeTLS failure on first request.
func (p tlsPair) validate() error {
	for _, kv := range []struct{ name, path string }{
		{"cert", p.CertPath},
		{"key", p.KeyPath},
	} {
		st, err := os.Stat(kv.path)
		if err != nil {
			return fmt.Errorf("TLS %s file %q: %w", kv.name, kv.path, err)
		}
		if st.IsDir() {
			return fmt.Errorf("TLS %s path %q is a directory, not a file", kv.name, kv.path)
		}
	}
	return nil
}

// hstsMiddleware sets the Strict-Transport-Security header on every
// response. Wraps a handler only when its listener is TLS-bound;
// plaintext listeners do NOT set HSTS (it would instruct clients to
// upgrade requests Sieve isn't ready to handle).
func hstsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 2 years = the documented modern default for any host that
		// commits to TLS. includeSubDomains is on because Sieve doesn't
		// host child domains today; future deployments behind subdomain
		// load balancers stay opted in.
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// serveListener picks between ListenAndServe and ListenAndServeTLS
// based on whether the supplied tlsPair is enabled. The handler is
// wrapped with hstsMiddleware ONLY when TLS is in effect.
func serveListener(srv *http.Server, p tlsPair) error {
	tlsOn, err := p.enabled()
	if err != nil {
		return err
	}
	if !tlsOn {
		return srv.ListenAndServe()
	}
	if err := p.validate(); err != nil {
		return err
	}
	// Pin the negotiated minimum to TLS 1.2 explicitly. Today's Go default
	// is TLS 1.2 on the server side anyway, but pinning here means a future
	// stdlib relaxation, or any library that embeds this server, can't
	// negotiate a weaker protocol without our consent.
	if srv.TLSConfig == nil {
		srv.TLSConfig = &tls.Config{}
	}
	if srv.TLSConfig.MinVersion < tls.VersionTLS12 {
		srv.TLSConfig.MinVersion = tls.VersionTLS12
	}
	// HSTS only for an operator-supplied (real-CA) cert. On the auto-generated
	// self-signed cert HSTS would make the browser's cert warning
	// non-bypassable — a permanent lockout — so it is deliberately skipped.
	if !p.SelfSigned {
		srv.Handler = hstsMiddleware(srv.Handler)
	}
	return srv.ListenAndServeTLS(p.CertPath, p.KeyPath)
}
