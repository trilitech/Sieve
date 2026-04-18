package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func generateTestPEM(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	return priv, string(pemBytes)
}

func TestSignAppJWT(t *testing.T) {
	_, pemStr := generateTestPEM(t)
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)

	tok, err := signAppJWT(12345, pemStr, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT must have 3 parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr map[string]string
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr["alg"] != "RS256" || hdr["typ"] != "JWT" {
		t.Errorf("bad header: %v", hdr)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Iss != "12345" {
		t.Errorf("iss=%q, want 12345", payload.Iss)
	}
	if payload.Iat != now.Add(-60*time.Second).Unix() {
		t.Errorf("iat=%d, want %d (now-60s)", payload.Iat, now.Add(-60*time.Second).Unix())
	}
	if payload.Exp <= payload.Iat || payload.Exp-payload.Iat > 600 {
		t.Errorf("exp=%d iat=%d not within (iat, iat+600]", payload.Exp, payload.Iat)
	}
}

func TestInstallationTokenCache(t *testing.T) {
	_, pemStr := generateTestPEM(t)

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/777/access_tokens" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing Bearer authz")
		}
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token": "ghs_xxx_%d", "expires_at": %q}`,
			atomic.LoadInt32(&calls), time.Now().Add(time.Hour).Format(time.RFC3339))
	}))
	defer srv.Close()

	cache := newAppTokenCache(srv.Client())
	cache.apiBase = srv.URL
	cred := &Credential{
		Kind:           KindAppInstallation,
		AppID:          1,
		InstallationID: 777,
		PrivateKeyPEM:  pemStr,
	}

	tok1, err := cache.installationToken(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := cache.installationToken(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	if tok1 != tok2 {
		t.Errorf("expected cache hit, got distinct tokens %q %q", tok1, tok2)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected 1 upstream call, got %d", got)
	}

	// Force expiry: set cache entry to expire in 30 seconds (within slack window).
	cache.mu.Lock()
	cache.entries[appTokenKey{appID: 1, installationID: 777}] = appTokenCacheEntry{
		token: tok1, expires: time.Now().Add(30 * time.Second),
	}
	cache.mu.Unlock()

	tok3, err := cache.installationToken(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	if tok3 == tok1 {
		t.Errorf("expected refresh, still got %q", tok3)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected 2 upstream calls after refresh, got %d", got)
	}
}
