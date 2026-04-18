package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGitHubAppState_PutTake(t *testing.T) {
	g := newGitHubAppState()
	g.put("s1", pendingGitHubApp{ID: "conn", DisplayName: "d", CreatedAt: time.Now()})

	got, ok := g.take("s1", time.Now())
	if !ok || got.ID != "conn" {
		t.Errorf("expected take to succeed, got ok=%v, val=%+v", ok, got)
	}
	if _, ok := g.take("s1", time.Now()); ok {
		t.Error("expected second take to fail — entry must be consumed")
	}
}

func TestGitHubAppState_Expired(t *testing.T) {
	g := newGitHubAppState()
	g.put("s1", pendingGitHubApp{CreatedAt: time.Now().Add(-20 * time.Minute)})
	if _, ok := g.take("s1", time.Now()); ok {
		t.Error("expected take to fail on expired entry")
	}
	// Expired entry must still be removed so it can't be re-consumed.
	g.mu.Lock()
	_, stillPresent := g.pending["s1"]
	g.mu.Unlock()
	if stillPresent {
		t.Error("expired entry should be removed from map after take")
	}
}

func TestGitHubAppState_Update(t *testing.T) {
	g := newGitHubAppState()
	g.put("s1", pendingGitHubApp{ID: "conn", CreatedAt: time.Now().Add(-5 * time.Minute)})

	ok := g.update("s1", func(p *pendingGitHubApp) {
		p.AppID = 42
		p.Slug = "my-app"
		p.PrivateKeyPEM = "PEM"
	})
	if !ok {
		t.Fatal("update returned false")
	}

	got, ok := g.take("s1", time.Now())
	if !ok || got.AppID != 42 || got.Slug != "my-app" || got.PrivateKeyPEM != "PEM" {
		t.Errorf("update didn't persist: %+v", got)
	}
	// Update must also restart the TTL window — otherwise a flow that exchanges
	// the manifest code 9 minutes in would immediately expire at the install
	// callback.
	if time.Since(got.CreatedAt) > time.Second {
		t.Errorf("CreatedAt not refreshed by update: %v ago", time.Since(got.CreatedAt))
	}
}

func TestGitHubAppState_Has(t *testing.T) {
	g := newGitHubAppState()
	g.put("s1", pendingGitHubApp{CreatedAt: time.Now()})

	if !g.has("s1") {
		t.Error("has should return true for present entry")
	}
	if g.has("nonexistent") {
		t.Error("has should return false for missing entry")
	}

	// has must not mutate: a follow-up take should still succeed.
	if _, ok := g.take("s1", time.Now()); !ok {
		t.Error("has mutated the entry: take after has failed")
	}
}

func generateTestPEM(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}))
}

func TestFetchInstallationScope_Organization(t *testing.T) {
	pemStr := generateTestPEM(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/12345" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Error("missing Bearer JWT in Authorization header")
		}
		fmt.Fprintln(w, `{"account": {"login": "trilitech", "type": "Organization"}}`)
	}))
	defer srv.Close()

	scopeType, scopeName, err := fetchInstallationScopeWith(
		context.Background(), srv.Client(), srv.URL, 1, 12345, pemStr)
	if err != nil {
		t.Fatal(err)
	}
	if scopeType != "org" || scopeName != "trilitech" {
		t.Errorf("got scopeType=%q scopeName=%q, want org/trilitech", scopeType, scopeName)
	}
}

func TestFetchInstallationScope_UserAccount(t *testing.T) {
	pemStr := generateTestPEM(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"account": {"login": "murbard", "type": "User"}}`)
	}))
	defer srv.Close()

	scopeType, scopeName, err := fetchInstallationScopeWith(
		context.Background(), srv.Client(), srv.URL, 1, 42, pemStr)
	if err != nil {
		t.Fatal(err)
	}
	if scopeType != "user" || scopeName != "murbard" {
		t.Errorf("got %q/%q, want user/murbard", scopeType, scopeName)
	}
}

func TestFetchInstallationScope_UpstreamError(t *testing.T) {
	pemStr := generateTestPEM(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, `{"message": "Not Found"}`)
	}))
	defer srv.Close()

	_, _, err := fetchInstallationScopeWith(
		context.Background(), srv.Client(), srv.URL, 1, 99, pemStr)
	if err == nil {
		t.Fatal("expected error on 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}

func TestFetchInstallationScope_BadPEM(t *testing.T) {
	_, _, err := fetchInstallationScopeWith(
		context.Background(), http.DefaultClient, "http://unused",
		1, 42, "not a real pem")
	if err == nil {
		t.Fatal("expected error for malformed PEM")
	}
	if !strings.Contains(err.Error(), "sign app jwt") {
		t.Errorf("expected JWT signing error, got: %v", err)
	}
}

func TestGitHubAppState_Sweep(t *testing.T) {
	g := newGitHubAppState()
	g.put("fresh", pendingGitHubApp{CreatedAt: time.Now()})
	g.put("stale", pendingGitHubApp{CreatedAt: time.Now().Add(-20 * time.Minute)})

	g.sweep(time.Now())

	if _, ok := g.pending["fresh"]; !ok {
		t.Error("fresh entry was swept")
	}
	if _, ok := g.pending["stale"]; ok {
		t.Error("stale entry should have been swept")
	}
}