package slack

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/trilitech/Sieve/internal/connector"
)

// TestBuildTokenSource_StaticForBotToken is the T005 regression: a bot-token
// connection (KindToken) must produce a static source and drive a normal API
// call after the token-source refactor — no refresh, behavior unchanged.
func TestBuildTokenSource_StaticForBotToken(t *testing.T) {
	cfg := &Config{AuthKind: KindToken, BotToken: "xoxb-static"}
	ts, err := buildTokenSource(cfg, defaultBaseURL, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, ok := ts.(*refreshingTokenSource); ok {
		t.Fatal("bot token must not get a refreshing source")
	}
	tok, err := ts.Token()
	if err != nil || tok.AccessToken != "xoxb-static" {
		t.Fatalf("static token wrong: tok=%+v err=%v", tok, err)
	}
}

// TestBuildTokenSource_StaticForNonRotatingUserToken: a user token with no
// refresh_token never expires — a static source, not a refreshing one.
func TestBuildTokenSource_StaticForNonRotatingUserToken(t *testing.T) {
	cfg := &Config{AuthKind: KindUserOAuth, OAuthToken: map[string]any{"access_token": "xoxp-nonrotating"}}
	ts, err := buildTokenSource(cfg, defaultBaseURL, map[string]any{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, ok := ts.(*refreshingTokenSource); ok {
		t.Fatal("non-rotating user token must not get a refreshing source")
	}
}

// TestRefreshingTokenSource_RenewsAndPersists: an expired rotating token is
// renewed via oauth.v2.access?grant_type=refresh_token, the rotated pair is
// adopted, and onRefresh fires so the connections service can persist it.
func TestRefreshingTokenSource_RenewsAndPersists(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/oauth.v2.access" || r.FormValue("grant_type") != "refresh_token" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"ok":            true,
			"access_token":  "xoxe.xoxp-rotated",
			"refresh_token": "xoxe-1-newrefresh",
			"token_type":    "user",
			"expires_in":    43200,
		})
	}))
	defer mock.Close()

	var persisted *oauth2.Token
	src := &refreshingTokenSource{
		cur:          &oauth2.Token{AccessToken: "xoxe.xoxp-old", RefreshToken: "xoxe-1-oldrefresh", Expiry: time.Now().Add(-time.Minute)},
		baseURL:      mock.URL,
		httpClient:   http.DefaultClient,
		clientID:     "cid",
		clientSecret: "secret",
		onRefresh:    func(tok *oauth2.Token) { persisted = tok },
	}

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("Token(): %v", err)
	}
	if tok.AccessToken != "xoxe.xoxp-rotated" || tok.RefreshToken != "xoxe-1-newrefresh" {
		t.Fatalf("rotated token wrong: %+v", tok)
	}
	if persisted == nil || persisted.AccessToken != "xoxe.xoxp-rotated" {
		t.Fatalf("onRefresh not called with rotated token: %+v", persisted)
	}
	if tok.Expiry.IsZero() {
		t.Fatal("expected expiry set from expires_in")
	}
}

// TestRefreshingTokenSource_TerminalFailureReauth: a terminal Slack error on
// refresh fires onRefreshFailure and returns connector.ErrNeedsReauth.
func TestRefreshingTokenSource_TerminalFailureReauth(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "token_revoked"})
	}))
	defer mock.Close()

	var reason string
	src := &refreshingTokenSource{
		cur:              &oauth2.Token{AccessToken: "xoxe.xoxp-old", RefreshToken: "dead", Expiry: time.Now().Add(-time.Minute)},
		baseURL:          mock.URL,
		httpClient:       http.DefaultClient,
		clientID:         "cid",
		clientSecret:     "secret",
		onRefreshFailure: func(r string) { reason = r },
	}

	_, err := src.Token()
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Fatalf("expected ErrNeedsReauth, got %v", err)
	}
	if reason == "" {
		t.Fatal("onRefreshFailure not called")
	}
}

// TestRefreshingTokenSource_TransientPassthrough: a transient (non-terminal)
// error does NOT flip reauth — it returns a plain error to be retried.
func TestRefreshingTokenSource_TransientPassthrough(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "ratelimited"})
	}))
	defer mock.Close()

	failureCalled := false
	src := &refreshingTokenSource{
		cur:              &oauth2.Token{AccessToken: "xoxe.xoxp-old", RefreshToken: "r", Expiry: time.Now().Add(-time.Minute)},
		baseURL:          mock.URL,
		httpClient:       http.DefaultClient,
		clientID:         "cid",
		clientSecret:     "secret",
		onRefreshFailure: func(string) { failureCalled = true },
	}

	_, err := src.Token()
	if err == nil {
		t.Fatal("expected transient error")
	}
	if errors.Is(err, connector.ErrNeedsReauth) {
		t.Fatal("transient error must not map to reauth")
	}
	if failureCalled {
		t.Fatal("onRefreshFailure must not fire on transient error")
	}
}

// TestRefreshingTokenSource_ValidTokenNoRefresh: a still-valid token is
// returned without contacting Slack.
func TestRefreshingTokenSource_ValidTokenNoRefresh(t *testing.T) {
	called := false
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer mock.Close()

	src := &refreshingTokenSource{
		cur:        &oauth2.Token{AccessToken: "xoxe.xoxp-fresh", RefreshToken: "r", Expiry: time.Now().Add(time.Hour)},
		baseURL:    mock.URL,
		httpClient: http.DefaultClient,
	}
	tok, err := src.Token()
	if err != nil || tok.AccessToken != "xoxe.xoxp-fresh" {
		t.Fatalf("valid token path wrong: tok=%+v err=%v", tok, err)
	}
	if called {
		t.Fatal("refresh endpoint should not be contacted for a valid token")
	}
	_ = context.Background()
}
