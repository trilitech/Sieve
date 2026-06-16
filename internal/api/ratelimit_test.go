package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/ratelimit"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/tokens"
)

// Per-IP token-bucket throttling on the bearer-token validation path:
// failed auth depletes the bucket, success refunds. The router returns
// 429 + Retry-After when the bucket is empty.

func newRateLimitTestServer(t *testing.T, cap int, refill time.Duration) (*httptest.Server, *testenv.Env, *Router) {
	t.Helper()
	env := testenv.New(t)
	rt := NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, audit.NewLogger(env.DB))
	rt.SetRateLimiter(ratelimit.NewLimiter(cap, refill, 100))
	ts := httptest.NewServer(rt.Handler())
	t.Cleanup(ts.Close)
	return ts, env, rt
}

// TestRateLimit_BurstOfInvalidTokensTriggers429 — spray invalid bearer
// tokens at the agent API. Before the per-IP limiter landed the server
// accepted ~925 attempts/second with no throttling. Now the 11th
// invalid attempt within the window returns 429.
func TestRateLimit_BurstOfInvalidTokensTriggers429(t *testing.T) {
	ts, _, _ := newRateLimitTestServer(t, 5, time.Minute)

	var got401, got429 int
	for i := 0; i < 12; i++ {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/connections", nil)
		req.Header.Set("Authorization", "Bearer sieve_tok_FAKE_"+strconv.Itoa(i))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			got401++
		case http.StatusTooManyRequests:
			got429++
			if resp.Header.Get("Retry-After") == "" {
				t.Error("429 response missing Retry-After header")
			}
		default:
			t.Fatalf("unexpected status %d", resp.StatusCode)
		}
	}
	if got401 != 5 {
		t.Errorf("got %d 401, want 5 (the bucket capacity)", got401)
	}
	if got429 != 7 {
		t.Errorf("got %d 429, want 7 (12 attempts - 5 capacity)", got429)
	}
}

// TestRateLimit_SuccessRefundsBucket — successful auth must refund the
// token consumed at the top of authMiddleware so legitimate high-
// throughput agents are not penalised for an occasional miss.
func TestRateLimit_SuccessRefundsBucket(t *testing.T) {
	ts, env, _ := newRateLimitTestServer(t, 3, time.Minute)
	// Set up a valid token.
	role, err := env.Roles.Create("rl-role", nil)
	if err != nil {
		t.Fatal(err)
	}
	tokResult, err := env.Tokens.Create(&tokens.CreateRequest{Name: "rl-token", RoleID: role.ID})
	if err != nil {
		t.Fatal(err)
	}

	// Consume 2 of 3 with invalid auth.
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/connections", nil)
		req.Header.Set("Authorization", "Bearer sieve_tok_BAD_"+strconv.Itoa(i))
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d", i, resp.StatusCode)
		}
	}

	// Valid request — should succeed AND refund the bucket.
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/connections", nil)
	req.Header.Set("Authorization", "Bearer "+tokResult.PlaintextToken)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		t.Fatalf("valid token returned %d", resp.StatusCode)
	}

	// After refund: the bucket should now hold 2 tokens (started at 3,
	// drained to 1, refunded to 2). One more failure should not trip 429.
	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/connections", nil)
	req.Header.Set("Authorization", "Bearer sieve_tok_BAD_THIRD")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Error("post-refund failure shouldn't trip the bucket")
	}
}

