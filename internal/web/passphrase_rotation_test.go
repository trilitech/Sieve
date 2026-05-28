package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/secrets"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// rotationSrvByURL maps an httptest.Server URL to the underlying *Server
// so tests that need to reach into the lockout state machine (e.g.
// TestRotateHandlerCooldownClears) can recover the *Server without
// peeling apart the http.Handler.
var (
	rotationSrvMu    sync.Mutex
	rotationSrvByURL = map[string]*Server{}
)

// newRotationTestServer wires the same dependencies as cmd/sieve/main.go
// would and returns the running httptest.Server plus the test environment
// used for assertions. The test passphrase is testenv.New's default
// ("test-passphrase"); rotations target a fresh value the test picks.
func newRotationTestServer(t *testing.T) (*httptest.Server, *testenv.Env) {
	t.Helper()
	env := testenv.New(t)
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := NewServer(
		env.Tokens, env.Connections, env.Policies, env.Roles,
		env.Registry, env.Approval, env.Audit,
		"", env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "127.0.0.1:0",
	)
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	rotationSrvMu.Lock()
	rotationSrvByURL[ts.URL] = srv
	rotationSrvMu.Unlock()
	t.Cleanup(func() {
		rotationSrvMu.Lock()
		delete(rotationSrvByURL, ts.URL)
		rotationSrvMu.Unlock()
	})

	return ts, env
}

func countAuditOps(t *testing.T, audLog *audit.Logger, op string) int {
	t.Helper()
	entries, err := audLog.List(&audit.ListFilter{Operation: op, Limit: 100})
	if err != nil {
		t.Fatalf("list audit %q: %v", op, err)
	}
	return len(entries)
}

// TestRotateHandlerSuccess exercises the happy path: valid current /
// new / confirm fields, a connection in the DB so there's a DEK to
// rewrap, and a 303 redirect with the count plus a single audit row.
func TestRotateHandlerSuccess(t *testing.T) {
	ts, env := newRotationTestServer(t)

	// Add a connection so Rotate has at least one record to rewrap.
	env.SetupConnectionAndRole(t, "rot-conn-1")

	form := url.Values{}
	form.Set("current_passphrase", "test-passphrase")
	form.Set("new_passphrase", "rotated-passphrase")
	form.Set("new_passphrase_confirm", "rotated-passphrase")

	client := &http.Client{
		// Don't follow the 303 — we want to assert on the redirect itself.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequest("POST", ts.URL+"/settings/rotate-passphrase", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/settings?rotated=1&count=") {
		t.Fatalf("Location: got %q, want /settings?rotated=1&count=N", loc)
	}

	// Verify the new passphrase is now the active one by attempting a
	// fresh Load on a separate keyring against the same DB. The old
	// passphrase MUST fail.
	k2 := &secrets.Keyring{}
	if err := k2.Load(env.DB.DB, []byte("rotated-passphrase")); err != nil {
		t.Fatalf("load with new passphrase: %v", err)
	}
	k3 := &secrets.Keyring{}
	if err := k3.Load(env.DB.DB, []byte("test-passphrase")); err == nil {
		t.Fatal("old passphrase should no longer load the keyring")
	}

	// Audit row count: exactly one keyring.rotate row, zero rotate_lockout
	// rows.
	if got := countAuditOps(t, env.Audit, "keyring.rotate"); got != 1 {
		t.Fatalf("keyring.rotate audit rows: got %d, want 1", got)
	}
	if got := countAuditOps(t, env.Audit, "keyring.rotate_lockout"); got != 0 {
		t.Fatalf("keyring.rotate_lockout audit rows: got %d, want 0", got)
	}

	// The single keyring.rotate row MUST carry surface=ui and a
	// records_rewrapped count matching the running keyring state.
	entries, err := env.Audit.List(&audit.ListFilter{Operation: "keyring.rotate"})
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].PolicyResult != "success" {
		t.Fatalf("policy_result: got %q, want \"success\"", entries[0].PolicyResult)
	}
	if entries[0].TokenID != "system" || entries[0].ConnectionID != "-" {
		t.Fatalf("sentinel actors: got token_id=%q connection_id=%q", entries[0].TokenID, entries[0].ConnectionID)
	}
	var params map[string]any
	if err := json.Unmarshal([]byte(entries[0].Params), &params); err != nil {
		t.Fatalf("params unmarshal: %v", err)
	}
	if params["surface"] != "ui" {
		t.Fatalf("params.surface: got %v, want \"ui\"", params["surface"])
	}
	if _, ok := params["records_rewrapped"]; !ok {
		t.Fatalf("params.records_rewrapped missing: %v", params)
	}
}

// TestRotateHandlerRejectsAgentToken verifies that the rejectIfAgentToken
// middleware blocks any attempt to drive the rotation form with a Sieve
// agent bearer token, even if the Origin/Referer check would otherwise
// pass. No database write or audit row may result.
func TestRotateHandlerRejectsAgentToken(t *testing.T) {
	ts, env := newRotationTestServer(t)

	form := url.Values{}
	form.Set("current_passphrase", "test-passphrase")
	form.Set("new_passphrase", "anything")
	form.Set("new_passphrase_confirm", "anything")

	req, err := http.NewRequest("POST", ts.URL+"/settings/rotate-passphrase", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	req.Header.Set("Authorization", "Bearer sieve_tok_abc123")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d, want %d (Forbidden)", resp.StatusCode, http.StatusForbidden)
	}

	// No audit rows MUST have been written: rejectIfAgentToken returns
	// before any rotation logic runs.
	if got := countAuditOps(t, env.Audit, "keyring.rotate"); got != 0 {
		t.Fatalf("keyring.rotate rows after rejected agent-token request: got %d, want 0", got)
	}
	if got := countAuditOps(t, env.Audit, "keyring.rotate_lockout"); got != 0 {
		t.Fatalf("keyring.rotate_lockout rows after rejected agent-token request: got %d, want 0", got)
	}

	// And the keyring still loads with the OLD passphrase (no rotation
	// happened).
	k := &secrets.Keyring{}
	if err := k.Load(env.DB.DB, []byte("test-passphrase")); err != nil {
		t.Fatalf("keyring should still load with original passphrase, got %v", err)
	}
}

// rotateRequest is a helper that builds a POST to /settings/rotate-passphrase
// with the canonical Origin header (so the legitimate-flow check passes)
// plus form-encoded fields. Tests for the explicit defense paths
// (cross-origin, agent-token) override these as needed.
func rotateRequest(t *testing.T, ts *httptest.Server, current, newPP, confirm string) *http.Request {
	t.Helper()
	form := url.Values{}
	form.Set("current_passphrase", current)
	form.Set("new_passphrase", newPP)
	form.Set("new_passphrase_confirm", confirm)
	req, err := http.NewRequest("POST", ts.URL+"/settings/rotate-passphrase", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	return req
}

// rotateClient returns an http.Client that does NOT follow redirects so
// callers can assert on the 303 status itself.
func rotateClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// TestRotateHandlerWrongPassphrase verifies the wrong-current-passphrase
// branch: HTTP 200 re-render with the typed chip; no audit row written.
func TestRotateHandlerWrongPassphrase(t *testing.T) {
	ts, env := newRotationTestServer(t)

	req := rotateRequest(t, ts, "this-is-not-the-current-passphrase", "new", "new")
	resp, err := rotateClient().Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "current passphrase incorrect") {
		t.Fatalf("body should contain 'current passphrase incorrect', got: %s", body)
	}
	if got := countAuditOps(t, env.Audit, "keyring.rotate"); got != 0 {
		t.Fatalf("keyring.rotate audit rows: got %d, want 0", got)
	}
}

// TestRotateHandlerConfirmMismatch verifies the confirmation-mismatch
// branch produces a distinct error message and writes no audit row.
func TestRotateHandlerConfirmMismatch(t *testing.T) {
	ts, env := newRotationTestServer(t)
	req := rotateRequest(t, ts, "test-passphrase", "alpha", "beta")
	resp, err := rotateClient().Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body := readBody(t, resp)
	if !strings.Contains(body, "new passphrase and confirmation do not match") {
		t.Fatalf("expected confirmation-mismatch chip, body: %s", body)
	}
	if got := countAuditOps(t, env.Audit, "keyring.rotate"); got != 0 {
		t.Fatalf("audit rows: got %d, want 0", got)
	}
}

// TestRotateHandlerSameAsCurrent verifies the new=current refusal.
func TestRotateHandlerSameAsCurrent(t *testing.T) {
	ts, env := newRotationTestServer(t)
	req := rotateRequest(t, ts, "test-passphrase", "test-passphrase", "test-passphrase")
	resp, err := rotateClient().Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body := readBody(t, resp)
	if !strings.Contains(body, "new passphrase identical to current; no rotation performed") {
		t.Fatalf("expected new=current chip, body: %s", body)
	}
	if got := countAuditOps(t, env.Audit, "keyring.rotate"); got != 0 {
		t.Fatalf("audit rows: got %d, want 0", got)
	}
	// Keyring is unchanged: old passphrase still loads.
	k := &secrets.Keyring{}
	if err := k.Load(env.DB.DB, []byte("test-passphrase")); err != nil {
		t.Fatalf("keyring should still load with original passphrase, got %v", err)
	}
}

// TestRotateHandlerLockoutAtFifthFailure verifies the brute-force
// lockout: 5 consecutive wrong-current submissions trigger a 15-min
// cooldown; subsequent submissions return 423; exactly ONE audit row
// with operation="keyring.rotate_lockout" is written.
func TestRotateHandlerLockoutAtFifthFailure(t *testing.T) {
	ts, env := newRotationTestServer(t)

	// First five wrong submissions all return 200 with the wrong-current
	// chip. The 5th MUST also trigger the lockout (the response itself
	// is still HTTP 200 with the wrong-passphrase message because the
	// failure happened before the lockout flips on; the next request
	// gets 423).
	for i := 0; i < 5; i++ {
		req := rotateRequest(t, ts, "wrong", "new", "new")
		resp, err := rotateClient().Do(req)
		if err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("attempt %d status: got %d, want 200", i+1, resp.StatusCode)
		}
	}

	// 6th submission: cooldown is active. Status 423 Locked.
	req := rotateRequest(t, ts, "test-passphrase", "new", "new")
	resp, err := rotateClient().Do(req)
	if err != nil {
		t.Fatalf("6th attempt: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusLocked {
		t.Fatalf("6th status: got %d, want 423", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("Retry-After header missing on 423 response")
	}

	// Exactly ONE keyring.rotate_lockout row, zero keyring.rotate rows.
	if got := countAuditOps(t, env.Audit, "keyring.rotate_lockout"); got != 1 {
		t.Fatalf("keyring.rotate_lockout rows: got %d, want 1", got)
	}
	if got := countAuditOps(t, env.Audit, "keyring.rotate"); got != 0 {
		t.Fatalf("keyring.rotate rows: got %d, want 0", got)
	}

	// Submit a 7th request while still locked — no additional audit row
	// must be written (only the lockout-trigger event is recorded).
	req2 := rotateRequest(t, ts, "test-passphrase", "new", "new")
	resp2, err := rotateClient().Do(req2)
	if err != nil {
		t.Fatalf("7th attempt: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusLocked {
		t.Fatalf("7th status: got %d, want 423", resp2.StatusCode)
	}
	if got := countAuditOps(t, env.Audit, "keyring.rotate_lockout"); got != 1 {
		t.Fatalf("after 7th request: keyring.rotate_lockout rows: got %d, want still 1", got)
	}
}

// TestRotateHandlerCooldownClears verifies the cooldown-elapsed branch:
// a request that arrives after rotateLockedTil resets the counter and
// proceeds. Uses the test setter to time-travel past the cooldown.
func TestRotateHandlerCooldownClears(t *testing.T) {
	ts, env := newRotationTestServer(t)
	srv := serverFromHandler(ts)

	// Pretend we already triggered the lockout, but it expired 1 minute ago.
	srv.rotateMu.Lock()
	srv.rotateFailures = 5
	srv.rotateLockedTil = time.Now().Add(-1 * time.Minute)
	srv.rotateMu.Unlock()

	// A correct submission MUST proceed (cooldown elapsed → counter reset).
	req := rotateRequest(t, ts, "test-passphrase", "after-cooldown", "after-cooldown")
	resp, err := rotateClient().Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303 — cooldown should have cleared", resp.StatusCode)
	}

	// Counter and lockedTil are zeroed after the successful rotation.
	srv.rotateMu.Lock()
	defer srv.rotateMu.Unlock()
	if srv.rotateFailures != 0 {
		t.Fatalf("rotateFailures: got %d, want 0", srv.rotateFailures)
	}
	if !srv.rotateLockedTil.IsZero() {
		t.Fatalf("rotateLockedTil: got %v, want zero", srv.rotateLockedTil)
	}

	// Sanity: the new passphrase loads.
	k := &secrets.Keyring{}
	if err := k.Load(env.DB.DB, []byte("after-cooldown")); err != nil {
		t.Fatalf("load with new passphrase: %v", err)
	}
}

// TestRotateHandlerRejectsCrossOrigin verifies the Origin/Referer CSRF
// defense: a POST with an Origin that doesn't match the request Host
// is rejected with 403 before any rotation logic runs.
func TestRotateHandlerRejectsCrossOrigin(t *testing.T) {
	ts, env := newRotationTestServer(t)

	// Cross-origin: Origin set to a different host than r.Host.
	req := rotateRequest(t, ts, "test-passphrase", "x", "x")
	req.Header.Set("Origin", "http://evil.example")
	resp, err := rotateClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin status: got %d, want 403", resp.StatusCode)
	}

	// Missing both Origin and Referer: also 403.
	req2 := rotateRequest(t, ts, "test-passphrase", "x", "x")
	req2.Header.Del("Origin")
	resp2, err := rotateClient().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("missing-origin status: got %d, want 403", resp2.StatusCode)
	}

	// Zero rotation audit rows MUST result.
	if got := countAuditOps(t, env.Audit, "keyring.rotate"); got != 0 {
		t.Fatalf("audit rows: got %d, want 0", got)
	}
	if got := countAuditOps(t, env.Audit, "keyring.rotate_lockout"); got != 0 {
		t.Fatalf("lockout rows: got %d, want 0", got)
	}
}

// TestRotateHandlerNoEchoOnFailure verifies that failed submissions
// MUST NOT echo the typed values back into the rendered HTML.
func TestRotateHandlerNoEchoOnFailure(t *testing.T) {
	ts, _ := newRotationTestServer(t)

	const sentinel = "secret-sentinel-value-1234567890"

	// Confirmation-mismatch path with the sentinel as new+confirm; since
	// they don't match, the page re-renders with an error and MUST NOT
	// contain the sentinel anywhere.
	req := rotateRequest(t, ts, sentinel, sentinel+"-A", sentinel+"-B")
	resp, err := rotateClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := readBody(t, resp)
	if strings.Contains(body, sentinel) {
		t.Fatal("response body contains a submitted passphrase value (no-echo violation)")
	}

	// Wrong-current-passphrase path — same expectation.
	req2 := rotateRequest(t, ts, sentinel, "x", "x")
	resp2, err := rotateClient().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	body2 := readBody(t, resp2)
	if strings.Contains(body2, sentinel) {
		t.Fatal("wrong-current response contains submitted passphrase (no-echo violation)")
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b = append(b, buf[:n]...)
		if err != nil {
			break
		}
	}
	return string(b)
}

// serverFromHandler reaches into the test server to recover the underlying
// *Server. The test server is constructed with srv.Handler() — we have
// the handler, and the handler is a *http.ServeMux holding closures over
// the *Server. Rather than expose internals, the helper tests cheat: they
// keep a side-table of (testserver URL → *Server) populated by
// newRotationTestServer.
func serverFromHandler(ts *httptest.Server) *Server {
	rotationSrvMu.Lock()
	defer rotationSrvMu.Unlock()
	return rotationSrvByURL[ts.URL]
}
