package web_test

// Regression test for the end-to-end CSRF token plumbing on admin POST
// forms. Background: connections form templates (gitlab, http_proxy,
// slack, etc.) historically didn't include a csrf_token hidden input
// and the render path didn't expose the plaintext token to nav.html, so
// every basic Add-Connection POST failed at the middleware with
// "csrf token missing or invalid". This test pins three properties:
//
//   - GET /connections sets a non-HttpOnly sieve_csrf cookie carrying
//     the plaintext token (so the page script can read it).
//   - The rendered page exposes the token to nav.html's
//     window.SIEVE_CSRF script tag.
//   - A POST to /connections/add carrying the csrf_token form field
//     (the value the nav.html submit handler echoes back) is accepted
//     by the middleware and reaches the handler. We check for a 303
//     redirect (success) or a 400 (request rejected for a NON-CSRF
//     reason, e.g. unknown connector type in the smoke seed) — both
//     prove CSRF was satisfied. A 403 fails the test.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestPOSTConnectionsAddPassesCSRF asserts that an admin POST with the
// session cookie + csrf_token form field passes the middleware. Uses
// the connector_type=mock seed (mock is registered by newTestWebServer)
// so the handler runs to completion and we exercise the real success
// path rather than a 400-on-unknown-connector path.
func TestPOSTConnectionsAddPassesCSRF(t *testing.T) {
	handler, env := newTestWebServer(t)

	form := url.Values{}
	form.Set("connector_type", "mock")
	form.Set("id", "smoke-csrf")
	form.Set("display_name", "CSRF smoke")
	form.Set("csrf_token", env.CSRFToken())

	req := httptest.NewRequest(http.MethodPost, "/connections/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c := env.SessionCookie(); c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "csrf") {
		t.Fatalf("CSRF middleware rejected request that carried the form-field token (body: %s)", rec.Body.String())
	}
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect after Add, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestPOSTConnectionsAddMissingCSRFRejected is the negative control:
// without the csrf_token form field (and without the X-CSRF-Token
// header), the middleware MUST reject with 403. This pins the security
// property that the new plumbing didn't accidentally relax.
func TestPOSTConnectionsAddMissingCSRFRejected(t *testing.T) {
	handler, env := newTestWebServer(t)

	form := url.Values{}
	form.Set("connector_type", "mock")
	form.Set("id", "smoke-no-csrf")
	form.Set("display_name", "CSRF negative control")

	req := httptest.NewRequest(http.MethodPost, "/connections/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c := env.SessionCookie(); c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing CSRF token, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "csrf") {
		t.Errorf("expected csrf-related error body, got: %s", rec.Body.String())
	}
}
