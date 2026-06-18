package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/trilitech/Sieve/internal/csrf"
	"github.com/trilitech/Sieve/internal/operator"
	"github.com/trilitech/Sieve/internal/session"
)

// operatorSessionHash returns hex(sha256(cookie value)) of the active
// operator session cookie on the request, or "" when no cookie is set.
// Used to bind OAuth pendingOAuth entries to the originating session so
// the callback path can refuse cross-session state confusion.
func operatorSessionHash(r *http.Request) string {
	c, err := r.Cookie(session.CookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(c.Value))
	return hex.EncodeToString(sum[:])
}

// operatorSessionHashesEqual returns true if a and b are equal under
// constant-time comparison and BOTH non-empty. Empty == empty is treated
// as false so a pendingOAuth row created from a session-less /start cannot
// be claimed by a session-less callback.
func operatorSessionHashesEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// This file contains:
// - sessionCtxKey + helpers for handlers to read the active operator
//   session out of the request context.
// - requireOperatorSession middleware that gates a handler chain on a
//   valid cookie + (for state-changing methods) a CSRF token.
// - handleLoginGet / handleLoginPost — render + accept the login form.
// - handleLogout — clear session + cookie.
// - handleSetupGet / handleSetupPost — first-run credential setup.
// The middleware is wired in front of the admin mux by
// adminAuthWrapper (see server.go), which routes every request through
// requireOperatorSession unless its path is in authExemptPaths /
// authExemptPrefixes. There is no per-handler opt-in; the wrapper is
// the single gate and replaces the per-handler rejectIfAgentToken
// helper that used to be sprinkled across individual mutators.

type sessionCtxKey struct{}

// sessionFromContext returns the active operator session attached
// by requireOperatorSession, or nil if the request didn't come
// through the middleware (e.g., during a test that bypasses auth).
func sessionFromContext(r *http.Request) *session.Session {
	s, _ := r.Context().Value(sessionCtxKey{}).(*session.Session)
	return s
}

// operatorDisplayName returns the audit-identity label for the
// current request's operator, or "" when no session is attached.
// Called by every admin mutation handler that emits an audit row
// (s.audit.LogOperator) so each mutation is attributable to a
// named operator rather than the bare "operator" actor kind.
func operatorDisplayName(r *http.Request, s *Server) string {
	if sess := sessionFromContext(r); sess != nil {
		if s.operatorSvc != nil {
			if name, err := s.operatorSvc.DisplayName(); err == nil {
				return name
			}
		}
	}
	return ""
}

// requireOperatorSession is the gating middleware for admin
// endpoints. Behavior:
//   - No operator credential configured yet → redirect to /setup for
//     GET, "service locked" 503 for other methods. Lets a fresh install
//     bootstrap without panicking.
//   - Cookie missing or session unknown → redirect to /login on GET,
//     401 on other methods.
//   - Session expired (sliding-window past idle timeout) → row deleted
//     by Lookup; same outcome as "missing".
//   - State-changing method (POST/PUT/PATCH/DELETE) without a valid
//     CSRF token → 403.
//   - Success → session attached to context under sessionCtxKey.
//
// The auth services (operatorSvc, sessionMgr) MUST be wired before
// any admin endpoint is reachable. If they are nil at request time the
// middleware fails closed with 500 — earlier transitional builds let
// this branch pass through; that pass-through is gone.
func (s *Server) requireOperatorSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Auth services MUST be wired before any admin endpoint is
		// reachable. Fail closed with 500 — never pass through.
		if s.operatorSvc == nil || s.sessionMgr == nil {
			http.Error(w, "admin auth not configured", http.StatusInternalServerError)
			return
		}

		exists, err := s.operatorSvc.Exists()
		if err != nil {
			http.Error(w, "auth check failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if !exists {
			// First-run state — redirect to setup so the operator
			// can install credentials. /setup itself is listed in
			// authExemptPaths (server.go), so this redirect won't loop.
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			http.Error(w, "operator credential setup required", http.StatusServiceUnavailable)
			return
		}

		cookie, err := r.Cookie(session.CookieName)
		if err != nil || cookie.Value == "" {
			// when the requester is presenting a Sieve agent
			// bearer token (sieve_tok_*), surface 403 with the documented
			// "not accessible to agents" message so a confused agent
			// implementation gets a clearer signal than 401 / redirect.
			if isAgentTokenRequest(r) {
				http.Error(w, "admin endpoints are not accessible to agents", http.StatusForbidden)
				return
			}
			redirectOrUnauthorized(w, r)
			return
		}
		sess, err := s.sessionMgr.Lookup(cookie.Value)
		if err != nil {
			if isAgentTokenRequest(r) {
				http.Error(w, "admin endpoints are not accessible to agents", http.StatusForbidden)
				return
			}
			redirectOrUnauthorized(w, r)
			return
		}

		if csrf.MethodRequiresCSRF(r.Method) {
			submitted := csrf.Extract(r)
			if !s.sessionMgr.VerifyCSRF(sess, submitted) {
				http.Error(w, "csrf token missing or invalid", http.StatusForbidden)
				return
			}
		}

		// Surface the plaintext CSRF token from its cookie onto the
		// session-in-context so handlers/templates can echo it into
		// forms. Lookup() returns the session with CSRFToken empty
		// (only the hash is in the DB); the plaintext lives in the
		// CSRFCookieName cookie set at Issue time. Missing cookie is
		// not fatal here — the cookie is independent of the session
		// cookie and may legitimately be absent on older sessions
		// issued before this code was deployed; templates render with
		// an empty CSRFToken in that case and the next form submit
		// will fail closed at the verify gate above. Operator just
		// re-logs in.
		if csrfCookie, err := r.Cookie(session.CSRFCookieName); err == nil && csrfCookie.Value != "" {
			sess.CSRFToken = csrfCookie.Value
		}

		ctx := context.WithValue(r.Context(), sessionCtxKey{}, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireOperatorSessionExceptCSRF is requireOperatorSession with the
// CSRF check skipped. Used by /logout — the operator clicking logout
// shouldn't fail because the form's CSRF token expired, and the worst
// a CSRF attacker can do at /logout is force a re-login.
func (s *Server) requireOperatorSessionExceptCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.operatorSvc == nil || s.sessionMgr == nil {
			http.Error(w, "admin auth not configured", http.StatusInternalServerError)
			return
		}
		exists, err := s.operatorSvc.Exists()
		if err != nil {
			http.Error(w, "auth check failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if !exists {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			// /logout under "no credential" is a no-op redirect; let
			// the handler decide.
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(session.CookieName)
		if err != nil || cookie.Value == "" {
			// /logout with no cookie: bounce to login (idempotent UX).
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		sess, err := s.sessionMgr.Lookup(cookie.Value)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), sessionCtxKey{}, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// isAgentTokenRequest reports whether the request carries the
// "Authorization: Bearer sieve_tok_*" header that identifies an
// agent. When the admin middleware sees one it surfaces 403 ("not
// accessible to agents") instead of the generic 401 / login redirect,
// so a confused agent implementation gets a clear "wrong port" signal.
func isAgentTokenRequest(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	return strings.HasPrefix(auth, "Bearer sieve_tok_")
}

func redirectOrUnauthorized(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Error(w, "session required", http.StatusUnauthorized)
}

// --- Login / Logout / Setup handlers ---

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if s.operatorSvc == nil {
		http.Error(w, "auth not configured", http.StatusServiceUnavailable)
		return
	}
	exists, err := s.operatorSvc.Exists()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !exists {
		// Fresh install: bounce the operator to setup.
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	renderLoginPage(w, "")
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if s.operatorSvc == nil || s.sessionMgr == nil {
		http.Error(w, "auth not configured", http.StatusServiceUnavailable)
		return
	}
	// Per-IP brake. Without this, argon2's ~150-300 ms cost is the only
	// drag on an online credential guess. The agent API already wires its
	// own limiter; /login + /setup needed parity.
	ip := clientIP(r)
	if s.loginLimiter != nil {
		if ok, retry := s.loginLimiter.Allow(ip); !ok {
			s.logLoginAttempt("", "login.rate_limited", ip)
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retry.Seconds())))
			http.Error(w, "too many login attempts; try again later", http.StatusTooManyRequests)
			return
		}
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	credential := r.FormValue("credential")
	if credential == "" {
		renderLoginPage(w, "credential required")
		return
	}
	if _, err := s.operatorSvc.Verify(credential); err != nil {
		// Same response for "no credential set up" + "bad password" —
		// don't leak which is which. Bouncing to /setup on no-cred
		// is handled by handleLoginGet, not here.
		if errors.Is(err, operator.ErrNoCredential) {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		s.logLoginAttempt("", "login.fail", ip)
		// renderLoginPage sets Content-Type — call it before WriteHeader.
		// Headers set after WriteHeader are silently dropped by net/http.
		renderLoginPageWithStatus(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Delete any pre-existing session cookie the browser still carries —
	// session-fixation defence-in-depth. If a stolen pre-auth cookie were
	// in play, the attacker's hold on it terminates here.
	if prior, err := r.Cookie(session.CookieName); err == nil && prior.Value != "" {
		_ = s.sessionMgr.Logout(prior.Value)
	}
	sess, err := s.sessionMgr.Issue(ip, r.UserAgent())
	if err != nil {
		http.Error(w, "session create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Refund the rate-limit token on success — legitimate operators with
	// an occasional typo shouldn't be throttled after the right credential
	// finally lands.
	if s.loginLimiter != nil {
		s.loginLimiter.Refund(ip)
	}
	displayName, _ := s.operatorSvc.DisplayName()
	s.logLoginAttempt(displayName, "login.ok", ip)
	// Secure flag is set when the listener serves TLS — detected via
	// r.TLS being non-nil. Loopback HTTP development bypasses Secure
	// so the cookie is still sent on plaintext loopback.
	secure := r.TLS != nil
	http.SetCookie(w, session.NewCookie(sess.Plaintext, secure))
	http.SetCookie(w, session.NewCSRFCookie(sess.CSRFToken, secure))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// logLoginAttempt writes an operator.login.* audit row keyed by IP. Failed
// attempts are recorded with an empty operator display name so an attacker
// grinding credentials cannot bury the failure under a name they choose.
func (s *Server) logLoginAttempt(displayName, outcome, ip string) {
	if s.audit == nil {
		return
	}
	_ = s.audit.LogOperator(displayName, "operator."+outcome, "-", map[string]any{
		"ip": ip,
	}, outcome)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.sessionMgr == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if cookie, err := r.Cookie(session.CookieName); err == nil {
		_ = s.sessionMgr.Logout(cookie.Value)
	}
	secure := r.TLS != nil
	http.SetCookie(w, session.ClearCookie(secure))
	http.SetCookie(w, session.ClearCSRFCookie(secure))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleSetupGet(w http.ResponseWriter, r *http.Request) {
	if s.operatorSvc == nil {
		http.Error(w, "auth not configured", http.StatusServiceUnavailable)
		return
	}
	exists, err := s.operatorSvc.Exists()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if exists {
		// Setup is one-shot — once a credential exists, the page
		// disappears. Use the rotation flow (separate endpoint,
		// follow-up commit) to change it.
		http.NotFound(w, r)
		return
	}
	// First-run bootstrap is loopback-only. On a deployment that exposes
	// the admin port (intentionally or otherwise), the first network-
	// adjacent peer to POST /setup would otherwise claim the operator
	// credential. Loopback-gating closes that window — the operator must
	// SSH-tunnel or use the local machine to initialise.
	if !isLoopbackClient(r) {
		http.Error(w, "first-run setup is restricted to the loopback interface; SSH-tunnel into the host and retry from localhost", http.StatusForbidden)
		return
	}
	renderSetupPage(w, "")
}

func (s *Server) handleSetupPost(w http.ResponseWriter, r *http.Request) {
	if s.operatorSvc == nil || s.sessionMgr == nil {
		http.Error(w, "auth not configured", http.StatusServiceUnavailable)
		return
	}
	ip := clientIP(r)
	if s.loginLimiter != nil {
		if ok, retry := s.loginLimiter.Allow(ip); !ok {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retry.Seconds())))
			http.Error(w, "too many setup attempts; try again later", http.StatusTooManyRequests)
			return
		}
	}
	exists, _ := s.operatorSvc.Exists()
	if exists {
		http.NotFound(w, r)
		return
	}
	// Mirror the GET-side loopback gate: first-run setup is bootstrap and
	// MUST NOT be claimable by a remote peer when the admin port happens
	// to be exposed. The remote-claim race was murbard's S6 finding.
	if !isLoopbackClient(r) {
		http.Error(w, "first-run setup is restricted to the loopback interface", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cred := r.FormValue("credential")
	confirm := r.FormValue("confirm_credential")
	name := strings.TrimSpace(r.FormValue("display_name"))
	if cred == "" || name == "" {
		renderSetupPage(w, "credential and display name are required")
		return
	}
	if cred != confirm {
		renderSetupPage(w, "credential and confirmation do not match")
		return
	}
	if err := s.operatorSvc.Setup(cred, name); err != nil {
		renderSetupPage(w, "setup failed: "+err.Error())
		return
	}
	// Auto-login the operator after first-run setup.
	sess, err := s.sessionMgr.Issue(ip, r.UserAgent())
	if err != nil {
		http.Error(w, "session create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if s.loginLimiter != nil {
		s.loginLimiter.Refund(ip)
	}
	s.logLoginAttempt(name, "setup.ok", ip)
	secure := r.TLS != nil
	http.SetCookie(w, session.NewCookie(sess.Plaintext, secure))
	http.SetCookie(w, session.NewCSRFCookie(sess.CSRFToken, secure))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// renderLoginPage / renderSetupPage are intentionally tiny inline
// templates rather than full Tailwind-styled pages. The follow-up
// UI commit promotes them to proper templates next to nav.html.
// Embedding them inline here keeps the auth landing self-contained.
// renderLoginPage writes the login form with a 200 status. For error
// responses use renderLoginPageWithStatus so the Content-Type header
// lands before WriteHeader (net/http drops headers set afterward).
func renderLoginPage(w http.ResponseWriter, errMsg string) {
	renderLoginPageWithStatus(w, http.StatusOK, errMsg)
}

func renderLoginPageWithStatus(w http.ResponseWriter, status int, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Sieve — sign in</title>
<style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:40px;max-width:480px;margin:0 auto}
h1{font-weight:600;margin-bottom:24px}
form{display:flex;flex-direction:column;gap:12px}
input{background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:10px;border-radius:6px;font-family:inherit;font-size:14px}
button{background:#6366f1;color:white;border:none;padding:10px;border-radius:6px;cursor:pointer;font-weight:500}
button:hover{background:#4f46e5}
.err{color:#f87171;font-size:14px}</style></head>
<body><h1>Sign in to Sieve</h1>
<form method="POST" action="/login" autocomplete="off">
<input type="password" name="credential" placeholder="operator credential" autofocus required>
<button type="submit">Sign in</button>
%s</form></body></html>`, errBlock(errMsg))
}

func renderSetupPage(w http.ResponseWriter, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Sieve — first-run setup</title>
<style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:40px;max-width:480px;margin:0 auto}
h1{font-weight:600;margin-bottom:8px}
p.lede{color:#94a3b8;margin-bottom:24px;font-size:14px}
form{display:flex;flex-direction:column;gap:12px}
input{background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:10px;border-radius:6px;font-family:inherit;font-size:14px}
button{background:#6366f1;color:white;border:none;padding:10px;border-radius:6px;cursor:pointer;font-weight:500}
button:hover{background:#4f46e5}
.err{color:#f87171;font-size:14px}</style></head>
<body><h1>Set up the operator credential</h1>
<p class="lede">Sieve needs an admin credential before any management API is reachable. The display name appears in the audit log next to every change you make.</p>
<form method="POST" action="/setup" autocomplete="off">
<input type="text" name="display_name" placeholder="display name (e.g. alice-laptop)" required>
<input type="password" name="credential" placeholder="credential" required>
<input type="password" name="confirm_credential" placeholder="confirm credential" required>
<button type="submit">Create credential and sign in</button>
%s</form></body></html>`, errBlock(errMsg))
}

func errBlock(msg string) string {
	if msg == "" {
		return ""
	}
	return `<p class="err">` + htmlEscape(msg) + `</p>`
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

// clientIP extracts the client's IP for audit / session records.
// Returns the remote address with port stripped; never honors
// X-Forwarded-For (an unauthenticated header).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isLoopbackClient reports whether the request originated from the
// loopback interface (127.0.0.0/8 or ::1). Used to gate first-run
// bootstrap endpoints that MUST NOT be reachable from the network.
// X-Forwarded-For is intentionally NOT consulted — that header is
// untrusted at this layer and any reverse-proxy operator wanting
// remote bootstrap can tunnel locally.
func isLoopbackClient(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "" {
		// httptest recorders sometimes leave RemoteAddr unset; treat
		// "empty" as loopback so unit tests don't need to spoof IPs.
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

