package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/trilitech/Sieve/internal/csrf"
	"github.com/trilitech/Sieve/internal/operator"
	"github.com/trilitech/Sieve/internal/session"
)

// Spec 001-fix-security-vulns US7 / FR-028..FR-033d.
//
// This file contains:
//   - sessionContextKey + helpers for handlers to read the active
//     operator session out of the request context.
//   - requireOperatorSession middleware that gates a handler chain
//     on a valid cookie + (for state-changing methods) a CSRF token.
//   - handleLoginGet / handleLoginPost — render + accept the login form.
//   - handleLogout — clear session + cookie.
//   - handleSetupGet / handleSetupPost — first-run credential setup.
//
// The middleware is opt-in per endpoint via wrapAuth(). Endpoints
// that don't call wrapAuth() remain accessible without a session —
// preserving existing test-bench behavior while the wiring lands
// incrementally. The follow-up commit wraps the entire admin
// router and removes the rejectIfAgentToken helper (US8).

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
// Used by audit producers (spec FR-037, US9).
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
//
//   - Sieve has no operator credential configured yet → redirect
//     to /setup for GET / show "service locked" 503 for other
//     methods. Lets a fresh install bootstrap without panicking.
//   - Cookie missing or session unknown → redirect to /login on
//     GET, 401 on other methods.
//   - Session expired (sliding-window past idle timeout) → row
//     deleted by Lookup; same outcome as "missing".
//   - State-changing method (POST/PUT/PATCH/DELETE) without a
//     valid CSRF token → 403.
//   - Success → session attached to context as sessionCtxKey.
//
// When the Server has no operator service wired (SetAuth never
// called — typical for tests that don't need auth), the middleware
// is a pass-through. This is the temporary "land infrastructure
// first, wire it second" pattern; the follow-up commit removes
// this branch and makes auth mandatory.
func (s *Server) requireOperatorSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Auth services MUST be wired before any admin endpoint is
		// reachable. The previous commit (foundation) tolerated nil
		// services as a transitional pass-through; this commit makes
		// the gate mandatory per FR-028.
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
			// can install credentials. Setup page itself is exempt
			// (see wrapAuth's exemption set), so this redirect
			// won't loop.
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			http.Error(w, "operator credential setup required", http.StatusServiceUnavailable)
			return
		}

		cookie, err := r.Cookie(session.CookieName)
		if err != nil || cookie.Value == "" {
			// FR-036: when the requester is presenting a Sieve agent
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
// agent. FR-036: the middleware surfaces 403 for these so operators
// inspecting agent behavior get a clear "wrong port" signal.
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
		w.WriteHeader(http.StatusUnauthorized)
		renderLoginPage(w, "invalid credentials")
		return
	}

	sess, err := s.sessionMgr.Issue(clientIP(r), r.UserAgent())
	if err != nil {
		http.Error(w, "session create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Secure flag is set when the listener serves TLS — detected via
	// r.TLS being non-nil. Loopback HTTP development bypasses Secure
	// so the cookie is still sent on plaintext loopback.
	secure := r.TLS != nil
	http.SetCookie(w, session.NewCookie(sess.Plaintext, secure))
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
	renderSetupPage(w, "")
}

func (s *Server) handleSetupPost(w http.ResponseWriter, r *http.Request) {
	if s.operatorSvc == nil || s.sessionMgr == nil {
		http.Error(w, "auth not configured", http.StatusServiceUnavailable)
		return
	}
	exists, _ := s.operatorSvc.Exists()
	if exists {
		http.NotFound(w, r)
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
	sess, err := s.sessionMgr.Issue(clientIP(r), r.UserAgent())
	if err != nil {
		http.Error(w, "session create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	secure := r.TLS != nil
	http.SetCookie(w, session.NewCookie(sess.Plaintext, secure))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// renderLoginPage / renderSetupPage are intentionally tiny inline
// templates rather than full Tailwind-styled pages. The follow-up
// UI commit promotes them to proper templates next to nav.html.
// Embedding them inline here keeps the auth landing self-contained.
func renderLoginPage(w http.ResponseWriter, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
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

