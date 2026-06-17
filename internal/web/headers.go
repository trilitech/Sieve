package web

import "net/http"

// WriteSensitive sets the cache-prevention header set required on every
// response that may carry a credential, secret, or one-time-use value.
// Belt-and-suspenders: the header set covers HTTP/1.1 (Cache-Control),
// HTTP/1.0 (Pragma, Expires), and pins Vary on both Authorization
// (agent-token surface) and Cookie (operator-session surface) so any
// future shared cache that ignores Cache-Control at least segregates
// by credential. Call BEFORE w.WriteHeader / w.Write — headers committed
// after the body bytes start are ignored by net/http.
func WriteSensitive(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store, no-cache, max-age=0, must-revalidate, private")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
	h.Set("Vary", "Authorization, Cookie")
}

// writeSecurityHeaders sets the static security-headers that apply to
// every admin response. Defense-in-depth against a future XSS regression
// or a clickjack pivot: even if a script-injection sink slips back in,
// the CSP refuses to execute cross-origin script (outside the documented
// CDN allowlist); X-Frame-Options refuses to frame; nosniff refuses
// MIME-confusion; no-referrer refuses to leak in-page URLs to third
// parties.
//
// CSP uses 'unsafe-inline' for script-src because admin templates carry
// per-page inline <script> blocks today. Moving those to nonces or
// external files is a larger lift; the inline opener is documented here
// so the next pass can tighten it.
//
// The CDN allowlist is the minimum the bundled templates require:
//   - script-src cdn.tailwindcss.com — Tailwind CDN runtime
//   - script-src cdn.jsdelivr.net    — marked + DOMPurify (docs)
//   - script-src unpkg.com           — htmx (approvals)
//   - style-src + font-src fonts.googleapis.com / fonts.gstatic.com
//     — Inter font, loaded by every admin page header
//
// connect-src also names these hosts because tailwindcss.com's runtime
// fetches its CSS via XHR; without that, the page loads but stays
// unstyled.
func writeSecurityHeaders(w http.ResponseWriter) {
	const cdnScripts = "https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://unpkg.com"
	const cdnStyles = "https://fonts.googleapis.com"
	const cdnFonts = "https://fonts.gstatic.com"
	h := w.Header()
	h.Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' 'unsafe-inline' "+cdnScripts+"; "+
			"style-src 'self' 'unsafe-inline' "+cdnStyles+"; "+
			"font-src 'self' "+cdnFonts+"; "+
			"img-src 'self' data:; "+
			"connect-src 'self' "+cdnScripts+" "+cdnStyles+"; "+
			"object-src 'none'; "+
			"frame-ancestors 'none'; "+
			"base-uri 'none'; "+
			"form-action 'self'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
}

// noCacheAllAdmin wraps an http.Handler and writes both the cache-prevention
// and static security headers on every response. The admin UI is the human
// surface; we treat every response there as potentially containing a
// credential / audit record / token list value the operator does not want
// cached by an intermediate proxy. The cost is a handful of extra response
// headers per request, negligible compared to the alternative of an
// operator missing a per-handler header call.
func noCacheAllAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteSensitive(w)
		writeSecurityHeaders(w)
		next.ServeHTTP(w, r)
	})
}
