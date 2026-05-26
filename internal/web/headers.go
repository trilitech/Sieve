package web

import "net/http"

// WriteSensitive sets the cache-prevention header set required on every
// response that may carry a credential, secret, or one-time-use value.
// Spec 001-fix-security-vulns US11 / FR-044..FR-045.
//
// Belt-and-suspenders: the header set covers HTTP/1.1 (Cache-Control),
// HTTP/1.0 (Pragma, Expires), and pins Vary on Authorization so any
// future shared cache that ignores Cache-Control at least segregates
// by credential. Call BEFORE w.WriteHeader / w.Write — headers committed
// after the body bytes start are ignored by net/http.
func WriteSensitive(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store, no-cache, max-age=0, must-revalidate, private")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
	h.Set("Vary", "Authorization")
}

// noCacheAllAdmin wraps an http.Handler and writes the sensitive-header
// set on every response. The admin UI is the human surface; we treat
// every response there as potentially containing a credential / audit
// record / token list value the operator does not want cached by an
// intermediate proxy. The cost is four extra response headers per request,
// which is negligible compared to the alternative of an operator missing
// a per-handler header call (Shannon AUTH-VULN-10 was exactly that case
// on /tokens/create).
func noCacheAllAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteSensitive(w)
		next.ServeHTTP(w, r)
	})
}
