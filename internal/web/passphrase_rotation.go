package web

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/trilitech/Sieve/internal/secrets"
	"github.com/trilitech/Sieve/internal/settings"
)

// rotateLockoutThreshold is the number of consecutive wrong-current-passphrase
// submissions that trigger the cooldown.
const rotateLockoutThreshold = 5

// rotateLockoutCooldown is the duration of the lockout (15 minutes);
// tests override via setRotateLockoutCooldownForTest.
var rotateLockoutCooldown = 15 * time.Minute

// SetRotateLockoutCooldownForTest is a test-only knob. Production callers
// MUST NOT use this. Tests use a sub-second cooldown so they can verify
// the cooldown-clearing branch deterministically.
func SetRotateLockoutCooldownForTest(d time.Duration) (restore func()) {
	prev := rotateLockoutCooldown
	rotateLockoutCooldown = d
	return func() { rotateLockoutCooldown = prev }
}

// handleRotatePassphrase serves POST /settings/rotate-passphrase. It runs an
// online rotation against the running keyring and re-renders the Settings
// page with a success card (303 PRG redirect) or a typed error chip.
// Order of validation gates:
//  1. requireOperatorSession (upstream middleware) — verifies the session
//     cookie + CSRF token and rejects any agent bearer token with 403.
//  2. checkRotationOrigin — Origin/Referer allow-list (defence-in-depth).
//  3. checkRotationLockout — per-process brute-force lockout.
//  4. Field presence.
//  5. Confirmation match.
//  6. New != current.
//  7. keyring.Rotate (verifies current passphrase, runs the SQL tx and the
//     in-memory KEK swap, writes the audit row inside the same tx).
func (s *Server) handleRotatePassphrase(w http.ResponseWriter, r *http.Request) {
	if !s.checkRotationOrigin(r) {
		http.Error(w, "rotation requires same-origin admin UI submission", http.StatusForbidden)
		return
	}

	// Parse the form so we can read the three password fields. ParseForm
	// must be called before any access to r.PostForm; failure here means
	// the request body was unreadable.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}

	// Read the three fields, then immediately remove them from the
	// PostForm map so a downstream handler accident (or a future error
	// path) cannot echo them back into the rendered HTML.
	current := []byte(r.PostForm.Get("current_passphrase"))
	newPP := []byte(r.PostForm.Get("new_passphrase"))
	confirm := []byte(r.PostForm.Get("new_passphrase_confirm"))
	r.PostForm.Del("current_passphrase")
	r.PostForm.Del("new_passphrase")
	r.PostForm.Del("new_passphrase_confirm")
	defer zeroBytes(current)
	defer zeroBytes(newPP)
	defer zeroBytes(confirm)

	// Lockout check. Returning here MUST happen before any argon2 work
	// so a locked-out attacker cannot keep the CPU pinned by submitting
	// forms.
	if locked, retryAfter := s.checkRotationLockout(); locked {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
		s.renderRotationError(w, r, http.StatusLocked,
			fmt.Sprintf("rotation form temporarily locked due to repeated failures (try again in %d minutes)",
				int(retryAfter.Minutes())+1))
		return
	}

	if len(current) == 0 || len(newPP) == 0 || len(confirm) == 0 {
		s.renderRotationError(w, r, http.StatusOK, "all three passphrase fields are required")
		return
	}
	if subtle.ConstantTimeCompare(newPP, confirm) != 1 {
		s.renderRotationError(w, r, http.StatusOK, "new passphrase and confirmation do not match")
		return
	}
	if subtle.ConstantTimeCompare(newPP, current) == 1 {
		s.renderRotationError(w, r, http.StatusOK, "new passphrase identical to current; no rotation performed")
		return
	}

	// Drive the rotation. The audit row is written inside the rotation
	// transaction by the auditor adapter, so a rolled-back rotation
	// leaves no stray row.
	auditor := s.audit.AsRotationAuditor("ui")
	count, err := s.keyring.Rotate(s.db.DB, current, newPP, auditor)
	if err != nil {
		switch {
		case errors.Is(err, secrets.ErrAlreadyRotating):
			http.Error(w, "another rotation is already in progress", http.StatusConflict)
			return
		case errors.Is(err, secrets.ErrWrongPassphrase):
			s.recordRotationFailure()
			s.renderRotationError(w, r, http.StatusOK, "current passphrase incorrect")
			return
		case errors.Is(err, secrets.ErrCryptoMetaMissing):
			s.renderRotationError(w, r, http.StatusInternalServerError,
				"keyring not initialized — first-run setup has not been completed on this database")
			return
		case errors.Is(err, secrets.ErrKeyringNotLoaded):
			http.Error(w, "service locked: passphrase required", http.StatusServiceUnavailable)
			return
		default:
			// Unexpected failure (I/O error, transaction rollback, etc.).
			// The error message is surfaced to the operator without
			// echoing any input.
			s.renderRotationError(w, r, http.StatusInternalServerError,
				"rotation failed: "+err.Error())
			return
		}
	}

	// Success: reset the lockout counter, then PRG-redirect so refresh
	// is safe and the URL carries the count for the success card.
	s.resetRotationFailures()
	http.Redirect(w, r, fmt.Sprintf("/settings?rotated=1&count=%d", count), http.StatusSeeOther)
}

// renderRotationError re-renders the Settings page with the rotation form
// chip set to msg. The three submitted form fields are NEVER echoed back
// — the caller is responsible for not having stuffed them into the
// template data, and this helper does not read them.
func (s *Server) renderRotationError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	// Build the same template data shape that handleSettings produces so
	// the existing settings.html partials render correctly. The rotation
	// error chip is keyed off the new RotationError field.
	allSettings, err := s.settings.GetAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	conns, err := s.connections.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	maxTokens := allSettings[settings.KeyLLMMaxTokens]
	if maxTokens == "" {
		maxTokens = "4096"
	}
	data := map[string]any{
		"Active":        "settings",
		"Connections":   conns,
		"LLMConnection": allSettings[settings.KeyLLMConnection],
		"LLMModel":      allSettings[settings.KeyLLMModel],
		"LLMMaxTokens":  maxTokens,
		"RotationError": msg,
	}
	// Failed-rotation responses MUST NOT be cached. A shared HTTP cache or a
	// browser bfcache entry could replay the page (and the visible
	// rotation-error chip) to a later operator. The form fields aren't
	// echoed, but the *fact that a rotation failed* is itself a
	// signal we don't want to leak to a different session on the same
	// machine.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	s.render(w, r, "settings", data)
}

// checkRotationOrigin is a lightweight, defense-in-depth CSRF check layered
// on top of the session CSRF token that requireOperatorSession already
// enforces on every state-mutating admin POST. It rejects a request whose
// Origin (or, as a fallback, Referer) is PRESENT but matches neither the
// request's own Host NOR the operator-configured canonical host
// (public_base_url) — the signature of a cross-origin form submission.
//
// Why accept public_base_url too, not just r.Host: behind an HTTP reverse
// proxy (or the exposure portal) the app sees a REWRITTEN Host header — e.g.
// the browser is at https://sieve.example while the app receives
// Host: 127.0.0.1:19816. A strict r.Host match then rejects every legitimate
// admin POST with a spurious "cross-origin request rejected". public_base_url
// is the operator's own declaration of the canonical URL, so an Origin that
// matches it is same-origin by definition; an attacker's page still carries a
// foreign Origin and is rejected. (An SSH -L tunnel forwards bytes verbatim,
// so Origin and Host already agree there — this only helps the proxy case.)
//
// It deliberately does NOT reject when both Origin and Referer are absent.
// A cross-origin attacker cannot suppress the Origin header: browsers force
// it onto every cross-origin state-changing request, so a forged CSRF POST
// always arrives WITH a (mismatching) Origin and is caught above. An ABSENT
// Origin is instead what several legitimate SAME-origin submissions look like
// here — this app sends `Referrer-Policy: no-referrer` (so the Referer
// fallback is always empty), and browsers such as Safari omit Origin on
// same-origin classic form POSTs. Rejecting those produced a spurious
// "cross-origin request rejected" with no security benefit; the session CSRF
// token remains the primary guarantee in the absent case.
func (s *Server) checkRotationOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" || origin == "null" {
		// Absent, or the opaque origin "null". Chrome sends `Origin: null` on a
		// form-navigation POST when the document's Referrer-Policy is
		// no-referrer (which this app sets) — so a legitimate same-origin admin
		// form submission arrives with Origin: null and NO host to match. It is
		// indistinguishable from the absent case and must be treated the same:
		// fall through to the session CSRF token, which is the primary guard.
		// This is safe as defence-in-depth — an attacker cannot read the
		// victim's per-session CSRF token, so the token check still blocks the
		// forged POST regardless of what Origin it carries.
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Host == r.Host {
		return true
	}
	// Accept the operator-configured canonical host (public_base_url). This is
	// what makes the check work behind a Host-rewriting reverse proxy.
	if pub, perr := url.Parse(s.publicBaseURL(r)); perr == nil && pub.Host != "" && u.Host == pub.Host {
		return true
	}
	// Log the ground truth so a genuine misconfiguration (operator browsing a
	// host that is neither r.Host nor public_base_url) is diagnosable instead of
	// an opaque 403. Origin/Host are not secrets.
	log.Printf("admin POST rejected as cross-origin: origin_host=%q request_host=%q public_base_url=%q path=%s — set public_base_url to the URL you browse the admin UI at",
		u.Host, r.Host, s.publicBaseURL(r), r.URL.Path)
	return false
}

// zeroBytes overwrites a byte slice in place. Same shape as the helper
// in cmd/sieve/main.go; duplicated here to keep this file self-contained.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// --- Lockout state machine (Phase 4) ---
// Scope:
// - Per-process. State lives on the *Server, so a Sieve restart clears
// the counter and the cooldown. An attacker who can force a restart
// (or wait through one) bypasses the lockout. Acceptable here because
// the only surface that hits this state machine is the admin web UI,
// which is single-process and not exposed to agents.
// - Global, not per-source. A locked-out form blocks every browser and
// every IP; a legitimate operator from a different machine cannot
// submit until the cooldown elapses. Sieve is admin-only with a
// small operator population, so we accept the friction in exchange
// for a much simpler state machine. If multi-operator deployments
// ever become a goal, scope this by source IP (and persist across
// restarts).

// checkRotationLockout returns (true, retryAfter) if the rotation form is
// currently in cooldown (5 consecutive wrong-current-passphrase
// submissions trigger a 15-minute cooldown).
// Side effect: if the cooldown has elapsed since the last check, the
// counter and the lockout are cleared so the next submission runs
// normally — saving callers from a separate "expired-lockout cleanup"
// goroutine.
func (s *Server) checkRotationLockout() (locked bool, retryAfter time.Duration) {
	s.rotateMu.Lock()
	defer s.rotateMu.Unlock()
	if s.rotateLockedTil.IsZero() {
		return false, 0
	}
	now := time.Now()
	if now.Before(s.rotateLockedTil) {
		return true, s.rotateLockedTil.Sub(now)
	}
	// Cooldown elapsed. Clear and let the caller proceed.
	s.rotateFailures = 0
	s.rotateLockedTil = time.Time{}
	return false, 0
}

// recordRotationFailure increments the consecutive-failure counter and,
// when the count reaches rotateLockoutThreshold, sets the cooldown
// expiry and writes a single audit row for the lockout-trigger event.
// Returns true when this call triggered the lockout (caller does not
// need this signal today, but it makes the state transition explicit
// for future callers).
func (s *Server) recordRotationFailure() (triggeredLockout bool) {
	s.rotateMu.Lock()
	s.rotateFailures++
	if s.rotateFailures == rotateLockoutThreshold {
		s.rotateLockedTil = time.Now().Add(rotateLockoutCooldown)
		triggeredLockout = true
	}
	s.rotateMu.Unlock()

	if triggeredLockout {
		// Write the lockout-trigger audit row outside the rotation
		// transaction (there is no rotation transaction — verification
		// failed). Exactly one row per cooldown. LogRotationLockout is
		// best-effort: an error here is logged but does not change the
		// lockout's enforcement.
		_ = s.audit.LogRotationLockout("ui", rotateLockoutThreshold)
	}
	return
}

// resetRotationFailures clears the counter and any active lockout.
// Called on a successful rotation.
func (s *Server) resetRotationFailures() {
	s.rotateMu.Lock()
	s.rotateFailures = 0
	s.rotateLockedTil = time.Time{}
	s.rotateMu.Unlock()
}

// SetRotateLockedTilForTest sets the lockout-expiry directly. Test-only
// helper for verifying the cooldown-clearing branch without sleeping.
// Production callers MUST NOT use this.
func (s *Server) SetRotateLockedTilForTest(t time.Time) {
	s.rotateMu.Lock()
	s.rotateLockedTil = t
	s.rotateMu.Unlock()
}
