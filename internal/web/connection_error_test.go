package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trilitech/Sieve/internal/secrets"
)

// TestWriteConnectionError_KeyringStates covers the centralized keyring→HTTP
// mapping every web connection read/write path now routes through (including the
// two handleSlackReauth UpdateConfig calls that previously returned a bare 500).
// The helper touches no Server fields, so a zero-value Server exercises it.
func TestWriteConnectionError_KeyringStates(t *testing.T) {
	s := &Server{}

	t.Run("locked keyring → 503", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.writeConnectionError(w, http.StatusInternalServerError, "boom", secrets.ErrKeyringNotLoaded)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("want 503, got %d", w.Code)
		}
	})

	t.Run("wrapped locked keyring → 503", func(t *testing.T) {
		w := httptest.NewRecorder()
		// Add/UpdateConfig wrap the sentinel; errors.Is must still match.
		s.writeConnectionError(w, http.StatusInternalServerError, "boom", fmt.Errorf("update: %w", secrets.ErrKeyringNotLoaded))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("want 503 for wrapped sentinel, got %d", w.Code)
		}
	})

	t.Run("rotating keyring → 503 + Retry-After", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.writeConnectionError(w, http.StatusInternalServerError, "boom", secrets.ErrKeyringRotating)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("want 503, got %d", w.Code)
		}
		if ra := w.Header().Get("Retry-After"); ra == "" {
			t.Fatal("want a Retry-After header on a rotation-in-progress response, got none")
		}
	})

	t.Run("unrelated error → caller default", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.writeConnectionError(w, http.StatusNotFound, "connection not found", errors.New("no such row"))
		if w.Code != http.StatusNotFound {
			t.Fatalf("want caller default 404, got %d", w.Code)
		}
	})
}
