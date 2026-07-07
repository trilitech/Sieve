package iampolicies

import (
	"testing"

	"github.com/trilitech/Sieve/internal/iam"
)

// TestObligationsToFilters_UnknownKindFailsClosed proves that a post-obligation
// whose kind isn't one of redact/exclude_items/script_filter fails CLOSED
// (returns an error → the caller denies) rather than being silently dropped,
// which would let the response go out unfiltered while the decision stayed allow.
func TestObligationsToFilters_UnknownKindFailsClosed(t *testing.T) {
	_, err := obligationsToFilters([]iam.Filter{
		{Name: "mystery", Kind: iam.FilterKind("some_future_kind")},
	})
	if err == nil {
		t.Fatal("an unknown post-obligation kind must fail closed (error), not be silently dropped")
	}

	// A recognized kind still translates cleanly.
	out, err := obligationsToFilters([]iam.Filter{
		{Name: "r", Kind: iam.KindRedact, Config: map[string]any{"patterns": []any{"x"}}},
	})
	if err != nil {
		t.Fatalf("known kind should translate without error: %v", err)
	}
	if len(out) != 1 || len(out[0].RedactPatterns) != 1 {
		t.Fatalf("expected one redact filter with one pattern, got %+v", out)
	}
}
