package slack

import "testing"

func TestPageSizeFrom(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
		want   int
	}{
		{"missing", map[string]any{}, defaultPageSize},
		{"zero clamped to default", map[string]any{"page_size": 0}, defaultPageSize},
		{"negative clamped to default", map[string]any{"page_size": -5}, defaultPageSize},
		{"in range int", map[string]any{"page_size": 25}, 25},
		{"at cap", map[string]any{"page_size": 100}, 100},
		{"over cap clamped", map[string]any{"page_size": 1000}, maxPageSize},
		{"int64", map[string]any{"page_size": int64(50)}, 50},
		{"float64 (JSON)", map[string]any{"page_size": float64(75)}, 75},
		{"non-numeric falls back to default", map[string]any{"page_size": "lots"}, defaultPageSize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pageSizeFrom(tc.params)
			if got != tc.want {
				t.Fatalf("pageSizeFrom(%v) = %d, want %d", tc.params, got, tc.want)
			}
		})
	}
}

func TestCursorFrom(t *testing.T) {
	if got := cursorFrom(map[string]any{}); got != "" {
		t.Fatalf("missing cursor: got %q, want empty", got)
	}
	if got := cursorFrom(map[string]any{"cursor": "abc123"}); got != "abc123" {
		t.Fatalf("present cursor: got %q, want abc123", got)
	}
	// Non-string cursor — discard rather than crash.
	if got := cursorFrom(map[string]any{"cursor": 42}); got != "" {
		t.Fatalf("non-string cursor: got %q, want empty", got)
	}
}

func TestNextCursorFrom(t *testing.T) {
	// Fully exhausted result — no metadata.
	if got := nextCursorFrom(map[string]any{}); got != "" {
		t.Fatalf("no metadata: got %q, want empty", got)
	}
	// Empty next_cursor — Slack signal for "no more pages".
	body := map[string]any{
		"response_metadata": map[string]any{"next_cursor": ""},
	}
	if got := nextCursorFrom(body); got != "" {
		t.Fatalf("empty next_cursor: got %q, want empty", got)
	}
	// Real next_cursor — pass through verbatim.
	body = map[string]any{
		"response_metadata": map[string]any{"next_cursor": "dXNlcjpVMDYxTkZUVDI="},
	}
	if got := nextCursorFrom(body); got != "dXNlcjpVMDYxTkZUVDI=" {
		t.Fatalf("real next_cursor: got %q, want dXNlcjpVMDYxTkZUVDI=", got)
	}
}
