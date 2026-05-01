package slack

// Slack-side translation for the FR-014 normalized pagination shape.
//
// Normalized agent-facing input: { cursor: string?, page_size: int? }
// Normalized agent-facing output: { items: [...], next_cursor: string }
//
// Slack's native shape is already cursor-based for paginated Web API
// methods (conversations.list, conversations.history, users.list, etc.):
//   - request param `cursor` (opaque, omitted on first call)
//   - request param `limit` (1-1000; we cap at the FR-014 hard cap of 100)
//   - response.response_metadata.next_cursor (empty string when exhausted)
//
// So Slack is a near-passthrough: cursor maps verbatim, page_size maps
// to `limit`, and next_cursor lifts directly from response_metadata.

const (
	// defaultPageSize matches the FR-014 default. Operators who want more
	// must paginate explicitly — server-side auto-pagination is forbidden
	// per the same FR.
	defaultPageSize = 100

	// maxPageSize is the FR-014 hard cap. Slack itself permits up to 1000
	// on most paginated methods, but Sieve enforces 100 across the board
	// so policy authors don't have to reason per-connector.
	maxPageSize = 100
)

// pageSizeFrom resolves the agent-supplied page_size param to a
// Slack `limit` value, applying the default and the hard cap.
func pageSizeFrom(params map[string]any) int {
	v, ok := params["page_size"]
	if !ok {
		return defaultPageSize
	}
	switch x := v.(type) {
	case int:
		return clampPageSize(x)
	case int64:
		return clampPageSize(int(x))
	case float64:
		// JSON numbers decode as float64 through encoding/json.
		return clampPageSize(int(x))
	}
	return defaultPageSize
}

func clampPageSize(n int) int {
	if n <= 0 {
		return defaultPageSize
	}
	if n > maxPageSize {
		return maxPageSize
	}
	return n
}

// cursorFrom extracts the agent's cursor verbatim. Slack's cursors are
// opaque base64-ish strings; we don't parse or validate.
func cursorFrom(params map[string]any) string {
	if c, ok := params["cursor"].(string); ok {
		return c
	}
	return ""
}

// nextCursorFrom lifts response_metadata.next_cursor out of a Slack
// response body. Empty string (or absent metadata) means the result
// set is exhausted.
func nextCursorFrom(body map[string]any) string {
	meta, ok := body["response_metadata"].(map[string]any)
	if !ok {
		return ""
	}
	cur, _ := meta["next_cursor"].(string)
	return cur
}
