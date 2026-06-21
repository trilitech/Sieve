// Package mockslack is a tiny in-process Slack Web API mock used by
// connector tests. It implements only the endpoints the curated Slack
// operation set exercises plus oauth.v2.access for OAuth-callback
// tests.
// The mock is intentionally minimal: enough to drive happy-path and
// terminal-auth-failure code paths in the Slack connector and admin
// UI. It is NOT a faithful Slack simulator.
// Pattern mirrors internal/testing/mockconnector — same shape, but
// instead of implementing the connector.Connector interface it stands
// up an http.Handler that the Slack connector's HTTP client points at
// via the `_base_url` config override.
package mockslack

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
)

// Server wraps a httptest.Server and tracks per-method invocations so
// tests can assert "method X was called once with these params" without
// reaching for a third-party mock library.
type Server struct {
	*httptest.Server

	mu sync.Mutex

	// forceError, if non-empty, makes every Slack-API method return
	// {ok: false, error: forceError} with HTTP 200. Used to drive the
	// terminal-auth-classifier paths from connector_test.
	forceError string

	// channels and users are seeded fixtures returned by list_channels
	// and list_users. Tests can override before calls. Default = small
	// canned set so paginate-past-100 tests work out of the box.
	channels []map[string]any
	users    []map[string]any

	// calls records each request the mock received. Tests assert
	// against this slice to verify the connector translated params
	// correctly (cursor → cursor, page_size → limit, etc.).
	calls []Call
}

// Call records a single inbound API call. Path is the URL path (e.g.
// "/api/conversations.list"), Form is the parsed form body for POST
// or query string for GET.
type Call struct {
	Path string
	Form map[string][]string
}

// New returns a Server with default seed data. The caller is
// responsible for srv.Close — usually `t.Cleanup(s.Close)`.
func New() *Server {
	s := &Server{}
	s.channels = defaultChannels()
	s.users = defaultUsers()
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// SetForceError makes every method return {ok:false, error: code}.
// Use to exercise terminal-auth-classifier paths and reauth-required
// transitions.
func (s *Server) SetForceError(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forceError = code
}

// SetChannels overrides the canned conversations.list fixture. The
// mock paginates the slice using the requested limit + cursor.
func (s *Server) SetChannels(channels []map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.channels = channels
}

// Calls returns a snapshot of recorded invocations.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Call, len(s.calls))
	copy(out, s.calls)
	return out
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.calls = append(s.calls, Call{Path: r.URL.Path, Form: cloneForm(r.Form)})
	forced := s.forceError
	s.mu.Unlock()

	if forced != "" {
		writeJSON(w, map[string]any{"ok": false, "error": forced})
		return
	}

	switch r.URL.Path {
	case "/api/auth.test":
		s.handleAuthTest(w, r)
	case "/api/conversations.list":
		s.handleConversationsList(w, r)
	case "/api/conversations.history":
		s.handleConversationsHistory(w, r)
	case "/api/conversations.replies":
		s.handleConversationsReplies(w, r)
	case "/api/users.list":
		s.handleUsersList(w, r)
	case "/api/users.profile.get":
		s.handleUsersProfileGet(w, r)
	case "/api/chat.postMessage":
		s.handlePostMessage(w, r)
	case "/api/search.messages":
		// Search requires user-token install — return the documented
		// "operation_not_enabled" shape per research R1a.
		writeJSON(w, map[string]any{"ok": false, "error": "not_allowed_token_type"})
	case "/api/oauth.v2.access":
		s.handleOAuthAccess(w, r)
	default:
		writeJSON(w, map[string]any{"ok": false, "error": "unknown_method"})
	}
}

func (s *Server) handleAuthTest(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"ok":      true,
		"team":    "Acme Workspace",
		"team_id": "T012ABCDEF",
		"user":    "sieve-bot",
		"user_id": "U0KRQLJ9H",
	})
}

func (s *Server) handleConversationsList(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit, cursor := parsePaging(r, len(s.channels))
	start := 0
	if cursor != "" {
		// Cursors are decimal indices — opaque to the agent but easy
		// to advance for tests.
		if i, err := strconv.Atoi(cursor); err == nil {
			start = i
		}
	}
	end := start + limit
	if end > len(s.channels) {
		end = len(s.channels)
	}
	page := s.channels[start:end]
	resp := map[string]any{
		"ok":       true,
		"channels": page,
	}
	if end < len(s.channels) {
		resp["response_metadata"] = map[string]any{"next_cursor": strconv.Itoa(end)}
	} else {
		resp["response_metadata"] = map[string]any{"next_cursor": ""}
	}
	writeJSON(w, resp)
}

func (s *Server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit, cursor := parsePaging(r, len(s.users))
	start := 0
	if cursor != "" {
		if i, err := strconv.Atoi(cursor); err == nil {
			start = i
		}
	}
	end := start + limit
	if end > len(s.users) {
		end = len(s.users)
	}
	page := s.users[start:end]
	resp := map[string]any{
		"ok":      true,
		"members": page,
	}
	if end < len(s.users) {
		resp["response_metadata"] = map[string]any{"next_cursor": strconv.Itoa(end)}
	} else {
		resp["response_metadata"] = map[string]any{"next_cursor": ""}
	}
	writeJSON(w, resp)
}

func (s *Server) handleConversationsHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"ok": true,
		"messages": []any{
			map[string]any{"type": "message", "user": "U0K1", "text": "hello", "ts": "1700000001.000100"},
			map[string]any{"type": "message", "user": "U0K2", "text": "world", "ts": "1700000002.000200"},
		},
		"has_more":          false,
		"response_metadata": map[string]any{"next_cursor": ""},
	})
}

func (s *Server) handleConversationsReplies(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"ok": true,
		"messages": []any{
			map[string]any{"type": "message", "user": "U0K1", "text": "thread root", "ts": "1700000001.000100", "thread_ts": "1700000001.000100"},
			map[string]any{"type": "message", "user": "U0K2", "text": "reply", "ts": "1700000003.000100", "thread_ts": "1700000001.000100"},
		},
		"has_more":          false,
		"response_metadata": map[string]any{"next_cursor": ""},
	})
}

func (s *Server) handleUsersProfileGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"ok": true,
		"profile": map[string]any{
			"real_name":    "Alice Tester",
			"display_name": "alice",
			"email":        "alice@example.com",
		},
	})
}

func (s *Server) handlePostMessage(w http.ResponseWriter, r *http.Request) {
	channel := r.FormValue("channel")
	text := r.FormValue("text")
	if channel == "" || text == "" {
		writeJSON(w, map[string]any{"ok": false, "error": "missing_required_param"})
		return
	}
	writeJSON(w, map[string]any{
		"ok":      true,
		"channel": channel,
		"ts":      "1700000099.000100",
		"message": map[string]any{"text": text, "user": "U0KRQLJ9H"},
	})
}

func (s *Server) handleOAuthAccess(w http.ResponseWriter, r *http.Request) {
	// Minimal v2 access response. The connector's OAuth callback uses
	// the access_token + bot_user_id fields.
	writeJSON(w, map[string]any{
		"ok":           true,
		"access_token": "xoxb-test-installed-token",
		"token_type":   "bot",
		"scope":        "channels:read,chat:write",
		"bot_user_id":  "U0KRQLJ9H",
		"app_id":       "A0KRD7HC3",
		"team":         map[string]any{"id": "T012ABCDEF", "name": "Acme Workspace"},
	})
}

// parsePaging extracts limit + cursor from the request, applying the
// normalized default page size when absent. nElems is the underlying
// fixture length, used to clamp `limit` to a reasonable value.
func parsePaging(r *http.Request, nElems int) (limit int, cursor string) {
	limit = 100
	if l := r.FormValue("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > nElems && nElems > 0 {
		limit = nElems
	}
	cursor = r.FormValue("cursor")
	return limit, cursor
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func cloneForm(f map[string][]string) map[string][]string {
	out := make(map[string][]string, len(f))
	for k, vs := range f {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func defaultChannels() []map[string]any {
	chans := make([]map[string]any, 0, 8)
	for i := 0; i < 8; i++ {
		chans = append(chans, map[string]any{
			"id":          fmt.Sprintf("C%07d", i+1),
			"name":        fmt.Sprintf("channel-%d", i+1),
			"is_private":  false,
			"is_archived": false,
			"topic":       map[string]any{"value": ""},
			"purpose":     map[string]any{"value": ""},
		})
	}
	return chans
}

func defaultUsers() []map[string]any {
	return []map[string]any{
		{"id": "U0001", "name": "alice", "real_name": "Alice", "is_bot": false, "deleted": false},
		{"id": "U0002", "name": "bob", "real_name": "Bob", "is_bot": false, "deleted": false},
		{"id": "U0KRQLJ9H", "name": "sieve-bot", "real_name": "Sieve Bot", "is_bot": true, "deleted": false},
	}
}

// LargeChannelSet returns a fixture with n channels — useful for
// pagination tests that need to walk past the normalized page-size cap.
func LargeChannelSet(n int) []map[string]any {
	out := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, map[string]any{
			"id":   fmt.Sprintf("C%07d", i+1),
			"name": fmt.Sprintf("auto-channel-%d", i+1),
		})
	}
	return out
}

// EnsureLeadingSlash trims a base URL to canonical form for the
// connector's _base_url override. Helper since httptest.Server's URL
// has no trailing slash and the connector concatenates `/api/...` paths.
func EnsureLeadingSlash(s string) string {
	if !strings.HasSuffix(s, "/") {
		return s + "/"
	}
	return s
}
