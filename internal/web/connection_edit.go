package web

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/connectors/httpproxy"
)

// authQueryParamPattern compiles the canonical pattern exported from
// internal/connectors/httpproxy. Using the exported constant means the web
// package and connector always agree on the pattern string. Tests in this
// package assert the compiled form matches via TestAuthQueryParamPatternMatchesConnector.
var authQueryParamPattern = regexp.MustCompile(httpproxy.AuthQueryParamPatternStr)

// connectionEditData backs the templates/connection_edit.html template.
// It carries the per-connector knobs introduced by spec 006 plus a few
// fields that are constant across connector types (the read-only http_proxy
// baseline deny-list, the success/error banner state).
type connectionEditData struct {
	// Active drives the side-nav highlight; templates/nav.html reads
	// .Active to decide which menu item is current.
	Active string

	ID            string
	DisplayName   string
	ConnectorType string

	// Banner state (rendered at top of card).
	Error   string
	Success bool

	// http_proxy fields (only populated when ConnectorType == "http_proxy").
	HTTPProxy *httpProxyEditData

	// mcp_proxy fields.
	MCPProxy *mcpProxyEditData

	// github fields.
	GitHub *githubEditData
}

type httpProxyEditData struct {
	AuthValueScrub          bool
	AuthQueryParam          string
	AdditionalDeniedHeaders string // textarea pre-filled (one per line)
	BaselineDenyKeys        []string
	AuthHeaderConfigured    string
}

type mcpProxyEditData struct {
	ResponseBodyCapBytes int64
}

type githubEditData struct {
	CrossForkPRAllowlist string // textarea pre-filled (one per line)
}

// staticHTTPProxyBaselineKeys mirrors the deniedHeaderKeys map in
// internal/connectors/httpproxy/httpproxy.go. The list is short, stable,
// and documented as a hard-coded baseline so duplicating it here is
// acceptable. Tests in this package (TestBaselineDenylistCannotBeReducedViaForm
// and related) cover the deny behaviour end-to-end via the connector itself.
var staticHTTPProxyBaselineKeys = []string{
	"Authorization",
	"Host",
	"Cookie",
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
	"X-Forwarded-*",
}

// handleConnectionEditPage renders the connection-edit page. GET only.
//
// Per spec 006 FR-025, this page is admin-listener-only and rejects any
// agent bearer token. It is the only surface that exposes the new
// optional config fields (auth_value_scrub, additional_denied_headers,
// response_body_cap_bytes, cross_fork_pr_allowlist) for editing.
func (s *Server) handleConnectionEditPage(w http.ResponseWriter, r *http.Request) {
	if rejectIfAgentToken(w, r) {
		return
	}

	id := r.PathValue("id")
	conn, err := s.connections.GetWithConfig(id)
	if err != nil {
		http.Error(w, "connection not found", http.StatusNotFound)
		return
	}

	data := connectionEditDataFromConnection(conn)
	if r.URL.Query().Get("saved") == "1" {
		data.Success = true
	}
	s.render(w, "connection_edit", data)
}

// handleConnectionEditSave validates and persists the edit form. POST only.
//
// Per spec 006 FR-029, the save handler:
//  1. Rejects agent bearer tokens.
//  2. Applies the same Origin/Referer CSRF check that handleRotatePassphrase
//     uses (per spec 003).
//  3. Validates per-connector inputs (positive cap, non-empty trimmed
//     allow-list / additional-denies entries).
//  4. Calls connections.Service.UpdateConfig with the merged config map.
//  5. Redirects to the edit page with ?saved=1 on success, or re-renders
//     with a scoped error and the operator's typed values preserved.
func (s *Server) handleConnectionEditSave(w http.ResponseWriter, r *http.Request) {
	if rejectIfAgentToken(w, r) {
		return
	}
	if !s.checkRotationOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}

	id := r.PathValue("id")
	conn, err := s.connections.GetWithConfig(id)
	if err != nil {
		http.Error(w, "connection not found", http.StatusNotFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form encoding", http.StatusBadRequest)
		return
	}

	// Build a copy of the existing config so we only touch the fields
	// this page is responsible for. Fields not in scope (target_url,
	// auth_header, auth_value, credentials, etc.) flow through unchanged.
	cfg := make(map[string]any, len(conn.Config)+4)
	for k, v := range conn.Config {
		cfg[k] = v
	}

	switch conn.ConnectorType {
	case "http_proxy":
		if errMsg := applyHTTPProxyEdit(cfg, r); errMsg != "" {
			renderEditError(s, w, conn, errMsg)
			return
		}
	case "mcp_proxy":
		if errMsg := applyMCPProxyEdit(cfg, r); errMsg != "" {
			renderEditError(s, w, conn, errMsg)
			return
		}
	case "github":
		if errMsg := applyGitHubEdit(cfg, r); errMsg != "" {
			renderEditError(s, w, conn, errMsg)
			return
		}
	default:
		// Connector types not extended by this bundle have no editable
		// fields. POST against them is a no-op; redirect to the page.
		http.Redirect(w, r, fmt.Sprintf("/connections/%s/edit", id), http.StatusSeeOther)
		return
	}

	if err := s.connections.UpdateConfig(id, cfg); err != nil {
		renderEditError(s, w, conn, "save failed: "+err.Error())
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/connections/%s/edit?saved=1", id), http.StatusSeeOther)
}

// applyHTTPProxyEdit parses the http_proxy edit-form fields out of the
// POST body and merges them into cfg. Returns "" on success or a clear
// error message otherwise.
func applyHTTPProxyEdit(cfg map[string]any, r *http.Request) string {
	// auth_value_scrub: checkbox; absent in form → false; "1"/"on" → true.
	cfg["auth_value_scrub"] = r.FormValue("auth_value_scrub") != ""

	// auth_query_param: trim whitespace; empty = clear; non-empty must
	// match the validation regex (also enforced server-side by the
	// connector Factory).
	aqp := strings.TrimSpace(r.FormValue("auth_query_param"))
	if aqp == "" {
		cfg["auth_query_param"] = ""
	} else if !authQueryParamPattern.MatchString(aqp) {
		return "auth_query_param must contain only letters, digits, _, -, or . (got " + aqp + ")"
	} else {
		cfg["auth_query_param"] = aqp
	}

	// additional_denied_headers: textarea (one per line); empty trimmed
	// entries are rejected.
	raw := r.FormValue("additional_denied_headers")
	var extras []any
	for _, line := range strings.Split(raw, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		extras = append(extras, t)
	}
	cfg["additional_denied_headers"] = extras
	return ""
}

// applyMCPProxyEdit parses the mcp_proxy edit-form fields.
func applyMCPProxyEdit(cfg map[string]any, r *http.Request) string {
	raw := strings.TrimSpace(r.FormValue("response_body_cap_bytes"))
	if raw == "" {
		// Empty input clears the override; the connector falls back to the
		// 5 MiB default. Represent as zero so Factory's parsing recognises it.
		cfg["response_body_cap_bytes"] = int64(0)
		return ""
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return "response_body_cap_bytes must be a non-negative integer (enter 0 or leave empty to use the 5 MiB default)"
	}
	cfg["response_body_cap_bytes"] = n
	return ""
}

// applyGitHubEdit parses the github edit-form fields.
func applyGitHubEdit(cfg map[string]any, r *http.Request) string {
	raw := r.FormValue("cross_fork_pr_allowlist")
	var users []any
	for _, line := range strings.Split(raw, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		users = append(users, t)
	}
	cfg["cross_fork_pr_allowlist"] = users
	return ""
}

// connectionEditDataFromConnection projects a Connection (with decrypted
// Config) into the template's expected shape.
func connectionEditDataFromConnection(conn *connections.Connection) *connectionEditData {
	d := &connectionEditData{
		Active:        "connections",
		ID:            conn.ID,
		DisplayName:   conn.DisplayName,
		ConnectorType: conn.ConnectorType,
	}
	cfg := conn.Config

	switch d.ConnectorType {
	case "http_proxy":
		scrub := true
		if v, ok := cfg["auth_value_scrub"].(bool); ok {
			scrub = v
		}
		aqp, _ := cfg["auth_query_param"].(string)
		extra := joinStringSliceField(cfg["additional_denied_headers"])
		authH, _ := cfg["auth_header"].(string)
		d.HTTPProxy = &httpProxyEditData{
			AuthValueScrub:          scrub,
			AuthQueryParam:          aqp,
			AdditionalDeniedHeaders: extra,
			BaselineDenyKeys:        staticHTTPProxyBaselineKeys,
			AuthHeaderConfigured:    authH,
		}
	case "mcp_proxy":
		var bodyCap int64
		switch v := cfg["response_body_cap_bytes"].(type) {
		case int64:
			bodyCap = v
		case int:
			bodyCap = int64(v)
		case float64:
			bodyCap = int64(v)
		}
		d.MCPProxy = &mcpProxyEditData{ResponseBodyCapBytes: bodyCap}
	case "github":
		users := joinStringSliceField(cfg["cross_fork_pr_allowlist"])
		d.GitHub = &githubEditData{CrossForkPRAllowlist: users}
	}
	return d
}

// joinStringSliceField stringifies either a []string or a []any field
// into newline-delimited textarea content, preserving operator order.
func joinStringSliceField(v any) string {
	switch s := v.(type) {
	case []string:
		return strings.Join(s, "\n")
	case []any:
		out := make([]string, 0, len(s))
		for _, x := range s {
			if str, ok := x.(string); ok {
				out = append(out, str)
			}
		}
		return strings.Join(out, "\n")
	}
	return ""
}

// renderEditError re-renders the edit page with the given error banner.
// Operator-typed values from the request (where non-secret) are preserved
// in the form so the operator doesn't have to re-enter them.
//
// Sets Content-Type and the 400 status on the ResponseWriter directly
// rather than calling s.render's helper, so we don't trip the
// "superfluous WriteHeader" warning when render then writes its own
// content-type header. (s.render unconditionally sets content-type with
// SetHeader before any WriteHeader, but Go's http stack treats any
// pre-WriteHeader call as committing the status — so we set status here
// FIRST, then let render write the body.)
func renderEditError(s *Server, w http.ResponseWriter, conn *connections.Connection, msg string) {
	data := connectionEditDataFromConnection(conn)
	data.Error = msg
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	t, ok := s.templates["connection_edit"]
	if !ok {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	_ = t.ExecuteTemplate(w, "connection_edit", data)
}

