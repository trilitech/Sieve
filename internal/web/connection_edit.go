package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/connectors/httpproxy"
)

// authQueryParamPattern is the validation regex enforced by the
// http_proxy connector. We surface a friendlier error message in the
// edit handler when the operator types something invalid, but the
// connector Factory is the source of truth — see the validate_test
// suite for the contract that the two patterns stay in sync.
var authQueryParamPattern = regexp.MustCompile(httpproxy.AuthQueryParamPatternStr)

// connectionEditData backs templates/connection_edit.html.
//
// The form is fully data-driven from the connector's declared Editable
// fields (connector.ConnectorMeta.SetupFields). Adding a field to the
// connector's Meta() automatically surfaces it on this page — the
// template never references a field name directly.
type connectionEditData struct {
	// Active drives the side-nav highlight in templates/nav.html.
	Active string

	ID            string
	DisplayName   string
	ConnectorType string

	Error   string
	Success bool

	// Fields is the ordered list of editable fields the template renders.
	Fields []editFieldView

	// HTTPProxyBaseline carries the static deny-list info displayed
	// alongside the http_proxy edit form. Read-only; not a form field.
	HTTPProxyBaseline *httpProxyBaselineView
}

// editFieldView is the template-friendly projection of a single editable
// field, with the value already resolved from the stored config and
// rendered as the right shape for its Type.
type editFieldView struct {
	Name        string
	Label       string
	Type        string
	Placeholder string
	HelpText    string
	Secret      bool

	// Exactly one of these is populated, by Type.
	StringValue   string // text / password / select / number / json
	BoolValue     bool   // checkbox
	TextareaValue string // textarea (newline-joined)
}

// httpProxyBaselineView lists the always-denied header keys for the
// http_proxy connector. This is informational only — the connector
// enforces it regardless of what the operator submits.
type httpProxyBaselineView struct {
	BaselineDenyKeys     []string
	AuthHeaderConfigured string
}

// staticHTTPProxyBaselineKeys mirrors the deniedHeaderKeys map in
// internal/connectors/httpproxy/httpproxy.go. Tests in this package
// (TestBaselineDenylistCannotBeReducedViaForm and related) cover the
// deny behaviour end-to-end via the connector itself.
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
// Admin-listener-only; rejects any agent bearer token. The set of fields
// shown comes from the connector's declared Editable SetupFields — see
// connection_form.go and internal/connector/connector.go.
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

	data := s.connectionEditViewFromConnection(conn)
	if r.URL.Query().Get("saved") == "1" {
		data.Success = true
	}
	s.render(w, "connection_edit", data)
}

// handleConnectionEditSave validates and persists the edit form.
//
// All field parsing flows through applyConnectorFormFields, which is
// the same code path the create handler uses. The handler itself has no
// per-connector knowledge.
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

	meta, ok := s.registry.Meta(conn.ConnectorType)
	if !ok {
		s.renderEditError(w, conn, "unknown connector type "+conn.ConnectorType)
		return
	}

	// Start from the stored config so non-Editable fields and untouched
	// Secret fields flow through unchanged.
	cfg := make(map[string]any, len(conn.Config)+4)
	for k, v := range conn.Config {
		cfg[k] = v
	}

	if msg := applyConnectorFormFields(meta, formModeEdit, r, cfg); msg != "" {
		s.renderEditError(w, conn, msg)
		return
	}

	// Connector-specific shape check that doesn't belong in the generic
	// bridge. http_proxy enforces a regex on auth_query_param; the
	// connector Factory will reject the same value, but doing the check
	// here gives a clearer banner that preserves the rest of the form.
	if conn.ConnectorType == "http_proxy" {
		if aqp, _ := cfg["auth_query_param"].(string); aqp != "" && !authQueryParamPattern.MatchString(aqp) {
			s.renderEditError(w, conn,
				"auth_query_param must contain only letters, digits, _, -, or . (got "+aqp+")")
			return
		}
	}

	if err := s.connections.UpdateConfig(id, cfg); err != nil {
		s.renderEditError(w, conn, "save failed: "+err.Error())
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/connections/%s/edit?saved=1", id), http.StatusSeeOther)
}

// connectionEditViewFromConnection projects the stored config into the
// template's expected shape, using the connector's declared field list.
func (s *Server) connectionEditViewFromConnection(conn *connections.Connection) *connectionEditData {
	d := &connectionEditData{
		Active:        "connections",
		ID:            conn.ID,
		DisplayName:   conn.DisplayName,
		ConnectorType: conn.ConnectorType,
	}

	meta, ok := s.registry.Meta(conn.ConnectorType)
	if !ok {
		return d // empty Fields → "no editable settings"
	}
	for _, f := range meta.SetupFields {
		if !f.Editable {
			continue
		}
		d.Fields = append(d.Fields, fieldViewFromStored(f, conn.Config))
	}

	if conn.ConnectorType == "http_proxy" {
		authH, _ := conn.Config["auth_header"].(string)
		d.HTTPProxyBaseline = &httpProxyBaselineView{
			BaselineDenyKeys:     staticHTTPProxyBaselineKeys,
			AuthHeaderConfigured: authH,
		}
	}
	return d
}

// fieldViewFromStored renders a single field's value from the stored
// config into the right template-shaped slot for its Type.
func fieldViewFromStored(f connector.Field, cfg map[string]any) editFieldView {
	v := editFieldView{
		Name:        f.Name,
		Label:       f.Label,
		Type:        f.Type,
		Placeholder: f.Placeholder,
		HelpText:    f.HelpText,
		Secret:      f.Secret,
	}
	switch f.Type {
	case "checkbox":
		switch x := cfg[f.Name].(type) {
		case bool:
			v.BoolValue = x
		case nil:
			v.BoolValue = f.Default == "true"
		}
	case "textarea":
		v.TextareaValue = joinStringSliceField(cfg[f.Name])
	case "number":
		switch x := cfg[f.Name].(type) {
		case int64:
			if x > 0 {
				v.StringValue = fmt.Sprintf("%d", x)
			}
		case int:
			if x > 0 {
				v.StringValue = fmt.Sprintf("%d", x)
			}
		case float64:
			if x > 0 {
				v.StringValue = fmt.Sprintf("%d", int64(x))
			}
		}
	case "json":
		if obj, ok := cfg[f.Name].(map[string]any); ok && len(obj) > 0 {
			b, _ := json.MarshalIndent(obj, "", "  ")
			v.StringValue = string(b)
		}
	default:
		if f.Secret {
			// Never echo the stored secret back into the form. The
			// placeholder explains the "empty = keep stored" behaviour.
			v.StringValue = ""
			if v.Placeholder == "" {
				v.Placeholder = "(unchanged)"
			} else {
				v.Placeholder = "(unchanged; " + v.Placeholder + ")"
			}
		} else if s, ok := cfg[f.Name].(string); ok {
			v.StringValue = s
		}
	}
	return v
}

// joinStringSliceField stringifies either a []string or a []any field
// into newline-delimited textarea content, preserving operator order.
func joinStringSliceField(v any) string {
	switch s := v.(type) {
	case []string:
		return joinLines(s)
	case []any:
		out := make([]string, 0, len(s))
		for _, x := range s {
			if str, ok := x.(string); ok {
				out = append(out, str)
			}
		}
		return joinLines(out)
	}
	return ""
}

func joinLines(s []string) string {
	if len(s) == 0 {
		return ""
	}
	out := s[0]
	for _, x := range s[1:] {
		out += "\n" + x
	}
	return out
}

// renderEditError re-renders the edit page with the given error banner.
// Sets Content-Type and the 400 status on the ResponseWriter directly
// rather than calling s.render's helper, so we don't trip the
// "superfluous WriteHeader" warning when render writes its own
// content-type header.
func (s *Server) renderEditError(w http.ResponseWriter, conn *connections.Connection, msg string) {
	data := s.connectionEditViewFromConnection(conn)
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
