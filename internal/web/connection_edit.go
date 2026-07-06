package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/connectors/httpproxy"
	"github.com/trilitech/Sieve/internal/secrets"
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

	// CSRFToken is the plaintext token used by nav.html to seed
	// window.SIEVE_CSRF, which the delegated submit handler echoes
	// back into every POST form as `csrf_token`. Populated by render()
	// from the session-in-context — handlers don't set it directly.
	CSRFToken string
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
	Required    bool

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
	// Agent-token rejection happens upstream via the requireOperatorSession
	// middleware applied by the admin auth wrapper; per-handler
	// rejectIfAgentToken calls were removed when the middleware landed.

	id := r.PathValue("id")
	conn, err := s.connections.GetWithConfig(id)
	if err != nil {
		// The keyring being locked is a transient service state, not a
		// missing resource — surface it as 503 per the CLAUDE.md contract
		// (mirrors handleSlackOAuthConfigure / passphrase rotation), rather
		// than masking it as a 404.
		if errors.Is(err, secrets.ErrKeyringNotLoaded) {
			http.Error(w, "service locked: passphrase required", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "connection not found", http.StatusNotFound)
		return
	}

	// Connector-specific legacy-alias normalize (e.g. mcp_proxy's
	// target_url → url) so older rows render with the canonical key
	// pre-filled in the edit form. Best-effort: factory failures are
	// not fatal — fall back to the raw stored config.
	if c, err := s.registry.Create(conn.ConnectorType, conn.Config); err == nil {
		if normalizer, ok := c.(connector.EditConfigNormalizer); ok {
			conn.Config = normalizer.NormalizeForEdit(conn.Config)
		}
	}

	data := s.connectionEditViewFromConnection(conn)
	if r.URL.Query().Get("saved") == "1" {
		data.Success = true
	}
	s.render(w, r, "connection_edit", data)
}

// handleConnectionEditSave validates and persists the edit form.
//
// All field parsing flows through applyConnectorFormFields, which is
// the same code path the create handler uses. The handler itself has no
// per-connector knowledge.
func (s *Server) handleConnectionEditSave(w http.ResponseWriter, r *http.Request) {
	// Agent-token rejection happens upstream via requireOperatorSession.
	if !s.checkRotationOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}

	id := r.PathValue("id")
	conn, err := s.connections.GetWithConfig(id)
	if err != nil {
		// The keyring being locked is a transient service state, not a
		// missing resource — surface it as 503 per the CLAUDE.md contract
		// (mirrors handleSlackOAuthConfigure / passphrase rotation), rather
		// than masking it as a 404.
		if errors.Is(err, secrets.ErrKeyringNotLoaded) {
			http.Error(w, "service locked: passphrase required", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "connection not found", http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form encoding", http.StatusBadRequest)
		return
	}

	meta, ok := s.registry.Meta(conn.ConnectorType)
	if !ok {
		s.renderEditError(w, r, conn, "unknown connector type "+conn.ConnectorType)
		return
	}

	// Start from the stored config so non-Editable fields and untouched
	// Secret fields flow through unchanged.
	cfg := make(map[string]any, len(conn.Config)+4)
	for k, v := range conn.Config {
		cfg[k] = v
	}

	// Apply the same legacy-alias normalize the GET path uses so a
	// save against a legacy row migrates the alias into the canonical
	// key and persists only the canonical shape going forward.
	if c, err := s.registry.Create(conn.ConnectorType, conn.Config); err == nil {
		if normalizer, ok := c.(connector.EditConfigNormalizer); ok {
			cfg = normalizer.NormalizeForEdit(cfg)
		}
	}

	if msg := applyConnectorFormFields(meta, formModeEdit, r, cfg); msg != "" {
		// Render from cfg (the in-progress config carrying every
		// field parsed successfully so far) so the operator's typed
		// values are preserved in the form.
		s.renderEditErrorWithConfig(w, r, conn, cfg, msg)
		return
	}

	// Connector-specific shape check that doesn't belong in the generic
	// bridge. http_proxy enforces a regex on auth_query_param; the
	// connector Factory will reject the same value, but doing the check
	// here gives a clearer banner that preserves the rest of the form.
	if conn.ConnectorType == "http_proxy" {
		if aqp, _ := cfg["auth_query_param"].(string); aqp != "" && !authQueryParamPattern.MatchString(aqp) {
			s.renderEditErrorWithConfig(w, r, conn, cfg,
				"auth_query_param must contain only letters, digits, _, -, or . (got "+aqp+")")
			return
		}
	}

	if err := s.connections.UpdateConfig(id, cfg); err != nil {
		// Render from cfg so the operator's attempted values are
		// preserved on the retry.
		s.renderEditErrorWithConfig(w, r, conn, cfg, "save failed: "+err.Error())
		return
	}

	// Audit the field names whose values reached the saved config — never
	// the values themselves, since Secret fields are present in cfg. The
	// key name `submitted_keys` matches settings.save for downstream
	// log-search consistency.
	submittedKeys := make([]string, 0, len(cfg))
	for k := range cfg {
		submittedKeys = append(submittedKeys, k)
	}
	sort.Strings(submittedKeys)
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "connection.update_config", id,
		map[string]any{"connector_type": conn.ConnectorType, "submitted_keys": submittedKeys},
		"success")

	http.Redirect(w, r, fmt.Sprintf("/connections/%s/edit?saved=1", id), http.StatusSeeOther)
}

// connectionEditViewFromConnection is the success-path projection: it
// renders the page using whatever config is currently stored on the
// connection.
func (s *Server) connectionEditViewFromConnection(conn *connections.Connection) *connectionEditData {
	return s.connectionEditViewFromConfig(conn, conn.Config)
}

// connectionEditViewFromConfig projects an arbitrary config map into
// the template's expected shape. The two callers separate cleanly:
//
//   - success path (GET): cfg == conn.Config
//   - error  path (POST): cfg == the in-progress merge of stored config
//     with whatever was successfully parsed from the form before the
//     error. Using cfg here is what preserves the operator's typed
//     values across a re-render, instead of snapping them back to the
//     stored values.
//
// The filter uses fieldInMode rather than checking f.Editable directly
// so a field whose Type isn't renderable by the generic template is
// dropped here too. Asymmetric filtering between this projection and
// applyConnectorFormFields used to allow empty/partial forms — the
// symmetry makes both halves agree on which fields participate.
func (s *Server) connectionEditViewFromConfig(conn *connections.Connection, cfg map[string]any) *connectionEditData {
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
		if !fieldInMode(f, formModeEdit) {
			continue
		}
		d.Fields = append(d.Fields, fieldViewFromStored(f, cfg))
	}

	if conn.ConnectorType == "http_proxy" {
		authH, _ := cfg["auth_header"].(string)
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
		Required:    f.Required,
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
	case "json_array":
		if arr, ok := cfg[f.Name].([]any); ok && len(arr) > 0 {
			b, _ := json.MarshalIndent(arr, "", "  ")
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

// renderEditError re-renders the edit page using the stored config.
// Use this only when the in-progress config isn't meaningful (e.g.,
// unknown connector type, where there's nothing successfully parsed
// to preserve).
func (s *Server) renderEditError(w http.ResponseWriter, r *http.Request, conn *connections.Connection, msg string) {
	s.renderEditErrorWithConfig(w, r, conn, conn.Config, msg)
}

// renderEditErrorWithConfig re-renders the edit page using a specific
// config map for projecting field values. Use this on validation /
// save errors so the operator's typed values are preserved in the
// form across the retry — rendering from conn.Config would snap them
// back to the stored state and force re-entry.
//
// Sets Content-Type and the 400 status on the ResponseWriter directly
// rather than calling s.render's helper, so we don't trip the
// "superfluous WriteHeader" warning when render writes its own
// content-type header. The CSRFToken is injected manually here too,
// since we bypass s.render — without it, the rendered error page
// would carry an empty window.SIEVE_CSRF and the operator's retry
// POST would 403 at the middleware.
func (s *Server) renderEditErrorWithConfig(w http.ResponseWriter, r *http.Request, conn *connections.Connection, cfg map[string]any, msg string) {
	data := s.connectionEditViewFromConfig(conn, cfg)
	data.Error = msg
	if sess := sessionFromContext(r); sess != nil {
		data.CSRFToken = sess.CSRFToken
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	t, ok := s.templates["connection_edit"]
	if !ok {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	_ = t.ExecuteTemplate(w, "connection_edit", data)
}
