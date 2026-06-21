package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/roles"
)

// nonEmptyStrings drops empty entries from a form's multi-value slice (an
// unselected <select multiple> posts a single "" we don't want).
func nonEmptyStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// iam.go implements the /iam admin page: IAM role creation, a VISUAL rules
// builder (role → effect → connector → operations → connections, compiled to
// Cedar so an operator never writes Cedar), a raw-Cedar "advanced" escape hatch,
// the policy list (shown by human-readable summary), the iam_enabled toggle, and
// the decision explorer.
//
// Security: every route here is gated by requireOperatorSession (adminAuthWrapper
// in server.go) like the other admin pages — none of the /iam paths are in
// authExemptPaths, so each request needs a valid operator session, the POSTs need
// a valid CSRF token (injected client-side by nav.html for every same-origin POST
// form), and agent bearer tokens are rejected with 403. Cache-Control: no-store
// is stamped on every admin response by noCacheAllAdmin.
//
// All handlers tolerate s.iam == nil (SetIAM never called): the GET page renders
// an "IAM not configured" notice and the POST handlers redirect without touching
// storage.

// iamEnabled reports whether the iam_enabled flag is set. Matches the
// comparison in api/router.go and mcp/server.go ("true") so the admin
// indicator never diverges from what the PEPs actually enforce.
func (s *Server) iamEnabled() bool {
	if s.iamSettings == nil {
		return false
	}
	v, _ := s.iamSettings.Get("iam_enabled")
	return v == "true"
}

// --- view models ---

type iamOpView struct {
	Name     string `json:"name"`
	ReadOnly bool   `json:"readOnly"`
}

type iamConnView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type iamScopeFieldView struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
}

type iamScopeView struct {
	Key        string              `json:"key"`
	Label      string              `json:"label"`
	EntityType string              `json:"entityType"`
	IDFormat   string              `json:"idFormat"`
	Help       string              `json:"help"`
	Fields     []iamScopeFieldView `json:"fields"`
}

type iamCondView struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Help    string `json:"help"`
	Kind    string `json:"kind"`
	CtxPath string `json:"ctxPath"`
}

// iamConnectorOption is one entry in the connector dropdown.
type iamConnectorOption struct {
	Type string
	Name string
}

// iamFilterView is one entry in the filter-library list and the builder's
// "response filters & guards" checkbox group. Used only in the Go template
// (server-side {{range}}), so no json tags are needed.
type iamFilterView struct {
	Name string
	Kind string
}

// iamBuilderData is the set of inputs the visual rule builder needs (shared by
// the "Add a rule" form on iam.html and the edit form on iam_edit.html). It is
// filled by populateBuilderData.
type iamBuilderData struct {
	Roles      []roles.Role
	Connectors []iamConnectorOption
	// Filters is the filter-library list, rendered server-side both in the
	// library card and as the builder's response-filter/guard checkboxes.
	Filters []iamFilterView
	// Catalog maps connector type → {operations, connections} for the
	// client-side form (populate op + connection checkboxes when the connector
	// dropdown changes). Rendered via the `json` template func into a
	// <script type="application/json"> block (never template.JS / inline JS).
	Catalog map[string]map[string]any
}

// iamPageData is the view-model for iam.html.
type iamPageData struct {
	Active     string
	Configured bool
	Enabled    bool
	Policies   []iamPolicyView
	CSRFToken  string

	// Error is a friendly message shown as a banner when a POST fails
	// validation (e.g. a condition with no value) — never a raw error page.
	Error string

	// Builder inputs (shared with the edit page).
	iamBuilderData

	// Decision-explorer round-trip fields.
	ExploreDone      bool
	ExploreRoleIDs   []string
	ExploreConnID    string
	ExploreConnType  string
	ExploreOperation string
	ExploreAction    string
	ExploreReason    string
	ExploreError     string
}

// iamPolicyView wraps a StoredPolicy with a HasSpec flag so the rules list can
// show an "Edit" link only for builder-authored rules (those with a stored
// structured spec). Raw/migrated rules (SpecJSON == "") have no form to reload.
type iamPolicyView struct {
	iampolicies.StoredPolicy
	HasSpec bool
}

// iamEditPageData is the view-model for iam_edit.html (edit-in-place of one
// builder-authored rule). It carries the same builder inputs as the create
// page plus the policy being edited and its stored form-state JSON.
type iamEditPageData struct {
	Active    string
	CSRFToken string

	// Error is a friendly banner shown when an edit submission fails validation.
	Error string

	// HasSpec is false for raw/migrated rules — the template then renders a
	// "no structured form" notice instead of the builder.
	HasSpec  bool
	PolicyID string
	Name     string
	// Spec is the decoded builder form-state, emitted into a data-attribute via
	// jsonAttr and read client-side via JSON.parse (never template.JS /
	// innerHTML). Decoding server-side means a single, predictable JSON object
	// reaches the prefill script (no double-encoded string to unwrap).
	Spec builderFormState

	iamBuilderData
}

// handleIAM renders the IAM admin page (GET /iam).
func (s *Server) handleIAM(w http.ResponseWriter, r *http.Request) {
	s.renderIAM(w, r, &iamPageData{})
}

// renderIAM populates the page-wide fields and renders the iam template.
func (s *Server) renderIAM(w http.ResponseWriter, r *http.Request, data *iamPageData) {
	data.Active = "iam"
	if s.iam == nil {
		data.Configured = false
		s.render(w, r, "iam", data)
		return
	}
	data.Configured = true
	data.Enabled = s.iamEnabled()

	pols, err := s.iam.ListPolicies()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data.Policies = make([]iamPolicyView, 0, len(pols))
	for _, p := range pols {
		data.Policies = append(data.Policies, iamPolicyView{StoredPolicy: p, HasSpec: p.SpecJSON != ""})
	}

	s.populateBuilderData(&data.iamBuilderData)
	s.render(w, r, "iam", data)
}

// renderIAMError re-renders the IAM page with a friendly error banner instead of
// a raw error page when a form submission fails validation. The operator sees
// what went wrong and the rest of the page (rules, library) is intact.
func (s *Server) renderIAMError(w http.ResponseWriter, r *http.Request, msg string) {
	s.renderIAM(w, r, &iamPageData{Error: msg})
}

// populateBuilderData fills the roles list, connector dropdown, and the
// per-connector operations+connections catalog the builder/explorer JS needs.
// It operates on the shared iamBuilderData so both the create page (iam.html)
// and the edit page (iam_edit.html) get identical inputs.
func (s *Server) populateBuilderData(data *iamBuilderData) {
	if rs, err := s.roles.List(); err == nil {
		data.Roles = rs
	}

	// Connections grouped by connector type (for the catalog).
	connsByType := map[string][]iamConnView{}
	if conns, err := s.connections.List(); err == nil {
		for _, c := range conns {
			connsByType[c.ConnectorType] = append(connsByType[c.ConnectorType],
				iamConnView{ID: c.ID, Name: c.DisplayName})
		}
	}

	catalog := map[string]map[string]any{}
	reg := s.iamRegistry
	if reg == nil {
		reg = s.registry
	}
	if reg != nil {
		for _, m := range reg.AllMetas() {
			ops := make([]iamOpView, 0, len(m.Operations))
			for _, o := range m.Operations {
				ops = append(ops, iamOpView{Name: o.Name, ReadOnly: o.ReadOnly})
			}
			sort.Slice(ops, func(i, j int) bool { return ops[i].Name < ops[j].Name })
			conns := connsByType[m.Type]
			sort.Slice(conns, func(i, j int) bool { return conns[i].Name < conns[j].Name })

			scopes := make([]iamScopeView, 0, len(m.RuleScopes))
			for _, sc := range m.RuleScopes {
				fields := make([]iamScopeFieldView, 0, len(sc.Fields))
				for _, f := range sc.Fields {
					fields = append(fields, iamScopeFieldView{Key: f.Key, Label: f.Label, Placeholder: f.Placeholder})
				}
				scopes = append(scopes, iamScopeView{
					Key: sc.Key, Label: sc.Label, EntityType: sc.EntityType,
					IDFormat: sc.IDFormat, Help: sc.Help, Fields: fields,
				})
			}
			conds := make([]iamCondView, 0, len(m.RuleConditions))
			for _, c := range m.RuleConditions {
				conds = append(conds, iamCondView{Key: c.Key, Label: c.Label, Help: c.Help, Kind: c.Kind, CtxPath: c.CtxPath})
			}

			data.Connectors = append(data.Connectors, iamConnectorOption{Type: m.Type, Name: m.Name})
			catalog[m.Type] = map[string]any{
				"operations": ops, "connections": conns, "scopes": scopes, "conditions": conds,
			}
		}
	}
	sort.Slice(data.Connectors, func(i, j int) bool { return data.Connectors[i].Name < data.Connectors[j].Name })

	// Filter library: rendered server-side in the library card and the
	// builder's response-filter checkboxes, and mirrored into the catalog so
	// client-side JS can reach it too.
	if fs, err := s.iam.ListFilters(); err == nil {
		filters := make([]iamFilterView, 0, len(fs))
		for _, f := range fs {
			filters = append(filters, iamFilterView{Name: f.Name, Kind: string(f.Kind)})
		}
		data.Filters = filters
		catalog["_filters"] = map[string]any{"filters": filters}
	}

	data.Catalog = catalog
}

// handleIAMRoleCreate creates an IAM role (POST /iam/roles, field name). In the
// IAM model a role is just a named principal: tokens attach to it and rules
// target it via `principal in Sieve::Role::"<id>"`. No legacy bindings are set.
func (s *Server) handleIAMRoleCreate(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "role name is required", http.StatusBadRequest)
		return
	}
	role, err := s.roles.Create(name, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.role.create", role.ID,
		map[string]any{"name": name}, "success")
	http.Redirect(w, r, "/iam", http.StatusSeeOther)
}

// handleIAMFilterCreate creates a filter-library entry (POST /iam/filters).
// The filter library lets an operator author response filters (redact /
// exclude_items) and pre-execution guards (script_guard) by name, without
// writing Cedar; rules in the builder then reference them via the @filters
// annotation (the builder handler reads r.Form["filters"]).
func (s *Server) handleIAMFilterCreate(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "filter name is required", http.StatusBadRequest)
		return
	}

	kindStr := r.FormValue("kind")
	var kind iam.FilterKind
	config := map[string]any{}
	switch kindStr {
	case string(iam.KindRedact):
		kind = iam.KindRedact
		var patterns []string
		for _, line := range strings.Split(r.FormValue("patterns"), "\n") {
			if p := strings.TrimSpace(line); p != "" {
				patterns = append(patterns, p)
			}
		}
		config["patterns"] = patterns
	case string(iam.KindExcludeItems):
		kind = iam.KindExcludeItems
		config["text"] = r.FormValue("text")
	case string(iam.KindScriptGuard):
		kind = iam.KindScriptGuard
		config["command"] = iampolicies.ScriptCommand()
		config["inline"] = r.FormValue("script")
	default:
		http.Error(w, "unknown filter kind", http.StatusBadRequest)
		return
	}

	if _, err := s.iam.CreateFilter(name, r.FormValue("description"), kind, 0, config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.filter.create", name,
		map[string]any{"kind": kindStr}, "success")
	http.Redirect(w, r, "/iam", http.StatusSeeOther)
}

// handleIAMFilterDelete removes a filter-library entry
// (POST /iam/filters/{name}/delete).
func (s *Server) handleIAMFilterDelete(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	name := r.PathValue("name")
	// Refuse to delete a filter still attached to a rule — removing it would
	// fail-close (deny) every rule that references it.
	if inUse, err := s.iam.FilterInUse(name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if inUse {
		http.Error(w, "filter "+name+" is still attached to one or more rules — detach it there first", http.StatusConflict)
		return
	}
	if err := s.iam.DeleteFilter(name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.filter.delete", name, nil, "success")
	http.Redirect(w, r, "/iam", http.StatusSeeOther)
}

// handleIAMPolicyCreate creates an IAM policy (POST /iam/policies). mode=builder
// compiles the visual rule to Cedar; mode=advanced takes raw Cedar. Both paths
// validate the Cedar compiles before storing so one bad policy can't break the
// whole engine.
func (s *Server) handleIAMPolicyCreate(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if r.FormValue("mode") == "advanced" {
		s.createAdvancedPolicy(w, r)
		return
	}
	s.createBuilderPolicy(w, r)
}

// builderFormState is the RAW builder selections (JSON-serialized into the
// policy's spec_json column) needed to re-render the form for edit-in-place.
// Field names mirror the form controls so the prefill JS can map 1:1.
type builderFormState struct {
	RoleID        string            `json:"role_id"`
	Effect        string            `json:"effect"`
	ConnectorType string            `json:"connector_type"`
	OpScope       string            `json:"op_scope"`
	Operations    []string          `json:"operations"`
	ConnScope     string            `json:"conn_scope"`
	Connections   []string          `json:"connections"`
	ScopeKey      string            `json:"scope_key"`
	ScopeFields   map[string]string `json:"scope_fields"`
	Conditions    []builderCond     `json:"conditions"`
	Filters       []string          `json:"filters"`
}

// builderCond is one captured condition selection (checkbox on + op + value).
type builderCond struct {
	Key   string `json:"key"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// parseBuilderForm parses the visual rule form into a RuleSpec (for Cedar
// compilation), the human summary, and the raw form-state JSON (for storing in
// spec_json so the rule can be reloaded into the form for edit-in-place). It is
// shared by createBuilderPolicy and handleIAMPolicyUpdate so create/edit can
// never diverge. r.ParseForm must have been called by the caller.
//
// Validation that depends on the request (missing scope fields, scoping without
// a connection) returns a non-nil *parseError that the caller maps to an HTTP
// error; on success err is nil.
func (s *Server) parseBuilderForm(r *http.Request) (iampolicies.RuleSpec, string, string, *parseError) {
	spec := iampolicies.RuleSpec{
		RoleID:        r.FormValue("role_id"),
		Effect:        r.FormValue("effect"),
		ConnectorType: r.FormValue("connector_type"),
		OpScope:       r.FormValue("op_scope"),
		Operations:    r.Form["operations"],
	}
	connScope := r.FormValue("conn_scope")
	if connScope == "specific" {
		spec.ConnectionIDs = r.Form["connections"]
	}

	// Capture the raw selections for round-tripping into the edit form.
	state := builderFormState{
		RoleID:        spec.RoleID,
		Effect:        spec.Effect,
		ConnectorType: spec.ConnectorType,
		OpScope:       spec.OpScope,
		Operations:    r.Form["operations"],
		ConnScope:     connScope,
		Connections:   r.Form["connections"],
		ScopeKey:      r.FormValue("scope_key"),
		ScopeFields:   map[string]string{},
		Filters:       r.Form["filters"],
	}

	meta := s.connectorMeta(spec.ConnectorType)

	// Resource scope (connector-tailored). The entity id is connection-prefixed,
	// so scoping requires specific connection(s).
	if scopeKey := r.FormValue("scope_key"); scopeKey != "" {
		for _, sc := range meta.RuleScopes {
			if sc.Key != scopeKey {
				continue
			}
			fields := map[string]string{}
			for _, f := range sc.Fields {
				v := strings.TrimSpace(r.FormValue("scope_" + f.Key))
				if v == "" {
					return spec, "", "", &parseError{msg: "fill in all fields for the selected resource scope", code: http.StatusBadRequest}
				}
				fields[f.Key] = v
				state.ScopeFields[f.Key] = v
			}
			if len(spec.ConnectionIDs) == 0 {
				return spec, "", "", &parseError{msg: "resource scoping requires selecting specific connection(s)", code: http.StatusBadRequest}
			}
			for _, connID := range spec.ConnectionIDs {
				spec.Scopes = append(spec.Scopes, iampolicies.ScopeRef{
					EntityType: sc.EntityType,
					ID:         iampolicies.BuildScopeID(sc.IDFormat, connID, fields),
				})
			}
			break
		}
	}

	// Conditions (connector-tailored). Only on permit effects: a condition
	// REFINES what a rule covers, and Cedar skips a policy whose condition
	// errors (e.g. a missing/non-representable attribute). On a permit that
	// fails closed (skipped permit → default deny); on a forbid it would fail
	// OPEN (skipped forbid → allowed), so we never attach conditions to deny
	// rules. Express a cap as "allow when amount <= N", not "deny when > N".
	if spec.Effect != "deny" {
		for _, c := range meta.RuleConditions {
			if r.FormValue("cond_"+c.Key) != "on" {
				continue
			}
			op := r.FormValue("cond_" + c.Key + "_op")
			val := strings.TrimSpace(r.FormValue("cond_" + c.Key + "_val"))
			// Friendly, specific validation — an enabled condition with no (or a
			// bad) value must never reach the Cedar compiler as a raw error.
			if val == "" {
				return spec, "", "", &parseError{
					msg:  "Enter a value for the \"" + c.Label + "\" condition, or uncheck it.",
					code: http.StatusBadRequest,
				}
			}
			if c.Kind == "number" {
				if _, err := strconv.ParseInt(val, 10, 64); err != nil {
					return spec, "", "", &parseError{
						msg:  "The \"" + c.Label + "\" condition needs a whole number (you entered \"" + val + "\").",
						code: http.StatusBadRequest,
					}
				}
			}
			spec.Conditions = append(spec.Conditions, iampolicies.ConditionInput{
				Kind:    c.Kind,
				CtxPath: c.CtxPath,
				Op:      op,
				Value:   val,
			})
			state.Conditions = append(state.Conditions, builderCond{Key: c.Key, Op: op, Value: val})
		}
	}

	// Response-filter obligations (filter-library names).
	spec.Filters = r.Form["filters"]

	summary := iampolicies.HumanSummary(spec, s.roleName(spec.RoleID), s.connLabels(spec.ConnectionIDs))

	formStateJSON := "{}"
	if b, err := json.Marshal(state); err == nil {
		formStateJSON = string(b)
	}
	return spec, summary, formStateJSON, nil
}

// parseError is a request-derived validation failure from parseBuilderForm,
// carrying the message + HTTP status the handler should return.
type parseError struct {
	msg  string
	code int
}

// createBuilderPolicy compiles the visual rule form to Cedar and stores it with
// a human-readable summary as its description and the raw form-state as its
// spec_json (so it can be edited in place later).
func (s *Server) createBuilderPolicy(w http.ResponseWriter, r *http.Request) {
	spec, summary, formStateJSON, perr := s.parseBuilderForm(r)
	if perr != nil {
		s.renderIAMError(w, r, perr.msg)
		return
	}

	meta := s.connectorMeta(spec.ConnectorType)
	cedar, err := iampolicies.BuildRuleCedar(spec, meta.Operations)
	if err != nil {
		s.renderIAMError(w, r, "Could not build rule: "+err.Error())
		return
	}
	if err := s.iam.ValidateCedar(cedar); err != nil {
		s.renderIAMError(w, r, "Generated rule did not validate: "+err.Error())
		return
	}

	name := r.FormValue("name")
	if name == "" {
		name = summary
	}
	// Auto-uniquify so cloning a rule ("save as a new rule for another role")
	// or any same-named create never fails on the UNIQUE name constraint.
	name = s.uniqueRuleName(name)

	pol, err := s.iam.CreatePolicy(name, summary, cedar, true)
	if err != nil {
		s.renderIAMError(w, r, err.Error())
		return
	}
	// Persist the structured form-state so the rule can be reloaded into the
	// builder for edit-in-place. Best-effort: a spec write failure must not
	// orphan the (already-created) rule, which is fully functional without it.
	_ = s.iam.SetPolicySpec(pol.ID, formStateJSON)
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.policy.create", pol.ID,
		map[string]any{"name": name, "mode": "builder"}, "success")
	http.Redirect(w, r, "/iam", http.StatusSeeOther)
}

// createAdvancedPolicy stores raw Cedar (the escape hatch for expressivity the
// visual builder doesn't cover).
func (s *Server) createAdvancedPolicy(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	cedar := r.FormValue("cedar")
	if name == "" || cedar == "" {
		http.Error(w, "name and cedar are required", http.StatusBadRequest)
		return
	}
	if err := s.iam.ValidateCedar(cedar); err != nil {
		http.Error(w, "policy did not validate: "+err.Error(), http.StatusBadRequest)
		return
	}
	pol, err := s.iam.CreatePolicy(name, "(raw Cedar)", cedar, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.policy.create", pol.ID,
		map[string]any{"name": name, "mode": "advanced"}, "success")
	http.Redirect(w, r, "/iam", http.StatusSeeOther)
}

// handleIAMPolicyEditPage renders the edit-in-place form for one
// builder-authored rule (GET /iam/policies/{id}/edit). Rules with no stored
// structured form (raw Cedar / migrated) render a notice instead — there's no
// form-state to reload, so they must be recreated via the builder or edited as
// raw Cedar in the Advanced section.
func (s *Server) handleIAMPolicyEditPage(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	s.renderEditPage(w, r, r.PathValue("id"), "")
}

// renderEditPage renders the edit-in-place form for one rule, optionally with a
// friendly error banner. Shared by the GET edit page and the update handler's
// validation-failure path so a bad edit re-renders the form instead of a raw
// error page.
func (s *Server) renderEditPage(w http.ResponseWriter, r *http.Request, id, errMsg string) {
	pol, err := s.iam.GetPolicy(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	data := &iamEditPageData{
		Active:   "iam",
		Error:    errMsg,
		PolicyID: pol.ID,
		Name:     pol.Name,
		HasSpec:  pol.SpecJSON != "",
	}
	if data.HasSpec {
		// Decode the stored form-state so the template emits one clean JSON
		// object for the prefill script. A corrupt spec falls back to the
		// notice page rather than rendering a half-populated form.
		if err := json.Unmarshal([]byte(pol.SpecJSON), &data.Spec); err != nil {
			data.HasSpec = false
		} else {
			s.populateBuilderData(&data.iamBuilderData)
		}
	}
	s.render(w, r, "iam_edit", data)
}

// handleIAMPolicyUpdate recompiles an edited builder rule and stores it in place
// (POST /iam/policies/{id}/update). It reuses parseBuilderForm so create/edit
// share identical parsing, validation, and form-state capture.
func (s *Server) handleIAMPolicyUpdate(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")

	spec, summary, formStateJSON, perr := s.parseBuilderForm(r)
	if perr != nil {
		s.renderEditPage(w, r, id, perr.msg)
		return
	}

	meta := s.connectorMeta(spec.ConnectorType)
	cedar, err := iampolicies.BuildRuleCedar(spec, meta.Operations)
	if err != nil {
		s.renderEditPage(w, r, id, "Could not build rule: "+err.Error())
		return
	}
	if err := s.iam.ValidateCedar(cedar); err != nil {
		s.renderEditPage(w, r, id, "Generated rule did not validate: "+err.Error())
		return
	}

	name := r.FormValue("name")
	if name == "" {
		name = summary
	}

	// Editing keeps the rule enabled (the list has its own enable/disable
	// toggle; edit-in-place is about the rule's content, not its on/off state).
	if err := s.iam.UpdatePolicy(id, name, summary, cedar, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.iam.SetPolicySpec(id, formStateJSON)
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.policy.update", id,
		map[string]any{"name": name, "mode": "builder"}, "success")
	http.Redirect(w, r, "/iam", http.StatusSeeOther)
}

// uniqueRuleName returns base, or base with a numeric suffix, so that it does
// not collide with an existing policy name (the column is UNIQUE).
func (s *Server) uniqueRuleName(base string) string {
	pols, err := s.iam.ListPolicies()
	if err != nil {
		return base
	}
	taken := make(map[string]bool, len(pols))
	for _, p := range pols {
		taken[p.Name] = true
	}
	if !taken[base] {
		return base
	}
	for i := 2; ; i++ {
		cand := base + " (" + strconv.Itoa(i) + ")"
		if !taken[cand] {
			return cand
		}
	}
}

// connectorMeta returns the connector's metadata (operations + rule
// capabilities) for the handler to resolve op names, scopes, and conditions.
func (s *Server) connectorMeta(connType string) connector.ConnectorMeta {
	reg := s.iamRegistry
	if reg == nil {
		reg = s.registry
	}
	if reg != nil {
		if m, ok := reg.Meta(connType); ok {
			return m
		}
	}
	return connector.ConnectorMeta{}
}

// roleName resolves a role id to its display name ("" / unknown → "").
func (s *Server) roleName(id string) string {
	if id == "" {
		return ""
	}
	if role, err := s.roles.Get(id); err == nil {
		return role.Name
	}
	return id
}

// connLabels resolves connection ids to display names for the human summary.
func (s *Server) connLabels(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	labels := make([]string, 0, len(ids))
	for _, id := range ids {
		if c, err := s.connections.Get(id); err == nil {
			labels = append(labels, c.DisplayName)
		} else {
			labels = append(labels, id)
		}
	}
	return labels
}

// handleIAMPolicyDelete removes an IAM policy (POST /iam/policies/{id}/delete).
func (s *Server) handleIAMPolicyDelete(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	id := r.PathValue("id")
	if err := s.iam.DeletePolicy(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.policy.delete", id, nil, "success")
	http.Redirect(w, r, "/iam", http.StatusSeeOther)
}

// handleIAMPolicySetEnabled enables/disables a rule without deleting it
// (POST /iam/policies/{id}/enabled, field enabled="true"/"false").
func (s *Server) handleIAMPolicySetEnabled(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	enabled := r.FormValue("enabled") == "true"
	if err := s.iam.SetPolicyEnabled(id, enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.policy.set_enabled", id,
		map[string]any{"enabled": enabled}, "success")
	http.Redirect(w, r, "/iam", http.StatusSeeOther)
}

// handleIAMToggle sets the iam_enabled flag (POST /iam/toggle, field enabled).
func (s *Server) handleIAMToggle(w http.ResponseWriter, r *http.Request) {
	if s.iamSettings == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	enabled := "false"
	if r.FormValue("enabled") == "true" {
		enabled = "true"
	}
	if err := s.iamSettings.Set("iam_enabled", enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.toggle", "iam_enabled",
		map[string]any{"enabled": enabled}, "success")
	http.Redirect(w, r, "/iam", http.StatusSeeOther)
}

// handleIAMExplore runs the decision explorer (POST /iam/explore).
func (s *Server) handleIAMExplore(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	data := &iamPageData{
		ExploreDone:      true,
		ExploreRoleIDs:   nonEmptyStrings(r.Form["role_id"]),
		ExploreConnID:    r.FormValue("connection_id"),
		ExploreConnType:  r.FormValue("connector_type"),
		ExploreOperation: r.FormValue("operation"),
	}

	if s.iam == nil {
		data.ExploreError = "IAM is not configured."
		s.renderIAM(w, r, data)
		return
	}

	// If connector_type wasn't supplied but the connection is known, derive it.
	if data.ExploreConnType == "" && data.ExploreConnID != "" {
		if c, err := s.connections.Get(data.ExploreConnID); err == nil {
			data.ExploreConnType = c.ConnectorType
		}
	}

	dec, err := s.iam.Decide(
		r.Context(),
		s.iamRegistry,
		"explorer",
		data.ExploreRoleIDs,
		data.ExploreConnType,
		data.ExploreConnID,
		"active",
		data.ExploreOperation,
		nil,
	)
	if err != nil {
		data.ExploreError = err.Error()
		s.renderIAM(w, r, data)
		return
	}
	data.ExploreAction = dec.Action
	data.ExploreReason = dec.Reason
	s.renderIAM(w, r, data)
}
