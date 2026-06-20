package web

import (
	"net/http"
	"sort"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/roles"
)

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

// iamPageData is the view-model for iam.html.
type iamPageData struct {
	Active     string
	Configured bool
	Enabled    bool
	Policies   []iampolicies.StoredPolicy
	CSRFToken  string

	// Builder inputs.
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

	// Decision-explorer round-trip fields.
	ExploreDone      bool
	ExploreRoleID    string
	ExploreConnID    string
	ExploreConnType  string
	ExploreOperation string
	ExploreAction    string
	ExploreReason    string
	ExploreError     string
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
	data.Policies = pols

	s.populateBuilderData(data)
	s.render(w, r, "iam", data)
}

// populateBuilderData fills the roles list, connector dropdown, and the
// per-connector operations+connections catalog the builder/explorer JS needs.
func (s *Server) populateBuilderData(data *iamPageData) {
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

// createBuilderPolicy compiles the visual rule form to Cedar and stores it with
// a human-readable summary as its description.
func (s *Server) createBuilderPolicy(w http.ResponseWriter, r *http.Request) {
	spec := iampolicies.RuleSpec{
		RoleID:        r.FormValue("role_id"),
		Effect:        r.FormValue("effect"),
		ConnectorType: r.FormValue("connector_type"),
		OpScope:       r.FormValue("op_scope"),
		Operations:    r.Form["operations"],
	}
	if r.FormValue("conn_scope") == "specific" {
		spec.ConnectionIDs = r.Form["connections"]
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
					http.Error(w, "fill in all fields for the selected resource scope", http.StatusBadRequest)
					return
				}
				fields[f.Key] = v
			}
			if len(spec.ConnectionIDs) == 0 {
				http.Error(w, "resource scoping requires selecting specific connection(s)", http.StatusBadRequest)
				return
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

	// Conditions (connector-tailored).
	for _, c := range meta.RuleConditions {
		if r.FormValue("cond_"+c.Key) != "on" {
			continue
		}
		spec.Conditions = append(spec.Conditions, iampolicies.ConditionInput{
			Kind:    c.Kind,
			CtxPath: c.CtxPath,
			Op:      r.FormValue("cond_" + c.Key + "_op"),
			Value:   r.FormValue("cond_" + c.Key + "_val"),
		})
	}

	// Response-filter obligations (filter-library names).
	spec.Filters = r.Form["filters"]

	cedar, err := iampolicies.BuildRuleCedar(spec, meta.Operations)
	if err != nil {
		http.Error(w, "could not build rule: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.iam.ValidateCedar(cedar); err != nil {
		http.Error(w, "generated rule did not validate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	summary := iampolicies.HumanSummary(spec, s.roleName(spec.RoleID), s.connLabels(spec.ConnectionIDs))
	name := r.FormValue("name")
	if name == "" {
		name = summary
	}

	pol, err := s.iam.CreatePolicy(name, summary, cedar, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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
		ExploreRoleID:    r.FormValue("role_id"),
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
		data.ExploreRoleID,
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
