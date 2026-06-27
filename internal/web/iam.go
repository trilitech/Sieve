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
	Name           string `json:"name"`
	ReadOnly       bool   `json:"readOnly"`
	Disabled       bool   `json:"disabled,omitempty"`
	DisabledReason string `json:"disabledReason,omitempty"`
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
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Help    string   `json:"help"`
	Kind    string   `json:"kind"`
	CtxPath string   `json:"ctxPath"`
	Ops     []string `json:"ops,omitempty"` // op names this condition applies to; empty ⇒ all
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
	Name  string
	Kind  string
	Order int
}

// iamContentFieldView is one selectable content field in the redact/exclude
// filter form. The union across connectors (a filter lives in the shared
// library); leaving all unchecked applies to every connector's content fields.
type iamContentFieldView struct {
	Key   string
	Label string
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
	// ContentFields is the de-duped union of connectors' declared content fields,
	// shown as checkboxes in the redact/exclude filter form (narrow the scope).
	ContentFields []iamContentFieldView
	// Catalog maps connector type → {operations, connections} for the
	// client-side form (populate op + connection checkboxes when the connector
	// dropdown changes). Rendered via the `json` template func into a
	// <script type="application/json"> block (never template.JS / inline JS).
	Catalog map[string]map[string]any
}

// iamPageData is the view-model for iam.html.
type iamPageData struct {
	Active string
	// Section selects which subsection the page shows (roles|guardrails|filters|
	// explore) — mirrors the IAM sidebar sub-nav so the page isn't one long scroll.
	Section    string
	Configured bool
	Enabled    bool
	Policies   []iamPolicyView
	// RoleViews is the role list with per-role blast-radius counts (Roles card).
	RoleViews []iamRoleView
	// RuleGroups is the rules list grouped by the role each rule targets.
	RuleGroups []ruleGroupView
	Guardrails []iamGuardrailView
	// Transforms is the scoped-transform list (the Transforms section — the
	// self-contained successor to the guardrail+filter-library split).
	Transforms []iamTransformView
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
// Summary is the plain-English rendering recomputed from the stored spec (or ""
// for raw rules, which display their Cedar instead). Description is the
// operator's own free-form text (StoredPolicy.Description).
type iamPolicyView struct {
	iampolicies.StoredPolicy
	HasSpec bool
	Summary string
}

// iamRoleView wraps a role with its blast-radius counts, shown beside the role
// in the Roles list and used to confirm a cascade delete.
type iamRoleView struct {
	roles.Role
	RuleCount      int
	GuardrailCount int
	TokenCount     int
}

// ruleGroupView is one role's worth of rules in the (grouped) rules list. RoleID
// "" / RoleName "" is the catch-all bucket for raw/unscoped rules.
type ruleGroupView struct {
	RoleID   string
	RoleName string
	Policies []iamPolicyView
}

// iamGuardrailView wraps a StoredGuardrail for the guardrails list.
type iamGuardrailView struct {
	iampolicies.StoredGuardrail
	HasSpec bool
	// Summary is the plain-English rendering recomputed from spec_json, so the
	// list is legible without reading Cedar (raw guardrails have no spec → "").
	Summary string
}

// iamTransformView is one scoped transform in the Transforms list. Kind/Order/
// Summary are derived from spec_json so the row reads in plain English.
type iamTransformView struct {
	iampolicies.StoredTransform
	Kind    string
	Order   int
	Summary string
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
	HasSpec     bool
	PolicyID    string
	Name        string
	Description string
	// Spec is the decoded builder form-state, emitted into a data-attribute via
	// jsonAttr and read client-side via JSON.parse (never template.JS /
	// innerHTML). Decoding server-side means a single, predictable JSON object
	// reaches the prefill script (no double-encoded string to unwrap).
	Spec builderFormState

	iamBuilderData
}

// iamSections are the /iam subsections shown one-at-a-time via ?section= (the
// sidebar sub-nav). Default is roles — the main authoring surface.
var iamSections = map[string]bool{"roles": true, "transforms": true, "guardrails": true, "explore": true}

func iamSection(r *http.Request) string {
	if s := r.URL.Query().Get("section"); iamSections[s] {
		return s
	}
	return "roles"
}

// handleIAM renders the IAM admin page (GET /iam), one subsection at a time.
func (s *Server) handleIAM(w http.ResponseWriter, r *http.Request) {
	s.renderIAM(w, r, &iamPageData{Section: iamSection(r)})
}

// renderIAM populates the page-wide fields and renders the iam template.
func (s *Server) renderIAM(w http.ResponseWriter, r *http.Request, data *iamPageData) {
	if data.Section == "" {
		data.Section = "roles"
	}
	data.Active = "iam-" + data.Section
	if s.iam == nil {
		data.Configured = false
		s.render(w, r, "iam", data)
		return
	}
	data.Configured = true
	data.Enabled = s.iamEnabled()

	rolesList, _ := s.roles.List()

	pols, err := s.iam.ListPolicies()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data.Policies = make([]iamPolicyView, 0, len(pols))
	for _, p := range pols {
		data.Policies = append(data.Policies, iamPolicyView{
			StoredPolicy: p,
			HasSpec:      p.SpecJSON != "",
			Summary:      s.summaryFromSpecJSON(p.SpecJSON),
		})
	}

	guards, err := s.iam.ListGuardrails()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data.Guardrails = make([]iamGuardrailView, 0, len(guards))
	for _, g := range guards {
		data.Guardrails = append(data.Guardrails, iamGuardrailView{
			StoredGuardrail: g,
			HasSpec:         g.SpecJSON != "",
			Summary:         s.guardrailSummaryFromSpecJSON(g.SpecJSON),
		})
	}

	transforms, err := s.iam.ListTransforms()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lib := s.filterByName()
	data.Transforms = make([]iamTransformView, 0, len(transforms))
	for _, t := range transforms {
		kind, order := attachmentKindRank(t.SpecJSON, lib)
		data.Transforms = append(data.Transforms, iamTransformView{
			StoredTransform: t,
			Kind:            kind,
			Order:           order,
			Summary:         s.attachmentSummaryFromSpecJSON(t.SpecJSON, lib),
		})
	}

	data.RoleViews = s.roleViews(rolesList, pols, guards)
	data.RuleGroups = groupPoliciesByRole(data.Policies, rolesList)

	s.populateBuilderData(&data.iamBuilderData)
	s.render(w, r, "iam", data)
}

// summaryFromSpecJSON recomputes a rule's plain-English summary from its stored
// builder form-state (spec_json), so the list reflects the rule's *current*
// definition rather than a summary frozen at create time. Returns "" for raw or
// migrated rules (no spec_json) — those display their Cedar instead.
func (s *Server) summaryFromSpecJSON(specJSON string) string {
	if specJSON == "" {
		return ""
	}
	var st builderFormState
	if err := json.Unmarshal([]byte(specJSON), &st); err != nil {
		return ""
	}
	spec := s.specFromState(st)
	return iampolicies.HumanSummary(spec, s.roleName(spec.RoleID), s.connLabels(spec.ConnectionIDs))
}

// guardrailSummaryFromSpecJSON recomputes a guardrail's plain-English summary
// from its stored spec_json (same shape as a rule's), so the guardrails list is
// legible without reading Cedar. Returns "" for raw guardrails (no spec_json).
func (s *Server) guardrailSummaryFromSpecJSON(specJSON string) string {
	if specJSON == "" {
		return ""
	}
	var st builderFormState
	if err := json.Unmarshal([]byte(specJSON), &st); err != nil {
		return ""
	}
	spec := s.specFromState(st)
	return guardrailSummary(spec, s.roleName(spec.RoleID), s.connLabels(spec.ConnectionIDs))
}

// decodeAttachmentSpec decodes a stored attachment's spec_json (an
// AttachmentSpec — the binding of a reusable transform definition to a scope).
func decodeAttachmentSpec(specJSON string) (iampolicies.AttachmentSpec, bool) {
	if specJSON == "" {
		return iampolicies.AttachmentSpec{}, false
	}
	var as iampolicies.AttachmentSpec
	if err := json.Unmarshal([]byte(specJSON), &as); err != nil {
		return iampolicies.AttachmentSpec{}, false
	}
	return as, true
}

// filterByName indexes the transform-definition library by name (for attachment
// rows to look up their referenced definition's kind/rank).
func (s *Server) filterByName() map[string]iam.Filter {
	m := map[string]iam.Filter{}
	if s.iam == nil {
		return m
	}
	if fs, err := s.iam.ListFilters(); err == nil {
		for _, f := range fs {
			m[f.Name] = f
		}
	}
	return m
}

// attachmentKindRank resolves an attachment's kind + rank from the definition it
// references (the def carries them; the attachment carries only scope).
func attachmentKindRank(specJSON string, lib map[string]iam.Filter) (string, int) {
	as, ok := decodeAttachmentSpec(specJSON)
	if !ok {
		return "", 0
	}
	if def, found := lib[as.TransformName]; found {
		return string(def.Kind), def.Order
	}
	return "", 0
}

// attachmentSummaryFromSpecJSON recomputes an attachment's plain-English summary
// (which definition, its kind, scope) from spec_json so the list reads without
// Cedar.
func (s *Server) attachmentSummaryFromSpecJSON(specJSON string, lib map[string]iam.Filter) string {
	as, ok := decodeAttachmentSpec(specJSON)
	if !ok {
		return ""
	}
	var kind iam.FilterKind
	if def, found := lib[as.TransformName]; found {
		kind = def.Kind
	}
	return iampolicies.AttachmentHumanSummary(as, kind, s.roleName(as.RoleID), s.connLabels(as.ConnectionIDs))
}

// ruleSummariesByRole returns, per role id, the plain-English summaries of the
// rules that grant it. The Tokens page uses it to roll up "what can this token
// actually do" — a token's capability is the union over its roles.
func (s *Server) ruleSummariesByRole() map[string][]string {
	out := map[string][]string{}
	if s.iam == nil {
		return out
	}
	pols, err := s.iam.ListPolicies()
	if err != nil {
		return out
	}
	for _, p := range pols {
		if p.SpecJSON == "" {
			continue
		}
		var st builderFormState
		if err := json.Unmarshal([]byte(p.SpecJSON), &st); err != nil {
			continue
		}
		if sum := s.summaryFromSpecJSON(p.SpecJSON); sum != "" {
			out[st.RoleID] = append(out[st.RoleID], sum)
		}
	}
	return out
}

// specFromState reconstructs a RuleSpec from a stored builder form-state, the
// inverse of the capture in parseBuilderForm. It is used only to render a
// human-readable summary, so it resolves scopes and condition kinds via the
// connector metadata exactly as parseBuilderForm did.
func (s *Server) specFromState(st builderFormState) iampolicies.RuleSpec {
	meta := s.connectorMeta(st.ConnectorType)
	spec := iampolicies.RuleSpec{
		RoleID:        st.RoleID,
		Effect:        st.Effect,
		ConnectorType: st.ConnectorType,
		OpScope:       st.OpScope,
		Operations:    st.Operations,
	}
	if st.ConnScope == "specific" {
		spec.ConnectionIDs = st.Connections
	}
	if st.ScopeKey != "" {
		for _, sc := range meta.RuleScopes {
			if sc.Key != st.ScopeKey {
				continue
			}
			for _, connID := range spec.ConnectionIDs {
				spec.Scopes = append(spec.Scopes, iampolicies.ScopeRef{
					EntityType: sc.EntityType,
					ID:         iampolicies.BuildScopeID(sc.IDFormat, connID, st.ScopeFields),
				})
			}
			break
		}
	}
	if st.ConditionMode == "script" {
		spec.ConditionMode = "script"
		spec.ConditionScript = iampolicies.ScriptCondSpec{
			Command: iampolicies.ScriptCommandFor(st.ConditionScriptLanguage),
			Path:    st.ConditionScriptPath,
		}
	} else {
		condMeta := map[string]connector.RuleCondition{}
		for _, c := range meta.RuleConditions {
			condMeta[c.Key] = c
		}
		for _, bc := range st.Conditions {
			cm := condMeta[bc.Key]
			spec.Conditions = append(spec.Conditions, iampolicies.ConditionInput{
				Kind: cm.Kind, CtxPath: cm.CtxPath, Op: bc.Op, Value: bc.Value, Ops: cm.Ops,
			})
		}
	}
	spec.Filters = st.Filters
	return spec
}

// roleViews pairs each role with its blast-radius counts (rules + guardrails
// that target it, tokens that reference it) for the Roles list / delete confirm.
func (s *Server) roleViews(rolesList []roles.Role, pols []iampolicies.StoredPolicy, guards []iampolicies.StoredGuardrail) []iamRoleView {
	out := make([]iamRoleView, 0, len(rolesList))
	for _, role := range rolesList {
		marker := iampolicies.RoleMarker(role.ID)
		v := iamRoleView{Role: role}
		for _, p := range pols {
			if strings.Contains(p.Cedar, marker) {
				v.RuleCount++
			}
		}
		for _, g := range guards {
			if strings.Contains(g.Cedar, marker) {
				v.GuardrailCount++
			}
		}
		if n, err := s.tokens.TokensUsingRole(role.ID); err == nil {
			v.TokenCount = n
		}
		out = append(out, v)
	}
	return out
}

// groupPoliciesByRole buckets the rules list under the role each rule targets,
// in role-creation order, with raw/unscoped rules collected last under "". A
// rule's role comes from its builder spec when present, else from the role
// marker in its raw Cedar.
func groupPoliciesByRole(pols []iamPolicyView, rolesList []roles.Role) []ruleGroupView {
	idToName := make(map[string]string, len(rolesList))
	for _, r := range rolesList {
		idToName[r.ID] = r.Name
	}
	groups := make([]ruleGroupView, 0, len(rolesList)+1)
	index := map[string]int{}
	ensure := func(roleID string) int {
		if i, ok := index[roleID]; ok {
			return i
		}
		index[roleID] = len(groups)
		groups = append(groups, ruleGroupView{RoleID: roleID, RoleName: idToName[roleID]})
		return index[roleID]
	}
	// Seed groups in role order so empty roles still appear, then append rules.
	for _, r := range rolesList {
		ensure(r.ID)
	}
	for _, p := range pols {
		i := ensure(policyRoleID(p.StoredPolicy, rolesList))
		groups[i].Policies = append(groups[i].Policies, p)
	}
	// Drop seeded role groups that ended up with no rules (keep the page tight),
	// but always keep a group that has rules.
	pruned := groups[:0]
	for _, g := range groups {
		if len(g.Policies) > 0 {
			pruned = append(pruned, g)
		}
	}
	return pruned
}

// policyRoleID resolves the role a stored rule targets: its builder spec's
// role_id when present, else the first role whose Cedar marker appears in the
// raw policy text. "" means "any role / unscoped".
func policyRoleID(p iampolicies.StoredPolicy, rolesList []roles.Role) string {
	if p.SpecJSON != "" {
		var st builderFormState
		if json.Unmarshal([]byte(p.SpecJSON), &st) == nil && st.RoleID != "" {
			return st.RoleID
		}
	}
	for _, r := range rolesList {
		if strings.Contains(p.Cedar, iampolicies.RoleMarker(r.ID)) {
			return r.ID
		}
	}
	return ""
}

// renderIAMError re-renders the IAM page with a friendly error banner instead of
// a raw error page when a form submission fails validation. The operator sees
// what went wrong and the rest of the page (rules, library) is intact.
func (s *Server) renderIAMError(w http.ResponseWriter, r *http.Request, msg string) {
	s.renderIAM(w, r, &iamPageData{Error: msg, Section: iamSection(r)})
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
	contentUnion := map[string]string{} // key → label, de-duped across connectors
	reg := s.iamRegistry
	if reg == nil {
		reg = s.registry
	}
	if reg != nil {
		for _, m := range reg.AllMetas() {
			ops := make([]iamOpView, 0, len(m.Operations))
			for _, o := range m.Operations {
				ops = append(ops, iamOpView{Name: o.Name, ReadOnly: o.ReadOnly, Disabled: o.Disabled, DisabledReason: o.DisabledReason})
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
				conds = append(conds, iamCondView{Key: c.Key, Label: c.Label, Help: c.Help, Kind: c.Kind, CtxPath: c.CtxPath, Ops: c.Ops})
			}
			for _, cf := range m.ContentFields {
				if _, ok := contentUnion[cf.Key]; !ok {
					contentUnion[cf.Key] = cf.Label
				}
			}

			data.Connectors = append(data.Connectors, iamConnectorOption{Type: m.Type, Name: m.Name})
			catalog[m.Type] = map[string]any{
				"operations": ops, "connections": conns, "scopes": scopes, "conditions": conds,
			}
		}
	}
	sort.Slice(data.Connectors, func(i, j int) bool { return data.Connectors[i].Name < data.Connectors[j].Name })

	for k, label := range contentUnion {
		data.ContentFields = append(data.ContentFields, iamContentFieldView{Key: k, Label: label})
	}
	sort.Slice(data.ContentFields, func(i, j int) bool { return data.ContentFields[i].Label < data.ContentFields[j].Label })

	// Filter library: rendered server-side in the library card and the
	// builder's response-filter checkboxes, and mirrored into the catalog so
	// client-side JS can reach it too.
	if fs, err := s.iam.ListFilters(); err == nil {
		filters := make([]iamFilterView, 0, len(fs))
		for _, f := range fs {
			filters = append(filters, iamFilterView{Name: f.Name, Kind: string(f.Kind), Order: f.Order})
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

// handleIAMRoleDelete deletes a role and CASCADES (POST /iam/roles/{id}/delete):
// it strips the role from every token, then deletes the rules and guardrails
// that target it, then the role itself. The token strip runs FIRST and is the
// security-critical step — a token that kept the (now-deleted) role id in its
// set would be synthesized as `in` that role by the IAM engine, so the access
// would survive a UI-only delete. Ordering is fail-safe: if a later step errors,
// access is already revoked.
func (s *Server) handleIAMRoleDelete(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	id := r.PathValue("id")

	tokensChanged, err := s.tokens.RemoveRoleFromAll(id)
	if err != nil {
		http.Error(w, "revoke role from tokens: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rulesDeleted, err := s.iam.DeletePoliciesForRole(id)
	if err != nil {
		http.Error(w, "delete role rules: "+err.Error(), http.StatusInternalServerError)
		return
	}
	guardsDeleted, err := s.iam.DeleteGuardrailsForRole(id)
	if err != nil {
		http.Error(w, "delete role guardrails: "+err.Error(), http.StatusInternalServerError)
		return
	}
	transformsDeleted, err := s.iam.DeleteTransformsForRole(id)
	if err != nil {
		http.Error(w, "delete role transforms: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.roles.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.role.delete", id,
		map[string]any{"tokens_changed": tokensChanged, "rules_deleted": rulesDeleted, "guardrails_deleted": guardsDeleted, "transforms_deleted": transformsDeleted}, "success")
	http.Redirect(w, r, "/iam", http.StatusSeeOther)
}

// handleIAMFilterCreate creates a filter-library entry (POST /iam/filters).
// The filter library holds response TRANSFORMS (redact / exclude_items /
// script_filter) authored by name; rules in the builder then reference them via
// the @filters annotation (the builder handler reads r.Form["filters"]). A script
// that DECIDES allow/deny/approval is not a filter — it's a rule's script
// condition (spec §5.4), authored on the rule.
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

	kind, config, perr := s.parseFilterConfig(r)
	if perr != nil {
		http.Error(w, perr.msg, perr.code)
		return
	}

	if _, err := s.iam.CreateFilter(name, r.FormValue("description"), kind, parseFilterOrder(r, kind), config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.filter.create", name,
		map[string]any{"kind": string(kind)}, "success")
	http.Redirect(w, r, "/iam?section=transforms", http.StatusSeeOther)
}

// parseFilterConfig reads the filter form's kind + per-kind config, shared by
// filter create and edit so the two can never diverge. r.ParseForm must have
// been called. A library filter is a connector-AGNOSTIC transform (just a
// pattern / a script) — it declares no fields; field-targeting comes from the
// connector of the rule/guardrail it's attached to at request time.
func (s *Server) parseFilterConfig(r *http.Request) (iam.FilterKind, map[string]any, *parseError) {
	kindStr := r.FormValue("kind")
	config := map[string]any{}
	switch kindStr {
	case string(iam.KindRedact), string(iam.KindExcludeItems):
		// redact and exclude share the SAME matching model: a list of patterns
		// interpreted by a match mode (contains|regex). redact masks matches;
		// exclude drops list items that match.
		var patterns []string
		for _, line := range strings.Split(r.FormValue("patterns"), "\n") {
			if p := strings.TrimSpace(line); p != "" {
				patterns = append(patterns, p)
			}
		}
		if len(patterns) == 0 {
			return "", nil, &parseError{msg: "at least one pattern is required", code: http.StatusBadRequest}
		}
		config["patterns"] = patterns
		if m := r.FormValue("match"); m == "regex" {
			config["match"] = "regex"
		} else {
			config["match"] = "contains"
		}
		return iam.FilterKind(kindStr), config, nil
	case string(iam.KindScriptFilter):
		// script_filter is a post-execution response transform (rewrite). Config is
		// a language → interpreter and a path under the allowlisted scripts dir.
		// (A script that DECIDES allow/deny/approval is not a filter — it's a rule's
		// script CONDITION, authored on the rule, spec §5.4.)
		path := strings.TrimSpace(r.FormValue("script_path"))
		if err := iampolicies.ValidateScriptPath(path); err != nil {
			return "", nil, &parseError{msg: "script path rejected: " + err.Error(), code: http.StatusBadRequest}
		}
		// Language selector → interpreter (Python or JavaScript/Node). Validate it
		// against the command allowlist before storing.
		command := iampolicies.ScriptCommandFor(r.FormValue("language"))
		if err := iampolicies.ValidateScriptCommand(command); err != nil {
			return "", nil, &parseError{msg: "script runtime rejected: " + err.Error(), code: http.StatusBadRequest}
		}
		config["command"] = command
		config["path"] = path
		return iam.FilterKind(kindStr), config, nil
	default:
		return "", nil, &parseError{msg: "unknown filter kind", code: http.StatusBadRequest}
	}
}

// defaultFilterOrder gives a sensible per-kind rank so the common pipeline works
// without the operator setting one — exclusions run before redactions before
// scripts (lower runs first).
func defaultFilterOrder(kind iam.FilterKind) int {
	switch kind {
	case iam.KindExcludeItems:
		return 10
	case iam.KindRedact:
		return 20
	default:
		return 30
	}
}

// parseFilterOrder reads the operator-set rank, falling back to the per-kind
// default when the field is blank or unparseable. Shared by filter create+edit.
func parseFilterOrder(r *http.Request, kind iam.FilterKind) int {
	if v := strings.TrimSpace(r.FormValue("order")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultFilterOrder(kind)
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
	http.Redirect(w, r, "/iam?section=transforms", http.StatusSeeOther)
}

// iamFilterEditPageData is the view-model for iam_filter_edit.html. The name is
// the stable key (not editable); the form prefills the kind + per-kind config.
type iamFilterEditPageData struct {
	Active      string
	CSRFToken   string
	Error       string
	Name        string
	Description string
	Kind        string
	Order       int
	// redact / exclude_items
	Patterns string // one per line
	Match    string // contains|regex
	// script_guard
	ScriptPath string
	Language   string // python|javascript
}

// handleIAMFilterEditPage renders the edit form for one filter
// (GET /iam/filters/{name}/edit).
func (s *Server) handleIAMFilterEditPage(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	s.renderFilterEditPage(w, r, r.PathValue("name"), "")
}

// renderFilterEditPage renders the filter edit form prefilled from storage,
// optionally with a friendly error banner (shared by the GET page and the
// update handler's validation-failure path).
func (s *Server) renderFilterEditPage(w http.ResponseWriter, r *http.Request, name, errMsg string) {
	f, err := s.iam.GetFilter(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	data := &iamFilterEditPageData{
		Active: "iam-guardrails", Error: errMsg,
		Name: f.Name, Description: f.Description, Kind: string(f.Kind), Order: f.Order, Match: "contains",
	}
	switch f.Kind {
	case iam.KindRedact, iam.KindExcludeItems:
		data.Patterns = strings.Join(anyToStrings(f.Config["patterns"]), "\n")
		if m, _ := f.Config["match"].(string); m == "regex" {
			data.Match = "regex"
		}
	case iam.KindScriptFilter:
		data.ScriptPath, _ = f.Config["path"].(string)
		cmd, _ := f.Config["command"].(string)
		data.Language = languageForCommand(cmd)
	}
	s.render(w, r, "iam_filter_edit", data)
}

// handleIAMFilterUpdate edits a filter in place (POST /iam/filters/{name}/update).
// It reuses parseFilterConfig so create and edit can't diverge.
func (s *Server) handleIAMFilterUpdate(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := r.PathValue("name")
	kind, config, perr := s.parseFilterConfig(r)
	if perr != nil {
		s.renderFilterEditPage(w, r, name, perr.msg)
		return
	}
	if err := s.iam.UpdateFilter(name, r.FormValue("description"), kind, parseFilterOrder(r, kind), config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.filter.update", name,
		map[string]any{"kind": string(kind)}, "success")
	http.Redirect(w, r, "/iam?section=transforms", http.StatusSeeOther)
}

// handleIAMRoleRename renames a role in place (POST /iam/roles/{id}/rename). The
// id is stable, so rules/guardrails/tokens that reference the role are unaffected.
// --- transforms (scoped response transforms; spec §7) ---

// attachmentSpecFromForm parses the Attach form into an AttachmentSpec + spec_json.
// The scope (role/connector/op/connections/resource) is parsed by the shared
// parseBuilderForm; the transform definition is chosen by name (the search
// picker). RoleID "" ⇒ a global attachment (the floor).
func (s *Server) attachmentSpecFromForm(r *http.Request) (iampolicies.AttachmentSpec, string, *parseError) {
	scope, _, _, perr := s.parseBuilderForm(r)
	if perr != nil {
		return iampolicies.AttachmentSpec{}, "", perr
	}
	name := strings.TrimSpace(r.FormValue("transform_name"))
	if name == "" {
		return iampolicies.AttachmentSpec{}, "", &parseError{msg: "choose a transform to attach", code: http.StatusBadRequest}
	}
	as := iampolicies.AttachmentSpec{
		TransformName: name,
		RoleID:        scope.RoleID,
		ConnectorType: scope.ConnectorType,
		OpScope:       scope.OpScope,
		Operations:    scope.Operations,
		ConnectionIDs: scope.ConnectionIDs,
		Scopes:        scope.Scopes,
	}
	specJSON := "{}"
	if b, err := json.Marshal(as); err == nil {
		specJSON = string(b)
	}
	return as, specJSON, nil
}

// handleIAMTransformCreate attaches a reusable transform definition to a scope
// (POST /iam/transforms). The attachment references the definition by name via
// @filters, so the SAME definition can be attached to many roles (or globally) —
// reuse across roles.
func (s *Server) handleIAMTransformCreate(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	as, specJSON, perr := s.attachmentSpecFromForm(r)
	if perr != nil {
		s.renderIAMError(w, r, perr.msg)
		return
	}
	// The referenced definition must exist — fail with a friendly message rather
	// than storing a dangling @filters that fail-closes every matching request.
	if _, err := s.iam.GetFilter(as.TransformName); err != nil {
		s.renderIAMError(w, r, "no transform named "+as.TransformName+" — create it in the library above first")
		return
	}
	meta := s.connectorMeta(as.ConnectorType)
	cedar, err := iampolicies.BuildAttachmentCedar(as, meta.Operations)
	if err != nil {
		s.renderIAMError(w, r, err.Error())
		return
	}
	if _, err := s.iam.CreateTransform(as.TransformName, r.FormValue("description"), cedar, specJSON, true); err != nil {
		s.renderIAMError(w, r, err.Error())
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.transform.attach", as.TransformName,
		map[string]any{"role_id": as.RoleID}, "success")
	http.Redirect(w, r, "/iam?section=transforms", http.StatusSeeOther)
}

// handleIAMTransformDelete removes a transform (POST /iam/transforms/{id}/delete).
func (s *Server) handleIAMTransformDelete(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	id := r.PathValue("id")
	if err := s.iam.DeleteTransform(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.transform.delete", id, nil, "success")
	http.Redirect(w, r, "/iam?section=transforms", http.StatusSeeOther)
}

// handleIAMTransformSetEnabled toggles a transform (POST /iam/transforms/{id}/enabled).
func (s *Server) handleIAMTransformSetEnabled(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	id := r.PathValue("id")
	enabled := r.FormValue("enabled") == "true"
	if err := s.iam.SetTransformEnabled(id, enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/iam?section=transforms", http.StatusSeeOther)
}

func (s *Server) handleIAMRoleRename(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "role name is required", http.StatusBadRequest)
		return
	}
	role, err := s.roles.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := s.roles.Update(id, name, role.Bindings); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.role.rename", id,
		map[string]any{"name": name}, "success")
	http.Redirect(w, r, "/iam", http.StatusSeeOther)
}

// anyToStrings flattens a JSON-decoded []any (or []string) of strings — filter
// config patterns come back as []any after a round-trip through SQLite JSON.
func anyToStrings(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

// languageForCommand maps a stored interpreter command back to the form's
// language option (a node command → javascript, else python).
func languageForCommand(cmd string) string {
	if strings.Contains(strings.ToLower(cmd), "node") {
		return "javascript"
	}
	return "python"
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
	// ConditionMode is "" / "declarative" (use Conditions) or "script" (use the
	// ConditionScript* fields) — the rule's condition is authored one way or the
	// other (spec §5.4).
	ConditionMode           string        `json:"condition_mode,omitempty"`
	ConditionScriptLanguage string        `json:"condition_script_language,omitempty"`
	ConditionScriptPath     string        `json:"condition_script_path,omitempty"`
	Conditions              []builderCond `json:"conditions"`
	// ExemptConditions are guardrail-only exemptions (the `unless` clause).
	ExemptConditions []builderCond `json:"exempt_conditions,omitempty"`
	Filters          []string      `json:"filters"`
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
	// Effect is the rule's decision (allow / require_approval / deny), read directly
	// from the select. In script mode the script returns the decision instead, so
	// the rule is an allow permit gated by the script — the Effect control is hidden
	// in the UI; force allow here so a stale/hand-crafted value can't leak in.
	if r.FormValue("condition_mode") == "script" {
		spec.Effect = "allow"
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
			// A resource-scope id is connection-prefixed (`<conn>/<owner>/…`), so
			// it is meaningful for exactly one connection. The builder hides the
			// scope controls unless a single connection is picked; this is the
			// server-side backstop for a hand-crafted submit.
			if len(spec.ConnectionIDs) != 1 {
				return spec, "", "", &parseError{msg: "Resource scoping (e.g. org/repo) targets a single connection — select exactly one connection above, or remove the resource scope.", code: http.StatusBadRequest}
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

	// A rule's CONDITION (its gate) is authored EITHER declaratively (cond_*) OR as
	// a script (spec §5.4) — never both. Both only apply to permit effects (Cedar
	// skips a condition-erroring policy: on a permit it fails closed → default deny;
	// on a forbid it would fail OPEN), so deny rules carry neither.
	if spec.Effect != "deny" && r.FormValue("condition_mode") == "script" {
		path := strings.TrimSpace(r.FormValue("condition_script_path"))
		if err := iampolicies.ValidateScriptPath(path); err != nil {
			return spec, "", "", &parseError{msg: "script condition path rejected: " + err.Error(), code: http.StatusBadRequest}
		}
		language := r.FormValue("condition_script_language")
		command := iampolicies.ScriptCommandFor(language)
		if err := iampolicies.ValidateScriptCommand(command); err != nil {
			return spec, "", "", &parseError{msg: "script condition runtime rejected: " + err.Error(), code: http.StatusBadRequest}
		}
		spec.ConditionMode = "script"
		spec.ConditionScript = iampolicies.ScriptCondSpec{Command: command, Path: path}
		state.ConditionMode = "script"
		state.ConditionScriptLanguage = language
		state.ConditionScriptPath = path
	} else if spec.Effect != "deny" {
		conds, st, perr := s.parseConditionSet(r, meta.RuleConditions, "cond")
		if perr != nil {
			return spec, "", "", perr
		}
		spec.Conditions = conds
		state.Conditions = st
	}

	// Exemption conditions (exempt_*) are guardrail-only: they compile to a
	// fail-safe `unless` clause (spec §7.6). Harmless on the rule form (it posts
	// none); BuildRuleCedar ignores them.
	exConds, exSt, perr := s.parseConditionSet(r, meta.RuleConditions, "exempt")
	if perr != nil {
		return spec, "", "", perr
	}
	spec.ExemptConditions = exConds
	state.ExemptConditions = exSt

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

// parseConditionSet reads the checked conditions for one form prefix ("cond" for
// grant conditions, "exempt" for guardrail exemptions) against the connector's
// declared RuleConditions, with friendly validation. Returns the compiler inputs
// and the round-trip form-state.
func (s *Server) parseConditionSet(r *http.Request, conds []connector.RuleCondition, prefix string) ([]iampolicies.ConditionInput, []builderCond, *parseError) {
	var out []iampolicies.ConditionInput
	var state []builderCond
	for _, c := range conds {
		if r.FormValue(prefix+"_"+c.Key) != "on" {
			continue
		}
		op := r.FormValue(prefix + "_" + c.Key + "_op")
		val := strings.TrimSpace(r.FormValue(prefix + "_" + c.Key + "_val"))
		if val == "" {
			return nil, nil, &parseError{
				msg:  "Enter a value for the \"" + c.Label + "\" condition, or uncheck it.",
				code: http.StatusBadRequest,
			}
		}
		if c.Kind == "number" && !isNumberValue(val) {
			return nil, nil, &parseError{
				msg:  "The \"" + c.Label + "\" condition needs a number, e.g. 1000 or 0.5 (you entered \"" + val + "\").",
				code: http.StatusBadRequest,
			}
		}
		out = append(out, iampolicies.ConditionInput{Kind: c.Kind, CtxPath: c.CtxPath, Op: op, Value: val, Ops: c.Ops})
		state = append(state, builderCond{Key: c.Key, Op: op, Value: val})
	}
	return out, state, nil
}

// isNumberValue accepts an integer or a decimal value (the builder compiles the
// fractional case to a Cedar decimal). Precise precision limits are enforced by
// the builder, which returns its own friendly error.
func isNumberValue(v string) bool {
	if _, err := strconv.ParseInt(v, 10, 64); err == nil {
		return true
	}
	_, err := strconv.ParseFloat(v, 64)
	return err == nil
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

	// Description is the operator's own free-form note (may be empty); the
	// plain-English summary is recomputed from spec_json for display, so we don't
	// overwrite the operator's words with it.
	description := strings.TrimSpace(r.FormValue("description"))
	name := r.FormValue("name")
	if name == "" {
		name = summary
	}
	// Auto-uniquify so any same-named create never fails on the UNIQUE name
	// constraint. (Reuse across roles is composition — assign a role to a token,
	// or compose roles on a token — not cloning rules.)
	name = s.uniqueRuleName(name)

	pol, err := s.iam.CreatePolicy(name, description, cedar, true)
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
		Active:      "iam",
		Error:       errMsg,
		PolicyID:    pol.ID,
		Name:        pol.Name,
		Description: pol.Description,
		HasSpec:     pol.SpecJSON != "",
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

	description := strings.TrimSpace(r.FormValue("description"))
	name := r.FormValue("name")
	if name == "" {
		name = summary
	}

	// Editing keeps the rule enabled (the list has its own enable/disable
	// toggle; edit-in-place is about the rule's content, not its on/off state).
	if err := s.iam.UpdatePolicy(id, name, description, cedar, true); err != nil {
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

// handleIAMGuardrailCreate compiles the guardrail form into a permit-only
// obligation overlay (POST /iam/guardrails). It reuses parseBuilderForm (the
// guardrail form posts the same field names); for a guardrail the obligation is
// approval (the approval checkbox posts effect="require_approval") and/or library
// filters — the allow/deny of a grant is irrelevant here. BuildGuardrailCedar
// emits a permit carrying @approval/@filters over the rule's scope; the engine's
// second pass attaches it to any matching allowed request, regardless of which
// rule granted it (spec §7.2), so composition can't bypass it.
func (s *Server) handleIAMGuardrailCreate(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	spec, _, formStateJSON, perr := s.parseBuilderForm(r)
	if perr != nil {
		s.renderIAMError(w, r, perr.msg)
		return
	}
	if spec.Effect != "require_approval" && len(spec.Filters) == 0 {
		s.renderIAMError(w, r, "A guardrail must impose approval and/or at least one filter — otherwise it does nothing.")
		return
	}

	meta := s.connectorMeta(spec.ConnectorType)
	cedar, err := iampolicies.BuildGuardrailCedar(spec, meta.Operations)
	if err != nil {
		s.renderIAMError(w, r, "Could not build guardrail: "+err.Error())
		return
	}

	summary := guardrailSummary(spec, s.roleName(spec.RoleID), s.connLabels(spec.ConnectionIDs))
	name := r.FormValue("name")
	if name == "" {
		name = summary
	}
	name = s.uniqueGuardrailName(name)

	g, err := s.iam.CreateGuardrail(name, summary, cedar, true)
	if err != nil {
		s.renderIAMError(w, r, err.Error())
		return
	}
	_ = s.iam.SetGuardrailSpec(g.ID, formStateJSON)
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.guardrail.create", g.ID,
		map[string]any{"name": name}, "success")
	http.Redirect(w, r, "/iam?section=guardrails", http.StatusSeeOther)
}

// handleIAMGuardrailDelete removes a guardrail (POST /iam/guardrails/{id}/delete).
func (s *Server) handleIAMGuardrailDelete(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	id := r.PathValue("id")
	if err := s.iam.DeleteGuardrail(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.guardrail.delete", id, nil, "success")
	http.Redirect(w, r, "/iam?section=guardrails", http.StatusSeeOther)
}

// handleIAMGuardrailSetEnabled enables/disables a guardrail
// (POST /iam/guardrails/{id}/enabled, field enabled="true"/"false").
func (s *Server) handleIAMGuardrailSetEnabled(w http.ResponseWriter, r *http.Request) {
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
	if err := s.iam.SetGuardrailEnabled(id, enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.guardrail.set_enabled", id,
		map[string]any{"enabled": enabled}, "success")
	http.Redirect(w, r, "/iam?section=guardrails", http.StatusSeeOther)
}

// iamGuardrailEditPageData is the view-model for iam_guardrail_edit.html
// (edit-in-place of one builder-authored guardrail). The guardrail's spec_json
// is the same builderFormState the rule builder stores, so the prefill JS mirrors
// the rule edit page.
type iamGuardrailEditPageData struct {
	Active      string
	CSRFToken   string
	Error       string
	HasSpec     bool
	GuardrailID string
	Name        string
	Spec        builderFormState
	iamBuilderData
}

// handleIAMGuardrailEditPage renders the edit-in-place form for one
// builder-authored guardrail (GET /iam/guardrails/{id}/edit). Guardrails with no
// stored structured form (raw Cedar) render a notice instead.
func (s *Server) handleIAMGuardrailEditPage(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	s.renderGuardrailEditPage(w, r, r.PathValue("id"), "")
}

// renderGuardrailEditPage renders the guardrail edit form, optionally with an
// error banner (shared by the GET page and the update handler's failure path).
func (s *Server) renderGuardrailEditPage(w http.ResponseWriter, r *http.Request, id, errMsg string) {
	g, err := s.iam.GetGuardrail(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	data := &iamGuardrailEditPageData{
		Active: "iam-guardrails", Error: errMsg,
		GuardrailID: g.ID, Name: g.Name, HasSpec: g.SpecJSON != "",
	}
	if data.HasSpec {
		if err := json.Unmarshal([]byte(g.SpecJSON), &data.Spec); err != nil {
			data.HasSpec = false
		} else {
			s.populateBuilderData(&data.iamBuilderData)
		}
	}
	s.render(w, r, "iam_guardrail_edit", data)
}

// handleIAMGuardrailUpdate recompiles an edited guardrail in place
// (POST /iam/guardrails/{id}/update). It reuses parseBuilderForm +
// BuildGuardrailCedar so create/edit share identical parsing and compilation.
func (s *Server) handleIAMGuardrailUpdate(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")

	spec, _, formStateJSON, perr := s.parseBuilderForm(r)
	if perr != nil {
		s.renderGuardrailEditPage(w, r, id, perr.msg)
		return
	}
	if spec.Effect != "require_approval" && len(spec.Filters) == 0 {
		s.renderGuardrailEditPage(w, r, id, "A guardrail must impose approval and/or at least one filter — otherwise it does nothing.")
		return
	}

	meta := s.connectorMeta(spec.ConnectorType)
	cedar, err := iampolicies.BuildGuardrailCedar(spec, meta.Operations)
	if err != nil {
		s.renderGuardrailEditPage(w, r, id, "Could not build guardrail: "+err.Error())
		return
	}

	summary := guardrailSummary(spec, s.roleName(spec.RoleID), s.connLabels(spec.ConnectionIDs))
	name := r.FormValue("name")
	if name == "" {
		name = summary
	}
	if err := s.iam.UpdateGuardrail(id, name, summary, cedar, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.iam.SetGuardrailSpec(id, formStateJSON)
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.guardrail.update", id,
		map[string]any{"name": name}, "success")
	http.Redirect(w, r, "/iam?section=guardrails", http.StatusSeeOther)
}

// guardrailSummary renders a one-line operator-readable description of a guardrail.
func guardrailSummary(spec iampolicies.RuleSpec, roleName string, connLabels []string) string {
	var obl []string
	if spec.Effect == "require_approval" {
		obl = append(obl, "Require approval")
	}
	if len(spec.Filters) > 0 {
		obl = append(obl, "filters["+strings.Join(spec.Filters, ", ")+"]")
	}
	var b strings.Builder
	if len(obl) == 0 {
		b.WriteString("(no obligation)")
	} else {
		b.WriteString(strings.Join(obl, " + "))
	}
	switch spec.OpScope {
	case "all":
		b.WriteString(" for all operations")
	case "read":
		b.WriteString(" for read-only operations")
	case "write":
		b.WriteString(" for write operations")
	case "specific":
		b.WriteString(" for [" + strings.Join(spec.Operations, ", ") + "]")
	}
	b.WriteString(" on " + spec.ConnectorType)
	if len(connLabels) > 0 {
		b.WriteString(" (" + strings.Join(connLabels, ", ") + ")")
	} else {
		b.WriteString(" (any connection)")
	}
	if roleName == "" {
		b.WriteString(" — any role")
	} else {
		b.WriteString(" — role: " + roleName)
	}
	return b.String()
}

// uniqueGuardrailName avoids the UNIQUE name collision for guardrails.
func (s *Server) uniqueGuardrailName(base string) string {
	gs, err := s.iam.ListGuardrails()
	if err != nil {
		return base
	}
	taken := make(map[string]bool, len(gs))
	for _, g := range gs {
		taken[g.Name] = true
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

// handleIAMExplore runs the decision explorer (POST /iam/explore).
func (s *Server) handleIAMExplore(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	data := &iamPageData{
		Section:          "explore",
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
