package web

import (
	"net/http"

	"github.com/trilitech/Sieve/internal/iampolicies"
)

// iam.go implements the /iam admin page: the Cedar-policy list/create/delete,
// the iam_enabled toggle, and the decision explorer. It wires the IAM engine
// (internal/iam via internal/iampolicies) into the human-facing admin surface.
//
// Security: every route here is gated by the requireOperatorSession middleware
// (adminAuthWrapper in server.go) like the other admin pages — none of the
// /iam paths are in authExemptPaths, so each request needs a valid operator
// session, the POSTs need a valid CSRF token (injected client-side by nav.html
// for every same-origin POST form), and agent bearer tokens are rejected with
// 403. Cache-Control: no-store is stamped on every admin response by
// noCacheAllAdmin. None of that is re-implemented here; the wrapper is the
// single gate.
//
// All five handlers tolerate s.iam == nil (SetIAM never called): the GET page
// renders an "IAM not configured" notice and the POST handlers redirect back
// to /iam without touching storage.

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

// iamPageData is the view-model for iam.html. The CSRFToken field is
// populated by render() (via injectCSRFToken) so nav.html can expose it
// to the client-side form-submit handler — same pattern as the typed
// connectionEditData view-model.
type iamPageData struct {
	Active     string
	Configured bool
	Enabled    bool
	Policies   []iampolicies.StoredPolicy
	CSRFToken  string

	// Decision-explorer round-trip fields. ExploreDone is set after a
	// POST /iam/explore so the template knows to render the result box;
	// the Explore* inputs are echoed back so the form keeps its values.
	ExploreDone      bool
	ExploreRoleID    string
	ExploreConnID    string
	ExploreConnType  string
	ExploreOperation string
	ExploreAction    string
	ExploreReason    string
	ExploreError     string
}

// handleIAM renders the IAM admin page (GET /iam). data carries the policy
// list, the enabled flag, and (when present) a decision-explorer result.
func (s *Server) handleIAM(w http.ResponseWriter, r *http.Request) {
	s.renderIAM(w, r, &iamPageData{})
}

// renderIAM populates the page-wide fields (Configured, Enabled, Policies)
// onto the supplied data and renders the iam template. Called by handleIAM
// for a plain page load and by handleIAMExplore after a decision lookup so
// the explorer result renders without a second round-trip.
func (s *Server) renderIAM(w http.ResponseWriter, r *http.Request, data *iamPageData) {
	data.Active = "iam"
	if s.iam == nil {
		// SetIAM was never called — the engine isn't wired. Render the
		// "not configured" notice rather than dereferencing s.iam.
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

	s.render(w, r, "iam", data)
}

// handleIAMPolicyCreate creates an IAM (Cedar) policy from form fields
// name + cedar, then redirects to /iam. New policies are created enabled.
func (s *Server) handleIAMPolicyCreate(w http.ResponseWriter, r *http.Request) {
	if s.iam == nil {
		http.Redirect(w, r, "/iam", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	cedar := r.FormValue("cedar")
	if name == "" || cedar == "" {
		http.Error(w, "name and cedar are required", http.StatusBadRequest)
		return
	}

	pol, err := s.iam.CreatePolicy(name, "", cedar, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "iam.policy.create", pol.ID,
		map[string]any{"name": name}, "success")

	http.Redirect(w, r, "/iam", http.StatusSeeOther)
}

// handleIAMPolicyDelete removes an IAM policy (POST /iam/policies/{id}/delete),
// then redirects to /iam.
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

// handleIAMToggle sets the iam_enabled flag from the form field enabled
// ("true"/"false"), then redirects to /iam. Any value other than "true"
// is normalized to "false" so the stored value matches the == "true"
// comparison used by the PEPs.
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

// handleIAMExplore runs the decision explorer (POST /iam/explore): it asks the
// IAM engine to decide a synthetic request built from the form fields
// (role_id, connection_id, connector_type, operation) and re-renders the page
// with the resulting Action + Reason shown in a result box. The principal is
// the fixed pseudo-token "explorer" and the connection status is "active".
// Unlike the create/delete/toggle POSTs this does NOT redirect — it renders
// the result inline so the operator sees the decision against the form they
// just submitted.
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
