package iammigrate

import (
	"strings"

	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/iam"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/policies"
	"github.com/trilitech/Sieve/internal/roles"
)

// AllReport summarizes a full legacy→IAM migration.
type AllReport struct {
	PoliciesCreated int
	FiltersCreated  int
	Manual          []ManualItem
}

// MigrateAll converts every legacy role-binding's `rules` policies into IAM
// policies + filter-library entries. One IAM policy per role aggregates that
// role's binding statements (scoped to each binding's connection). It is the
// one-shot bridge run when an operator enables the IAM engine; the caller
// guards idempotency (run only when no IAM policies exist yet). Non-`rules`
// policy types are reported as manual-port items, never mis-translated.
//
// connections/tokens are read-only here — credentials are never touched.
func MigrateAll(
	policiesSvc *policies.Service,
	rolesSvc *roles.Service,
	connSvc *connections.Service,
	iamSvc *iampolicies.Service,
) (AllReport, error) {
	var rep AllReport
	rs, err := rolesSvc.List()
	if err != nil {
		return rep, err
	}

	for _, role := range rs {
		var stmts []string
		var filters []iam.Filter

		for _, b := range role.Bindings {
			conn, err := connSvc.Get(b.ConnectionID)
			if err != nil {
				continue // connection removed; the binding is dead — skip (default deny)
			}
			for _, pid := range b.PolicyIDs {
				p, err := policiesSvc.Get(pid)
				if err != nil {
					continue
				}
				if p.PolicyType != "rules" {
					rep.Manual = append(rep.Manual, ManualItem{
						PolicyID: p.ID, Rule: -1,
						Reason: "policy_type " + p.PolicyType + " is not auto-migratable — port by hand",
					})
					continue
				}
				res, err := MigrateRulesBinding(conn.ConnectorType, role.ID, b.ConnectionID,
					PolicyInput{ID: p.ID, Config: p.PolicyConfig})
				if err != nil {
					return rep, err
				}
				if res.Cedar != "" {
					stmts = append(stmts, res.Cedar)
				}
				filters = append(filters, res.Filters...)
				rep.Manual = append(rep.Manual, res.Manual...)
			}
		}

		for _, f := range dedupeFilters(filters) {
			if _, err := iamSvc.CreateFilter(f.Name, "migrated", f.Kind, f.Order, f.Config); err == nil {
				rep.FiltersCreated++
			}
			// A duplicate filter name (UNIQUE) means an earlier role already
			// created it — fine, it's shared. Ignore the error.
		}
		if len(stmts) > 0 {
			if _, err := iamSvc.CreatePolicy("mig:"+role.Name, "migrated from role "+role.Name,
				strings.Join(stmts, "\n\n"), true); err == nil {
				rep.PoliciesCreated++
			}
		}
	}
	return rep, nil
}
