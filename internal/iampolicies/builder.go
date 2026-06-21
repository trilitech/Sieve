package iampolicies

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iam"
)

// builder.go compiles the admin UI's visual rules into Cedar, so an operator
// never types Cedar. Each RuleSpec is ONE allow/deny/approval rule; the policy
// list is the iptables-like chain (Cedar: forbid overrides permit, and no
// matching permit ⇒ default deny). Generated action ids / entity types come from
// the SAME taxonomy the runtime PIP uses (internal/iam), so a rule built here
// and a live request resolve identically.
//
// Beyond operations, a rule can carry connector-tailored RESOURCE SCOPES
// (resource in Github::Repo::"…"), CONDITIONS (context.param.amount <= N), and
// OBLIGATIONS (approval, response filters) — everything the legacy rules engine
// expressed, plus Cedar's conditions.

// ScopeRef is a resolved resource-scope entity reference (built by the handler
// from a connector RuleScope + the user's inputs via BuildScopeID).
type ScopeRef struct {
	EntityType string // e.g. "Sieve::Github::Repo"
	ID         string // e.g. "<conn>/<owner>/<repo>"
}

// ConditionInput is a resolved condition: Kind+CtxPath come from the connector's
// RuleCondition declaration, Op+Value from the operator's input.
type ConditionInput struct {
	Kind    string // "number" | "string" | "domain_allowlist"
	CtxPath string // e.g. "context.param.amount"
	Op      string // number ops only: "lte" | "lt" | "gte" | "gt" | "eq"
	Value   string // raw user input
}

// RuleSpec is one rule composed in the builder form.
type RuleSpec struct {
	RoleID        string   // "" ⇒ any principal
	Effect        string   // "allow" | "deny" | "require_approval"
	ConnectorType string   // required; connector-gates the rule
	OpScope       string   // "all" | "read" | "write" | "specific"
	Operations    []string // op NAMES when OpScope == "specific"
	ConnectionIDs []string // empty ⇒ any connection of ConnectorType (ignored if Scopes set)
	Scopes        []ScopeRef
	Conditions    []ConditionInput
	Filters       []string // filter-library names → @filters annotation
}

var intRE = regexp.MustCompile(`^-?\d+$`)

// cedarString renders a Go string as a quoted Cedar string literal.
func cedarString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// BuildScopeID builds a resource-scope entity id from a connector RuleScope's
// IDFormat: "{conn}" → connID and "{<field>}" → fields[field].
func BuildScopeID(format, connID string, fields map[string]string) string {
	out := strings.ReplaceAll(format, "{conn}", connID)
	for k, v := range fields {
		out = strings.ReplaceAll(out, "{"+k+"}", v)
	}
	return out
}

// BuildRuleCedar compiles a RuleSpec into a single Cedar GRANT statement
// (permit/forbid) — no obligations. Obligations (approval, filters) are authored
// as guardrails and compiled by BuildGuardrailCedar (spec §7.2): an obligation on
// a grant would be silently stripped by a sibling grant under composition (§7.0).
// `require_approval` is an allow at the grant layer; its approval obligation is
// the companion guardrail.
func BuildRuleCedar(spec RuleSpec, ops []connector.OperationDef) (string, error) {
	if spec.ConnectorType == "" {
		return "", fmt.Errorf("connector type is required")
	}

	var head string
	switch spec.Effect {
	case "allow", "require_approval":
		head = "permit"
	case "deny":
		head = "forbid"
	default:
		return "", fmt.Errorf("unknown effect %q", spec.Effect)
	}

	principal := principalClause(spec.RoleID)
	action, err := actionClause(spec, ops)
	if err != nil {
		return "", err
	}
	when, err := whenClause(spec)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s(\n  %s,\n  %s,\n  resource\n)%s;", head, principal, action, when), nil
}

// BuildGuardrailCedar compiles a RuleSpec's OBLIGATIONS (approval and/or filters)
// into a permit-only guardrail (spec §7.2), or "" when the rule carries none. The
// guardrail matches the rule's (principal, action, resource) scope but NOT its
// attribute conditions, so it covers EVERY allowed request in that scope —
// composition-safe (no sibling grant can route around it, §7.0) and fail-safe
// (broader coverage = more constraint, never less). `ops` is needed to resolve a
// "specific" op scope.
func BuildGuardrailCedar(spec RuleSpec, ops []connector.OperationDef) (string, error) {
	var anns []string
	if spec.Effect == "require_approval" {
		anns = append(anns, `@approval("required")`)
	}
	if len(spec.Filters) > 0 {
		for _, f := range spec.Filters {
			if strings.ContainsAny(f, " \t\"") {
				return "", fmt.Errorf("invalid filter name %q", f)
			}
		}
		anns = append(anns, fmt.Sprintf("@filters(%s)", cedarString(strings.Join(spec.Filters, " "))))
	}
	if len(anns) == 0 {
		return "", nil
	}
	action, err := actionClause(spec, ops)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s\npermit(\n  %s,\n  %s,\n  resource\n) when { %s };",
		strings.Join(anns, "\n"), principalClause(spec.RoleID), action, resourceScopeTerm(spec)), nil
}

// principalClause renders the principal scope for a role id ("" ⇒ any principal).
func principalClause(roleID string) string {
	if roleID == "" {
		return "principal"
	}
	return "principal in " + iam.TypeRole + "::" + cedarString(roleID)
}

func actionClause(spec RuleSpec, ops []connector.OperationDef) (string, error) {
	switch spec.OpScope {
	case "all":
		return "action", nil
	case "read":
		return "action in [" + iam.TypeAction + "::" + cedarString(spec.ConnectorType+"/read") + "]", nil
	case "write":
		return "action in [" + iam.TypeAction + "::" + cedarString(spec.ConnectorType+"/write") + "]", nil
	case "specific":
		if len(spec.Operations) == 0 {
			return "", fmt.Errorf("specific operations selected but none provided")
		}
		byName := make(map[string]connector.OperationDef, len(ops))
		for _, o := range ops {
			byName[o.Name] = o
		}
		ids := make([]string, 0, len(spec.Operations))
		for _, name := range spec.Operations {
			od, ok := byName[name]
			if !ok {
				od = connector.OperationDef{Name: name}
			}
			ids = append(ids, iam.TypeAction+"::"+cedarString(iam.ActionID(spec.ConnectorType, od)))
		}
		return "action in [" + strings.Join(ids, ", ") + "]", nil
	default:
		return "", fmt.Errorf("unknown operation scope %q", spec.OpScope)
	}
}

// resourceScopeTerm builds the Cedar resource constraint, most specific first:
// scopes > specific connections > the connector (the connector-gate).
func resourceScopeTerm(spec RuleSpec) string {
	switch {
	case len(spec.Scopes) > 0:
		refs := make([]string, 0, len(spec.Scopes))
		for _, s := range spec.Scopes {
			refs = append(refs, s.EntityType+"::"+cedarString(s.ID))
		}
		return "resource in [" + strings.Join(refs, ", ") + "]"
	case len(spec.ConnectionIDs) > 0:
		refs := make([]string, 0, len(spec.ConnectionIDs))
		for _, c := range spec.ConnectionIDs {
			refs = append(refs, iam.TypeConnection+"::"+cedarString(c))
		}
		return "resource in [" + strings.Join(refs, ", ") + "]"
	default:
		return "resource in " + iam.TypeConnector + "::" + cedarString(spec.ConnectorType)
	}
}

// whenClause builds the `when { … }` constraining the resource and any
// conditions (for a GRANT rule).
func whenClause(spec RuleSpec) (string, error) {
	terms := []string{resourceScopeTerm(spec)}
	for _, c := range spec.Conditions {
		expr, err := conditionExpr(c)
		if err != nil {
			return "", err
		}
		terms = append(terms, expr)
	}
	return " when { " + strings.Join(terms, " && ") + " }", nil
}

// conditionExpr renders one condition to a Cedar boolean expression.
func conditionExpr(c ConditionInput) (string, error) {
	if c.CtxPath == "" {
		return "", fmt.Errorf("condition missing context path")
	}
	switch c.Kind {
	case "number":
		op, ok := map[string]string{"lte": "<=", "lt": "<", "gte": ">=", "gt": ">", "eq": "=="}[c.Op]
		if !ok {
			return "", fmt.Errorf("unknown numeric operator %q", c.Op)
		}
		if !intRE.MatchString(strings.TrimSpace(c.Value)) {
			return "", fmt.Errorf("numeric condition needs an integer value, got %q", c.Value)
		}
		return fmt.Sprintf("%s %s %s", c.CtxPath, op, strings.TrimSpace(c.Value)), nil
	case "string":
		return fmt.Sprintf("%s == %s", c.CtxPath, cedarString(c.Value)), nil
	case "domain_allowlist":
		items := splitList(c.Value)
		if len(items) == 0 {
			return "", fmt.Errorf("domain allowlist is empty")
		}
		quoted := make([]string, 0, len(items))
		for _, it := range items {
			quoted = append(quoted, cedarString(it))
		}
		return fmt.Sprintf("[%s].containsAll(%s)", strings.Join(quoted, ", "), c.CtxPath), nil
	default:
		return "", fmt.Errorf("unknown condition kind %q", c.Kind)
	}
}

// splitList splits a comma/whitespace-separated list, trimming blanks.
func splitList(s string) []string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// HumanSummary renders a one-line operator-readable description of a rule, stored
// as the policy description so the rule list reads in plain English.
func HumanSummary(spec RuleSpec, roleName string, connLabels []string) string {
	var b strings.Builder
	switch spec.Effect {
	case "allow":
		b.WriteString("Allow ")
	case "deny":
		b.WriteString("Deny ")
	case "require_approval":
		b.WriteString("Require approval for ")
	}

	switch spec.OpScope {
	case "all":
		b.WriteString("all operations")
	case "read":
		b.WriteString("read-only operations")
	case "write":
		b.WriteString("write operations")
	case "specific":
		b.WriteString("operations [" + strings.Join(spec.Operations, ", ") + "]")
	}

	b.WriteString(" on " + spec.ConnectorType)
	switch {
	case len(spec.Scopes) > 0:
		ids := make([]string, 0, len(spec.Scopes))
		for _, s := range spec.Scopes {
			ids = append(ids, s.ID)
		}
		b.WriteString(" [" + strings.Join(ids, ", ") + "]")
	case len(connLabels) > 0:
		b.WriteString(" (" + strings.Join(connLabels, ", ") + ")")
	default:
		b.WriteString(" (any connection)")
	}

	for _, c := range spec.Conditions {
		b.WriteString(" where " + c.CtxPath + " " + c.Op + " " + c.Value)
	}
	if len(spec.Filters) > 0 {
		b.WriteString(" + filters[" + strings.Join(spec.Filters, ", ") + "]")
	}

	if roleName == "" {
		b.WriteString(" — any role")
	} else {
		b.WriteString(" — role: " + roleName)
	}
	return b.String()
}
