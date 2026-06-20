package iampolicies

import (
	"fmt"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/iam"
)

// builder.go compiles the admin UI's visual rules into Cedar, so an operator
// never types Cedar. Each RuleSpec is ONE allow/deny/approval rule; the policy
// list is the iptables-like chain (Cedar: forbid overrides permit, and no
// matching permit ⇒ default deny). The generated action ids / entity types come
// from the SAME taxonomy the runtime PIP uses (internal/iam), so a rule built
// here and a live request resolve identically.

// RuleSpec is one rule composed in the builder form.
type RuleSpec struct {
	RoleID        string   // "" ⇒ any principal (role-agnostic)
	Effect        string   // "allow" | "deny" | "require_approval"
	ConnectorType string   // required; connector-gates the rule
	OpScope       string   // "all" | "read" | "write" | "specific"
	Operations    []string // op NAMES; required when OpScope == "specific"
	ConnectionIDs []string // empty ⇒ any connection of ConnectorType
}

// cedarString renders a Go string as a quoted Cedar string literal, escaping
// backslash and double-quote (the two characters Cedar requires escaped).
func cedarString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// BuildRuleCedar compiles a RuleSpec into a single Cedar statement. ops is the
// connector's operation catalog (registry Meta().Operations), used to resolve
// specific op names to their action leaf ids.
func BuildRuleCedar(spec RuleSpec, ops []connector.OperationDef) (string, error) {
	if spec.ConnectorType == "" {
		return "", fmt.Errorf("connector type is required")
	}

	var annotation, head string
	switch spec.Effect {
	case "allow":
		head = "permit"
	case "deny":
		head = "forbid"
	case "require_approval":
		head, annotation = "permit", "@approval(\"required\")\n"
	default:
		return "", fmt.Errorf("unknown effect %q", spec.Effect)
	}

	principal := "principal"
	if spec.RoleID != "" {
		principal = "principal in " + iam.TypeRole + "::" + cedarString(spec.RoleID)
	}

	action, err := actionClause(spec, ops)
	if err != nil {
		return "", err
	}

	var when string
	if len(spec.ConnectionIDs) == 0 {
		// Any connection of this connector type: gate on the connector entity.
		// Every connection is `in` its connector (taxonomy ResolveResource), so
		// this also enforces connector-gating (a google rule can't hit github).
		when = " when { resource in " + iam.TypeConnector + "::" + cedarString(spec.ConnectorType) + " }"
	} else {
		refs := make([]string, 0, len(spec.ConnectionIDs))
		for _, c := range spec.ConnectionIDs {
			refs = append(refs, iam.TypeConnection+"::"+cedarString(c))
		}
		when = " when { resource in [" + strings.Join(refs, ", ") + "] }"
	}

	return fmt.Sprintf("%s%s(\n  %s,\n  %s,\n  resource\n)%s;", annotation, head, principal, action, when), nil
}

// actionClause builds the `action ...` scope for a rule.
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
				od = connector.OperationDef{Name: name} // derive <connType>/<name>
			}
			ids = append(ids, iam.TypeAction+"::"+cedarString(iam.ActionID(spec.ConnectorType, od)))
		}
		return "action in [" + strings.Join(ids, ", ") + "]", nil
	default:
		return "", fmt.Errorf("unknown operation scope %q", spec.OpScope)
	}
}

// HumanSummary renders a one-line, operator-readable description of a rule, used
// as the stored policy description so the policy list reads in plain English
// instead of Cedar. roleName/connLabels are the resolved display names ("" /
// empty fall back to ids or "any").
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
	if len(connLabels) == 0 {
		b.WriteString(" (any connection)")
	} else {
		b.WriteString(" (" + strings.Join(connLabels, ", ") + ")")
	}

	if roleName == "" {
		b.WriteString(" — any role")
	} else {
		b.WriteString(" — role: " + roleName)
	}
	return b.String()
}
