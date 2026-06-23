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

// ScriptCondSpec is a rule's script-mode condition: an allowlisted interpreter
// (Command) and a script path (under the allowlisted scripts dir). When set
// (ConditionMode == "script") it compiles to @condition_script_* annotations on
// the permit; the PEP runs it per-grant (deny ⇒ that grant is vetoed).
type ScriptCondSpec struct {
	Command string
	Path    string
}

// ConditionInput is a resolved condition: Kind+CtxPath+Ops come from the
// connector's RuleCondition declaration, Op+Value from the operator's input.
type ConditionInput struct {
	Kind    string // "number" | "string" | "one_of" | "domain_allowlist" | "bool"
	CtxPath string // e.g. "context.param.amount"
	Op      string // number ops only: "lte" | "lt" | "gte" | "gt" | "eq"
	Value   string // raw user input
	// Ops restricts the condition to specific operation names (empty ⇒ all ops).
	// whenClause guards a scoped condition so it binds ONLY those ops; for any
	// other op the condition is vacuously true and never fail-closes the permit.
	Ops []string
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
	// ConditionMode selects how the rule's CONDITION (its gate) is authored:
	// "" / "declarative" ⇒ the Conditions list below; "script" ⇒ ConditionScript,
	// a program that reads the request and returns allow/deny/approval. The two are
	// mutually exclusive — a script IS the condition, an alternative to building
	// declarative ones (spec §5.4). A script condition only gates a permit
	// (allow / require_approval), never a deny.
	ConditionMode   string
	ConditionScript ScriptCondSpec
	Conditions      []ConditionInput
	Filters         []string // filter-library names → @filters annotation
	// ExemptConditions are GUARDRAIL-only: the obligation applies to every
	// matching request EXCEPT those that satisfy these, compiled into a
	// has-guarded `unless { … }` so a missing attribute keeps the obligation in
	// force (fail-safe polarity, spec §7.6). Ignored by BuildRuleCedar.
	ExemptConditions []ConditionInput
}

var (
	intRE = regexp.MustCompile(`^-?\d+$`)
	// decRE matches a fractional number with up to 4 decimal places (Cedar
	// decimal's precision); such a value compiles to a `decimal("…")` literal.
	decRE = regexp.MustCompile(`^-?\d+\.\d{1,4}$`)
)

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
// (permit/forbid). An ALLOW permit carries its obligations (approval, response
// filters) as annotations directly on the grant — they are GRANT-SCOPED, so they
// apply exactly when this rule fires (its conditions included). This is safe
// under composition because the engine UNIONS obligations across every matching
// permit (spec §7): a sibling grant can only ADD an obligation, never strip one,
// so a rule's filter/approval cannot be composed away. `require_approval` is an
// allow permit carrying @approval. A `forbid` (deny) carries no obligations.
// Guardrails (BuildGuardrailCedar) remain the GLOBAL, role-agnostic invariant
// layer — use them when the obligation must hold regardless of which rule granted.
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

	scriptMode := strings.EqualFold(spec.ConditionMode, "script")
	if scriptMode && head != "permit" {
		return "", fmt.Errorf("a script condition can only gate an allow rule, not a deny")
	}

	principal := principalClause(spec.RoleID)
	action, err := actionClause(spec, ops)
	if err != nil {
		return "", err
	}
	// In script mode the script IS the condition (run by the PEP), so the Cedar
	// when-clause carries only the resource scope — never the declarative
	// conditions (they're an alternative authoring of the same slot).
	wspec := spec
	if scriptMode {
		wspec.Conditions = nil
	}
	when, err := whenClause(wspec)
	if err != nil {
		return "", err
	}

	// A permit carries its obligations (@approval/@filters) and, in script mode,
	// its condition script (@condition_script_*). A forbid carries none.
	var prefix string
	if head == "permit" {
		var anns []string
		ann, err := obligationAnnotations(spec)
		if err != nil {
			return "", err
		}
		if ann != "" {
			anns = append(anns, ann)
		}
		if scriptMode {
			sc, err := scriptConditionAnnotations(spec.ConditionScript)
			if err != nil {
				return "", err
			}
			anns = append(anns, sc)
		}
		if len(anns) > 0 {
			prefix = strings.Join(anns, "\n") + "\n"
		}
	}
	return fmt.Sprintf("%s%s(\n  %s,\n  %s,\n  resource\n)%s;", prefix, head, principal, action, when), nil
}

// scriptConditionAnnotations renders the @condition_script_command /
// @condition_script_path lines that carry a rule's script-mode condition to the
// engine. The engine surfaces them per-grant; the PEP runs the script.
func scriptConditionAnnotations(sc ScriptCondSpec) (string, error) {
	if sc.Command == "" || sc.Path == "" {
		return "", fmt.Errorf("a script condition needs an interpreter and a script path")
	}
	return fmt.Sprintf("@condition_script_command(%s)\n@condition_script_path(%s)",
		cedarString(sc.Command), cedarString(sc.Path)), nil
}

// obligationAnnotations renders the @approval / @filters lines a permit carries
// for its obligations — shared by grant rules (BuildRuleCedar) and guardrails
// (BuildGuardrailCedar) so the two emit identical annotation syntax. Returns ""
// when the spec carries no obligation.
func obligationAnnotations(spec RuleSpec) (string, error) {
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
	return strings.Join(anns, "\n"), nil
}

// BuildGuardrailCedar compiles a RuleSpec's OBLIGATIONS (approval and/or filters)
// into a permit-only guardrail (spec §7.2), or "" when the rule carries none. The
// guardrail matches the rule's (principal, action, resource) scope but NOT its
// attribute conditions, so it covers EVERY allowed request in that scope —
// composition-safe (no sibling grant can route around it, §7.0) and fail-safe
// (broader coverage = more constraint, never less). `ops` is needed to resolve a
// "specific" op scope.
func BuildGuardrailCedar(spec RuleSpec, ops []connector.OperationDef) (string, error) {
	ann, err := obligationAnnotations(spec)
	if err != nil {
		return "", err
	}
	if ann == "" {
		return "", nil
	}
	action, err := actionClause(spec, ops)
	if err != nil {
		return "", err
	}
	unless, err := exemptionClause(spec.ExemptConditions)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s\npermit(\n  %s,\n  %s,\n  resource\n) when { %s }%s;",
		ann, principalClause(spec.RoleID), action, resourceScopeTerm(spec), unless), nil
}

// exemptionClause builds the guardrail's `unless { … }` from exemption
// conditions, each has-guarded so a MISSING attribute makes the exemption false
// and the obligation STILL applies (fail-safe polarity, spec §7.6). Returns ""
// when there are no exemptions (the obligation then always applies). Multiple
// exemptions are ANDed — a request is exempt only when it satisfies all of them
// (the conservative, more-constraining direction).
func exemptionClause(exemptions []ConditionInput) (string, error) {
	if len(exemptions) == 0 {
		return "", nil
	}
	terms := make([]string, 0, len(exemptions))
	for _, c := range exemptions {
		expr, err := guardedConditionExpr(c)
		if err != nil {
			return "", err
		}
		terms = append(terms, expr)
	}
	return " unless { " + strings.Join(terms, " && ") + " }", nil
}

// guardedConditionExpr renders an exemption condition with its has-guard chain
// prepended, so accessing an absent attribute yields false (not an error) and the
// exemption does not fire (fail-safe).
func guardedConditionExpr(c ConditionInput) (string, error) {
	expr, err := conditionExpr(c)
	if err != nil {
		return "", err
	}
	if guard := hasGuardChain(c.CtxPath); guard != "" {
		return guard + " && " + expr, nil
	}
	return expr, nil
}

// hasGuardChain turns a context path into the `has` chain that proves each step
// is present: "context.param.amount" → "context has param && context.param has
// amount"; "context.recipient_domains" → "context has recipient_domains".
func hasGuardChain(ctxPath string) string {
	parts := strings.Split(ctxPath, ".")
	if len(parts) < 2 || parts[0] != "context" {
		return ""
	}
	var guards []string
	prefix := "context"
	for _, p := range parts[1:] {
		guards = append(guards, prefix+" has "+p)
		prefix = prefix + "." + p
	}
	return strings.Join(guards, " && ")
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
// conditions (for a GRANT rule). An op-scoped condition (ConditionInput.Ops set)
// is wrapped so it binds ONLY those ops: `(!actionInOps || condition)`. For any
// other op the left side is true and short-circuits, so the condition is never
// evaluated — a recipient_count cap scoped to sends can't fail-close reads on an
// all-operations rule, and an absent attribute only fail-closes the op(s) the
// condition actually governs.
func whenClause(spec RuleSpec) (string, error) {
	terms := []string{resourceScopeTerm(spec)}
	for _, c := range spec.Conditions {
		expr, err := conditionExpr(c)
		if err != nil {
			return "", err
		}
		if guard := actionGuard(spec.ConnectorType, c.Ops); guard != "" {
			expr = "(" + guard + " || (" + expr + "))"
		}
		terms = append(terms, expr)
	}
	return " when { " + strings.Join(terms, " && ") + " }", nil
}

// actionGuard renders "the action is NOT one of these ops" — the left disjunct of
// an op-scoped condition. Empty ops ⇒ "" (condition applies to every op). Action
// ids come from the SAME taxonomy (iam.ActionID) the runtime PIP uses.
func actionGuard(connType string, ops []string) string {
	if len(ops) == 0 {
		return ""
	}
	ids := make([]string, 0, len(ops))
	for _, op := range ops {
		ids = append(ids, iam.TypeAction+"::"+cedarString(iam.ActionID(connType, connector.OperationDef{Name: op})))
	}
	return "!([" + strings.Join(ids, ", ") + "].contains(action))"
}

// conditionExpr renders one condition to a Cedar boolean expression.
func conditionExpr(c ConditionInput) (string, error) {
	if c.CtxPath == "" {
		return "", fmt.Errorf("condition missing context path")
	}
	switch c.Kind {
	case "number":
		val := strings.TrimSpace(c.Value)
		switch {
		case intRE.MatchString(val):
			// Cedar Long: the </<=/… operators apply to integers.
			op, ok := map[string]string{"lte": "<=", "lt": "<", "gte": ">=", "gt": ">", "eq": "=="}[c.Op]
			if !ok {
				return "", fmt.Errorf("unknown numeric operator %q", c.Op)
			}
			return fmt.Sprintf("%s %s %s", c.CtxPath, op, val), nil
		case decRE.MatchString(val):
			// Cedar decimal (cost, temperature, …): ordering uses the decimal
			// EXTENSION METHODS, not </<= (those are Long-only). The runtime
			// attribute must also be a decimal (buildContext projects a fractional
			// JSON number to one), else Cedar errors → fail-closed/fail-safe.
			if c.Op == "eq" {
				return fmt.Sprintf(`%s == decimal("%s")`, c.CtxPath, val), nil
			}
			method, ok := map[string]string{
				"lte": "lessThanOrEqual", "lt": "lessThan",
				"gte": "greaterThanOrEqual", "gt": "greaterThan",
			}[c.Op]
			if !ok {
				return "", fmt.Errorf("unknown numeric operator %q", c.Op)
			}
			return fmt.Sprintf(`%s.%s(decimal("%s"))`, c.CtxPath, method, val), nil
		default:
			return "", fmt.Errorf("numeric condition needs a number (e.g. 1000 or 0.5, up to 4 decimal places), got %q", c.Value)
		}
	case "string":
		return fmt.Sprintf("%s == %s", c.CtxPath, cedarString(c.Value)), nil
	case "bool":
		// A boolean flag param (e.g. a github PR's draft): context.param.X == true.
		v := strings.ToLower(strings.TrimSpace(c.Value))
		if v != "true" && v != "false" {
			return "", fmt.Errorf("boolean condition needs true or false, got %q", c.Value)
		}
		return fmt.Sprintf("%s == %s", c.CtxPath, v), nil
	case "one_of":
		// A scalar attribute (e.g. context.param.model) must be one of a set of
		// allowed values: ["a","b"].contains(<scalar>). Allow + one_of = an
		// allowlist; deny + one_of = a blocklist.
		items := splitList(c.Value)
		if len(items) == 0 {
			return "", fmt.Errorf("provide at least one value")
		}
		quoted := make([]string, 0, len(items))
		for _, it := range items {
			quoted = append(quoted, cedarString(it))
		}
		return fmt.Sprintf("[%s].contains(%s)", strings.Join(quoted, ", "), c.CtxPath), nil
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

	if strings.EqualFold(spec.ConditionMode, "script") {
		b.WriteString(" where a script decides")
	} else {
		for _, c := range spec.Conditions {
			b.WriteString(" where " + c.CtxPath + " " + c.Op + " " + c.Value)
		}
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
