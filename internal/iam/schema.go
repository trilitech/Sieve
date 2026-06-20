package iam

import (
	"fmt"
	"sort"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
)

// GenerateSchema produces the Cedar schema (human-readable format) from the
// connector metas. The schema is authoring/CI-only — it validates policies at
// save and in CI; cedar.Authorize uses no schema at runtime (review C3). It is
// generated (never hand-edited) so it cannot drift from the connector catalog;
// a staleness test compares the checked-in copy to this output.
//
// Structure:
//   - namespace Sieve: core entity types + all actions (groups + leaves).
//   - namespace Sieve::<Connector>: that connector's resource object types.
//
// Each leaf action's appliesTo carries its single resource type (review M1) and
// a per-action context whose `param` record is typed from the op's ParamDefs
// (review N2: closed, validatable — not one open record).
func GenerateSchema(metas []connector.ConnectorMeta) (string, error) {
	metas = append([]connector.ConnectorMeta(nil), metas...)
	sort.Slice(metas, func(i, j int) bool { return metas[i].Type < metas[j].Type })

	var b strings.Builder

	// --- core namespace: entities + actions ---
	b.WriteString("namespace Sieve {\n")
	b.WriteString("  entity RoleGroup;\n")
	b.WriteString("  entity Role in [RoleGroup];\n")
	b.WriteString("  entity Token in [Role];\n")
	b.WriteString("  entity Connector;\n")
	b.WriteString("  entity Connection in [Connector] = { \"connection_status\"?: String };\n\n")

	// Collect action group memberships (group id -> its parent group id, "" for
	// top) and the leaf actions, deterministically.
	groupParent := map[string]string{}
	var leaves []leafAction
	for _, m := range metas {
		for _, op := range m.Operations {
			chain := actionGroupChain(m.Type, op.Name, op.ReadOnly)
			for i, g := range chain {
				parent := ""
				if i+1 < len(chain) {
					parent = chain[i+1]
				}
				groupParent[g] = parent
			}
			leaves = append(leaves, leafAction{
				id:       ActionID(m.Type, op),
				group:    chain[0],
				resource: op.ResourceType,
				params:   op.Params,
			})
		}
	}

	// Emit group actions (parents before children so the declaration reads
	// top-down; Cedar doesn't require order, but determinism does).
	groupIDs := make([]string, 0, len(groupParent))
	for g := range groupParent {
		groupIDs = append(groupIDs, g)
	}
	sort.Slice(groupIDs, func(i, j int) bool {
		di, dj := groupDepth(groupParent, groupIDs[i]), groupDepth(groupParent, groupIDs[j])
		if di != dj {
			return di < dj
		}
		return groupIDs[i] < groupIDs[j]
	})
	for _, g := range groupIDs {
		if p := groupParent[g]; p != "" {
			fmt.Fprintf(&b, "  action %q in [%q];\n", g, p)
		} else {
			fmt.Fprintf(&b, "  action %q;\n", g)
		}
	}
	b.WriteString("\n")

	// Emit leaf actions with appliesTo.
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].id < leaves[j].id })
	for _, lf := range leaves {
		res := lf.resource
		if res == "" {
			res = TypeConnection
		}
		fmt.Fprintf(&b, "  action %q in [%q] appliesTo {\n", lf.id, lf.group)
		fmt.Fprintf(&b, "    principal: [%s],\n", TypeToken)
		fmt.Fprintf(&b, "    resource: [%s],\n", res)
		fmt.Fprintf(&b, "    context: %s\n", contextRecord(lf.params))
		b.WriteString("  };\n")
	}
	b.WriteString("}\n")

	// --- per-connector resource-type namespaces ---
	byNS := map[string][]connector.ResourceType{}
	for _, m := range metas {
		for _, rt := range m.ResourceTypes {
			ns, _, err := splitType(rt.Name)
			if err != nil {
				return "", err
			}
			byNS[ns] = append(byNS[ns], rt)
		}
	}
	nsNames := make([]string, 0, len(byNS))
	for ns := range byNS {
		nsNames = append(nsNames, ns)
	}
	sort.Strings(nsNames)
	for _, ns := range nsNames {
		rts := byNS[ns]
		sort.Slice(rts, func(i, j int) bool { return rts[i].Name < rts[j].Name })
		fmt.Fprintf(&b, "\nnamespace %s {\n", ns)
		for _, rt := range rts {
			_, local, _ := splitType(rt.Name)
			parent := rt.Parent
			if parent == "" {
				parent = TypeConnection
			}
			fmt.Fprintf(&b, "  entity %s in [%s];\n", local, parent)
		}
		b.WriteString("}\n")
	}

	return b.String(), nil
}

type leafAction struct {
	id       string
	group    string
	resource string
	params   map[string]connector.ParamDef
}

// contextRecord renders the per-action context: common optional fields plus a
// typed `param` record from the op's ParamDefs (review N2).
func contextRecord(params map[string]connector.ParamDef) string {
	var sb strings.Builder
	sb.WriteString("{ \"http_method\"?: String, \"recipient_domains\"?: Set<String>, \"estimated_cost\"?: Long")
	if len(params) > 0 {
		keys := make([]string, 0, len(params))
		for k := range params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sb.WriteString(", \"param\"?: { ")
		for i, k := range keys {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "%q?: %s", k, cedarType(params[k].Type))
		}
		sb.WriteString(" }")
	}
	sb.WriteString(" }")
	return sb.String()
}

func cedarType(paramType string) string {
	switch paramType {
	case "int":
		return "Long"
	case "bool":
		return "Bool"
	case "[]string":
		return "Set<String>"
	default: // "string" and anything unmapped
		return "String"
	}
}

// splitType splits "Sieve::Google::Message" into namespace "Sieve::Google" and
// local "Message".
func splitType(name string) (ns, local string, err error) {
	i := strings.LastIndex(name, "::")
	if i < 0 {
		return "", "", fmt.Errorf("iam: resource type %q is not namespaced", name)
	}
	return name[:i], name[i+2:], nil
}

func groupDepth(parent map[string]string, g string) int {
	d := 0
	for g != "" {
		g = parent[g]
		d++
	}
	return d
}
