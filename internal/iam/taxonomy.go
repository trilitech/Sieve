package iam

import (
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
)

// Cedar entity type names. Everything is under the Sieve namespace.
const (
	TypeAction     = "Sieve::Action"
	TypeConnector  = "Sieve::Connector"
	TypeConnection = "Sieve::Connection"
	TypeRole       = "Sieve::Role"
	TypeRoleGroup  = "Sieve::RoleGroup"
	TypeToken      = "Sieve::Token"
)

// googleSubservices are the op-name prefixes that map a google op to a
// sub-service action group (gmail vs drive vs sheets …) — the distinction that
// makes the tezos_ops P0 scenario composable.
var googleSubservices = map[string]bool{
	"drive": true, "calendar": true, "sheets": true, "docs": true, "people": true,
}

// googleSubservice returns the sub-service for a google op name: the dotted
// prefix if it's a known sub-service, else "gmail" (bare names like list_emails).
func googleSubservice(opName string) string {
	if i := strings.IndexByte(opName, '.'); i >= 0 {
		if p := opName[:i]; googleSubservices[p] {
			return p
		}
	}
	return "gmail"
}

// ActionID returns the Cedar action leaf id for an op: the op's explicit Action
// override, else the derived "<connectorType>/<opName>".
func ActionID(connType string, op connector.OperationDef) string {
	if op.Action != "" {
		return op.Action
	}
	return connType + "/" + op.Name
}

// actionGroupChain returns the group action ids the leaf belongs to, MOST
// SPECIFIC FIRST, each a parent of the previous. For google it is
// [google/<svc>.<rw>, google/<rw>, <rw>]; otherwise [<conn>/<rw>, <rw>].
func actionGroupChain(connType, opName string, readOnly bool) []string {
	rw := "write"
	if readOnly {
		rw = "read"
	}
	if connType == "google" {
		svc := googleSubservice(opName)
		return []string{
			"google/" + svc + "." + rw, // e.g. google/gmail.read
			"google/" + rw,             // google/read
			rw,                         // read
		}
	}
	return []string{connType + "/" + rw, rw}
}

// ResolveAction returns the leaf action EntityUID and the entities (leaf + the
// group chain, with parent edges) that must be in the store for `action in
// <group>` to match. Because cedar.Authorize takes no schema, this hierarchy
// lives in the entity store (review C3).
func ResolveAction(connType string, op connector.OperationDef) (EntityUID, []Entity) {
	leafID := ActionID(connType, op)
	chain := actionGroupChain(connType, op.Name, op.ReadOnly)

	ents := make([]Entity, 0, len(chain)+1)
	// leaf → chain[0]
	ents = append(ents, Entity{
		UID:     EntityUID{Type: TypeAction, ID: leafID},
		Parents: []EntityUID{{Type: TypeAction, ID: chain[0]}},
	})
	// chain[i] → chain[i+1]; last has no parent
	for i, g := range chain {
		var parents []EntityUID
		if i+1 < len(chain) {
			parents = []EntityUID{{Type: TypeAction, ID: chain[i+1]}}
		}
		ents = append(ents, Entity{UID: EntityUID{Type: TypeAction, ID: g}, Parents: parents})
	}
	return EntityUID{Type: TypeAction, ID: leafID}, ents
}

// ResolveResource returns the resource leaf EntityUID and the entities (object
// chain → connection → connector, with parent edges) for the store. If the op
// has no Resource mapper (or it returns nothing), the connection itself is the
// resource (single-target connectors).
func ResolveResource(connType, connID string, op connector.OperationDef, params map[string]any) (EntityUID, []Entity) {
	connectorUID := EntityUID{Type: TypeConnector, ID: connType}
	connUID := EntityUID{Type: TypeConnection, ID: connID}

	var refs []connector.ResourceRef
	if op.Resource != nil {
		refs = op.Resource(connID, params)
	}

	// Always include connection (parent: connector) and connector.
	ents := []Entity{
		{UID: connectorUID},
		{UID: connUID, Parents: []EntityUID{connectorUID}},
	}

	if len(refs) == 0 {
		return connUID, ents
	}

	// Object chain: refs[0] (leaf) → refs[1] → … → refs[last] → connection.
	for i, r := range refs {
		var parent EntityUID
		if i+1 < len(refs) {
			parent = EntityUID{Type: refs[i+1].Type, ID: refs[i+1].ID}
		} else {
			parent = connUID
		}
		ents = append(ents, Entity{
			UID:     EntityUID{Type: r.Type, ID: r.ID},
			Parents: []EntityUID{parent},
		})
	}
	return EntityUID{Type: refs[0].Type, ID: refs[0].ID}, ents
}

// BuildRequest assembles a complete Request from taxonomy pieces — this is the
// PIP (NIST SP 800-162) the PEP calls per request (PR-D). Pure; no I/O. The
// caller supplies the role's groups (iampolicies.GroupsForRole), the
// connection's type + status (connections.Get), and the op's OperationDef (from
// the connector's Meta().Operations). The connection entity is annotated with
// connection_status so a policy may gate on it.
func BuildRequest(tokenID string, roleIDs []string, connType, connID, connStatus string, op connector.OperationDef, params map[string]any) Request {
	pUID, pEnts := PrincipalEntities(tokenID, roleIDs)
	aUID, aEnts := ResolveAction(connType, op)
	rUID, rEnts := ResolveResource(connType, connID, op, params)

	ents := make([]Entity, 0, len(pEnts)+len(aEnts)+len(rEnts))
	ents = append(ents, pEnts...)
	ents = append(ents, aEnts...)
	ents = append(ents, rEnts...)

	if connStatus != "" {
		for i := range ents {
			if ents[i].UID.Type == TypeConnection && ents[i].UID.ID == connID {
				if ents[i].Attrs == nil {
					ents[i].Attrs = map[string]any{}
				}
				ents[i].Attrs["connection_status"] = connStatus
			}
		}
	}
	return Request{Principal: pUID, Action: aUID, Resource: rUID, Entities: ents, Context: buildContext(params)}
}

// buildContext projects the request into the Cedar context: http_method (for
// escape-hatch / proxy ops) and a scalar `param` record. Connector
// ContextEnrichers (recipient_domains, estimated_cost) layer in at the PEP in
// PR-D; this is the always-available baseline.
func buildContext(params map[string]any) map[string]any {
	ctx := map[string]any{}
	if m, ok := params["method"].(string); ok && m != "" {
		ctx["http_method"] = m
	}
	pm := map[string]any{}
	for k, v := range params {
		switch x := v.(type) {
		case string, bool, int, int64:
			pm[k] = v
		case float64:
			// Cedar has no float. JSON numbers decode as float64: project a
			// whole number as a Long; OMIT a non-integral one (rather than let
			// it error the whole decision). A numeric condition referencing an
			// omitted value then sees an absent attribute — which on a permit
			// (the only effect the builder allows conditions on) skips the
			// permit and falls through to default-deny, i.e. fail-closed.
			if x == float64(int64(x)) {
				pm[k] = int64(x)
			}
		}
	}
	if len(pm) > 0 {
		ctx["param"] = pm
	}
	return ctx
}

// PrincipalEntities builds the token→roles chain for the entity store. A token
// is `in` EVERY role assigned to it (RBAC composition, spec §5.1), so a rule
// targeting any of those roles applies; the agent's capability is the union.
// (The principal side comes from the role/token stores, not connector metadata;
// this helper lives here so the whole entity-store vocabulary is in one place.)
func PrincipalEntities(tokenID string, roleIDs []string) (EntityUID, []Entity) {
	tokenUID := EntityUID{Type: TypeToken, ID: tokenID}
	roleUIDs := make([]EntityUID, len(roleIDs))
	for i, r := range roleIDs {
		roleUIDs[i] = EntityUID{Type: TypeRole, ID: r}
	}
	ents := []Entity{{UID: tokenUID, Parents: roleUIDs}}
	for _, r := range roleUIDs {
		ents = append(ents, Entity{UID: r})
	}
	return tokenUID, ents
}
