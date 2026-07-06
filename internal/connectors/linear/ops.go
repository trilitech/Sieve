package linear

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/trilitech/Sieve/internal/connector"
)

// operations is the catalog the connector exposes to the registry / UI /
// MCP layer. linear_request appears first so the escape hatch is
// prominent for agents and policy authors.
//
// Linear has many GraphQL fields per type; the curated queries return a
// conservative projection (id + the human-relevant fields). Agents
// needing a wider projection can use linear_request.
var operations = []connector.OperationDef{
	{
		Name:        "linear_request",
		Description: "Send a raw Linear GraphQL query or mutation. `query` is the GraphQL document; `variables` is an optional JSON object.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"query":     {Type: "string", Required: true, Description: "GraphQL document (query or mutation)."},
			"variables": {Type: "string", Required: false, Description: "GraphQL variables as a JSON object."},
		},
	},
	{
		Name:        "linear_list_issues",
		Description: "List issues visible to the authenticated user. Optional filters narrow by team, state, or assignee.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"team_id":     {Type: "string", Required: false, Description: "Restrict to issues in this team (UUID)."},
			"state_id":    {Type: "string", Required: false, Description: "Restrict to issues in this workflow state (UUID)."},
			"assignee_id": {Type: "string", Required: false, Description: "Restrict to issues assigned to this user (UUID)."},
			"first":       {Type: "int", Required: false, Description: "Page size; Linear caps at 250. Defaults to 50."},
			"after":       {Type: "string", Required: false, Description: "Cursor from a previous page's pageInfo.endCursor."},
		},
	},
	{
		Name:        "linear_get_issue",
		Description: "Get a single issue by ID. Accepts either the issue UUID or the issue identifier string (e.g. \"ENG-123\").",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"id": {Type: "string", Required: true, Description: "Issue UUID or identifier (e.g. \"ENG-123\")."},
		},
	},
	{
		Name:        "linear_create_issue",
		Description: "Create a new issue.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"team_id":     {Type: "string", Required: true, Description: "Team to create the issue in (UUID)."},
			"title":       {Type: "string", Required: true},
			"description": {Type: "string", Required: false, Description: "Markdown body."},
			"assignee_id": {Type: "string", Required: false},
			"state_id":    {Type: "string", Required: false, Description: "Initial workflow state (UUID). If omitted, Linear uses the team's default."},
			"priority":    {Type: "int", Required: false, Description: "Priority 0–4: 0=none, 1=urgent, 2=high, 3=medium, 4=low."},
		},
	},
	{
		Name:        "linear_update_issue",
		Description: "Update an existing issue. Any omitted field is left unchanged.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"id":          {Type: "string", Required: true, Description: "Issue UUID."},
			"title":       {Type: "string", Required: false},
			"description": {Type: "string", Required: false},
			"assignee_id": {Type: "string", Required: false},
			"state_id":    {Type: "string", Required: false},
			"priority":    {Type: "int", Required: false},
		},
	},
	{
		Name:        "linear_list_teams",
		Description: "List teams the authenticated user can see.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"first": {Type: "int", Required: false, Description: "Page size. Defaults to 50."},
			"after": {Type: "string", Required: false},
		},
	},
	{
		Name:        "linear_list_users",
		Description: "List workspace users.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"first": {Type: "int", Required: false, Description: "Page size. Defaults to 50."},
			"after": {Type: "string", Required: false},
		},
	},
	{
		Name:        "linear_list_workflow_states",
		Description: "List workflow states (Backlog, In Progress, Done, …) for a team.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"team_id": {Type: "string", Required: true, Description: "Team UUID."},
		},
	},
	{
		Name:        "linear_list_comments",
		Description: "List comments on a single issue.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"issue_id": {Type: "string", Required: true, Description: "Issue UUID."},
			"first":    {Type: "int", Required: false, Description: "Page size. Defaults to 50."},
			"after":    {Type: "string", Required: false},
		},
	},
	{
		Name:        "linear_create_comment",
		Description: "Post a comment on an issue.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"issue_id": {Type: "string", Required: true, Description: "Issue UUID."},
			"body":     {Type: "string", Required: true, Description: "Markdown body."},
		},
	},
}

// ---- escape hatch ----

// opRequest implements linear_request. `variables` is accepted as a JSON
// string for shell-friendly call sites; we parse it here and pass the
// decoded map into the GraphQL request.
func (l *Connector) opRequest(ctx context.Context, params map[string]any) (any, error) {
	query, err := requireString(params, "query")
	if err != nil {
		return nil, err
	}
	var vars map[string]any
	if raw := getString(params, "variables"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &vars); err != nil {
			return nil, fmt.Errorf("linear: variables must be a JSON object: %w", err)
		}
	} else if m := getMap(params, "variables"); m != nil {
		// Allow agents that pass a typed object directly (e.g. MCP
		// clients that already unmarshal arguments).
		vars = m
	}
	return l.doGraphQL(ctx, query, vars)
}

// ---- issues ----

const issueFields = `id identifier title description priority url createdAt updatedAt
		state { id name color type }
		team { id key name }
		assignee { id name email }`

func (l *Connector) opListIssues(ctx context.Context, params map[string]any) (any, error) {
	vars := map[string]any{
		"first": clampFirst(getInt(params, "first")),
	}
	if after := getString(params, "after"); after != "" {
		vars["after"] = after
	}

	// Linear's IssueFilter input shape.
	filter := map[string]any{}
	if v := getString(params, "team_id"); v != "" {
		filter["team"] = map[string]any{"id": map[string]any{"eq": v}}
	}
	if v := getString(params, "state_id"); v != "" {
		filter["state"] = map[string]any{"id": map[string]any{"eq": v}}
	}
	if v := getString(params, "assignee_id"); v != "" {
		filter["assignee"] = map[string]any{"id": map[string]any{"eq": v}}
	}
	if len(filter) > 0 {
		vars["filter"] = filter
	}

	q := `query ListIssues($first: Int, $after: String, $filter: IssueFilter) {
		issues(first: $first, after: $after, filter: $filter) {
			pageInfo { hasNextPage endCursor }
			nodes { ` + issueFields + ` }
		}
	}`
	return l.doGraphQL(ctx, q, vars)
}

func (l *Connector) opGetIssue(ctx context.Context, params map[string]any) (any, error) {
	id, err := requireString(params, "id")
	if err != nil {
		return nil, err
	}
	q := `query GetIssue($id: String!) {
		issue(id: $id) { ` + issueFields + ` }
	}`
	return l.doGraphQL(ctx, q, map[string]any{"id": id})
}

func (l *Connector) opCreateIssue(ctx context.Context, params map[string]any) (any, error) {
	teamID, err := requireString(params, "team_id")
	if err != nil {
		return nil, err
	}
	title, err := requireString(params, "title")
	if err != nil {
		return nil, err
	}

	input := map[string]any{
		"teamId": teamID,
		"title":  title,
	}
	if v := getString(params, "description"); v != "" {
		input["description"] = v
	}
	if v := getString(params, "assignee_id"); v != "" {
		input["assigneeId"] = v
	}
	if v := getString(params, "state_id"); v != "" {
		input["stateId"] = v
	}
	// Linear's priority: 0=no-priority, 1=urgent, 2=high, 3=medium, 4=low.
	// A presence check (NOT v > 0) preserves the "explicitly set to
	// no-priority" case — without it, priority=0 would be silently dropped.
	if v, present := getIntPresent(params, "priority"); present {
		input["priority"] = v
	}

	q := `mutation CreateIssue($input: IssueCreateInput!) {
		issueCreate(input: $input) {
			success
			issue { ` + issueFields + ` }
		}
	}`
	return l.doGraphQL(ctx, q, map[string]any{"input": input})
}

func (l *Connector) opUpdateIssue(ctx context.Context, params map[string]any) (any, error) {
	id, err := requireString(params, "id")
	if err != nil {
		return nil, err
	}

	input := map[string]any{}
	if v := getString(params, "title"); v != "" {
		input["title"] = v
	}
	if v := getString(params, "description"); v != "" {
		input["description"] = v
	}
	if v := getString(params, "assignee_id"); v != "" {
		input["assigneeId"] = v
	}
	if v := getString(params, "state_id"); v != "" {
		input["stateId"] = v
	}
	// Same priority handling as create — presence-checked so explicit 0
	// (= "no priority") survives. See opCreateIssue's comment.
	if v, present := getIntPresent(params, "priority"); present {
		input["priority"] = v
	}
	if len(input) == 0 {
		return nil, fmt.Errorf("linear: linear_update_issue requires at least one mutable field")
	}

	q := `mutation UpdateIssue($id: String!, $input: IssueUpdateInput!) {
		issueUpdate(id: $id, input: $input) {
			success
			issue { ` + issueFields + ` }
		}
	}`
	return l.doGraphQL(ctx, q, map[string]any{"id": id, "input": input})
}

// ---- teams / users / workflow states ----

func (l *Connector) opListTeams(ctx context.Context, params map[string]any) (any, error) {
	vars := map[string]any{
		"first": clampFirst(getInt(params, "first")),
	}
	if after := getString(params, "after"); after != "" {
		vars["after"] = after
	}
	q := `query ListTeams($first: Int, $after: String) {
		teams(first: $first, after: $after) {
			pageInfo { hasNextPage endCursor }
			nodes { id key name description }
		}
	}`
	return l.doGraphQL(ctx, q, vars)
}

func (l *Connector) opListUsers(ctx context.Context, params map[string]any) (any, error) {
	vars := map[string]any{
		"first": clampFirst(getInt(params, "first")),
	}
	if after := getString(params, "after"); after != "" {
		vars["after"] = after
	}
	q := `query ListUsers($first: Int, $after: String) {
		users(first: $first, after: $after) {
			pageInfo { hasNextPage endCursor }
			nodes { id name email displayName active }
		}
	}`
	return l.doGraphQL(ctx, q, vars)
}

func (l *Connector) opListWorkflowStates(ctx context.Context, params map[string]any) (any, error) {
	teamID, err := requireString(params, "team_id")
	if err != nil {
		return nil, err
	}
	// Linear's WorkflowStateFilter expects `team: { id: { eq: $teamId } }`.
	q := `query ListStates($teamId: ID!) {
		workflowStates(filter: { team: { id: { eq: $teamId } } }) {
			nodes { id name color type position }
		}
	}`
	return l.doGraphQL(ctx, q, map[string]any{"teamId": teamID})
}

// ---- comments ----

func (l *Connector) opListComments(ctx context.Context, params map[string]any) (any, error) {
	issueID, err := requireString(params, "issue_id")
	if err != nil {
		return nil, err
	}
	vars := map[string]any{
		"issueId": issueID,
		"first":   clampFirst(getInt(params, "first")),
	}
	if after := getString(params, "after"); after != "" {
		vars["after"] = after
	}
	q := `query ListComments($issueId: String!, $first: Int, $after: String) {
		issue(id: $issueId) {
			comments(first: $first, after: $after) {
				pageInfo { hasNextPage endCursor }
				nodes {
					id body createdAt updatedAt url
					user { id name email }
				}
			}
		}
	}`
	return l.doGraphQL(ctx, q, vars)
}

func (l *Connector) opCreateComment(ctx context.Context, params map[string]any) (any, error) {
	issueID, err := requireString(params, "issue_id")
	if err != nil {
		return nil, err
	}
	body, err := requireString(params, "body")
	if err != nil {
		return nil, err
	}
	q := `mutation CreateComment($input: CommentCreateInput!) {
		commentCreate(input: $input) {
			success
			comment {
				id body createdAt url
				user { id name email }
			}
		}
	}`
	return l.doGraphQL(ctx, q, map[string]any{
		"input": map[string]any{
			"issueId": issueID,
			"body":    body,
		},
	})
}

// clampFirst applies a sensible default + Linear's documented cap.
// Linear's connection arguments accept up to 250 per page; without a
// cap an agent could request millions and choke the connector.
func clampFirst(v int) int {
	if v <= 0 {
		return 50
	}
	if v > 250 {
		return 250
	}
	return v
}
