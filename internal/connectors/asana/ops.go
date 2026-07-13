package asana

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
)

// operations is the catalog the connector exposes to the registry / UI / MCP /
// IAM taxonomy. asana_request appears first so the escape hatch is prominent.
//
// Asana wraps request bodies under a "data" key ({"data": {...}}); the write
// ops build that wrapper for the caller from scalar params. Anything the
// curated ops don't cover goes through asana_request, whose body is a raw JSON
// string forwarded verbatim (the caller supplies the {"data": …} envelope).
var operations = []connector.OperationDef{
	{
		Name:        "asana_request",
		Description: "Send a raw Asana API request. Path must start with '/' (relative to /api/1.0, e.g. /tasks). Body is a JSON string (Asana wraps payloads under a \"data\" key).",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"method": {Type: "string", Required: true, Description: "HTTP method (GET, POST, PUT, DELETE). Case-insensitive."},
			"path":   {Type: "string", Required: true, Description: "API path beginning with '/' (relative to /api/1.0)."},
			"query":  {Type: "string", Required: false, Description: "Query string without leading '?'."},
			"body":   {Type: "string", Required: false, Description: "JSON request body, as a string."},
		},
	},
	{
		Name:        "asana_list_workspaces",
		Description: "List the workspaces the token can access.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"limit":  {Type: "int", Required: false, Description: "Page size (1-100)."},
			"offset": {Type: "string", Required: false, Description: "Pagination offset token from a prior response's next_page.offset."},
		},
	},
	{
		Name:        "asana_list_projects",
		Description: "List projects, optionally within a workspace.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"workspace":  {Type: "string", Required: false, Description: "Workspace gid to scope to."},
			"archived":   {Type: "bool", Required: false, Description: "If set, filter on archived state."},
			"limit":      {Type: "int", Required: false},
			"offset":     {Type: "string", Required: false},
			"opt_fields": {Type: "string", Required: false, Description: "Comma-separated fields to include."},
		},
	},
	{
		Name:        "asana_get_project",
		Description: "Get a single project by gid.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"project_gid": {Type: "string", Required: true},
			"opt_fields":  {Type: "string", Required: false},
		},
	},
	{
		Name:        "asana_list_tasks",
		Description: "List tasks. Asana requires a filter: a project, OR assignee together with workspace.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"project":         {Type: "string", Required: false, Description: "Project gid."},
			"assignee":        {Type: "string", Required: false, Description: "Assignee user gid (requires workspace)."},
			"workspace":       {Type: "string", Required: false, Description: "Workspace gid (required with assignee)."},
			"completed_since": {Type: "string", Required: false, Description: "ISO 8601 timestamp or 'now' to exclude older completed tasks."},
			"limit":           {Type: "int", Required: false},
			"offset":          {Type: "string", Required: false},
			"opt_fields":      {Type: "string", Required: false},
		},
	},
	{
		Name:        "asana_get_task",
		Description: "Get a single task by gid.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"task_gid":   {Type: "string", Required: true},
			"opt_fields": {Type: "string", Required: false},
		},
	},
	{
		Name:        "asana_create_task",
		Description: "Create a task. Provide a project OR a workspace.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"name":      {Type: "string", Required: true, Description: "Task title."},
			"notes":     {Type: "string", Required: false, Description: "Task description (plain text)."},
			"project":   {Type: "string", Required: false, Description: "Project gid to add the task to."},
			"workspace": {Type: "string", Required: false, Description: "Workspace gid (required if no project)."},
			"assignee":  {Type: "string", Required: false, Description: "Assignee user gid, or 'me'."},
			"due_on":    {Type: "string", Required: false, Description: "Due date, YYYY-MM-DD."},
		},
	},
	{
		Name:        "asana_update_task",
		Description: "Update fields on a task (name, notes, assignee, due date, completed).",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"task_gid":  {Type: "string", Required: true},
			"name":      {Type: "string", Required: false},
			"notes":     {Type: "string", Required: false},
			"assignee":  {Type: "string", Required: false},
			"due_on":    {Type: "string", Required: false, Description: "YYYY-MM-DD."},
			"completed": {Type: "bool", Required: false, Description: "Mark the task complete/incomplete."},
		},
	},
	{
		Name:        "asana_list_stories",
		Description: "List a task's stories (comments and activity).",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"task_gid":   {Type: "string", Required: true},
			"limit":      {Type: "int", Required: false},
			"offset":     {Type: "string", Required: false},
			"opt_fields": {Type: "string", Required: false},
		},
	},
	{
		Name:        "asana_create_story",
		Description: "Add a comment to a task.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"task_gid": {Type: "string", Required: true},
			"text":     {Type: "string", Required: true, Description: "Comment body (plain text)."},
		},
	},
	{
		Name:        "asana_list_users",
		Description: "List users in a workspace.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"workspace":  {Type: "string", Required: false, Description: "Workspace gid to scope to."},
			"limit":      {Type: "int", Required: false},
			"offset":     {Type: "string", Required: false},
			"opt_fields": {Type: "string", Required: false},
		},
	},
}

// --- helpers ---

// pagingQuery adds the common limit / offset / opt_fields params.
func pagingQuery(p map[string]any) url.Values {
	q := url.Values{}
	if n, ok := getIntPresent(p, "limit"); ok {
		q.Set("limit", strconv.Itoa(n))
	}
	if o := getString(p, "offset"); o != "" {
		q.Set("offset", o)
	}
	if f := getString(p, "opt_fields"); f != "" {
		q.Set("opt_fields", f)
	}
	return q
}

func idPath(prefix, id, suffix string) string {
	return prefix + url.PathEscape(id) + suffix
}

// dataBody wraps a fields map in Asana's required {"data": {...}} envelope.
func dataBody(fields map[string]any) map[string]any {
	return map[string]any{"data": fields}
}

// --- operation handlers ---

func (a *Connector) opRequest(ctx context.Context, params map[string]any) (any, error) {
	method, err := requireString(params, "method")
	if err != nil {
		return nil, err
	}
	method = strings.ToUpper(method)
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
	default:
		return nil, fmt.Errorf("asana: unsupported method %q", method)
	}

	path, err := requireString(params, "path")
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("asana: path must start with '/', got %q", path)
	}
	// Agents reading the Asana docs may type "/api/1.0/tasks"; doRequest
	// prepends apiPrefix unconditionally. Normalize so both conventions work.
	if path == apiPrefix || path == apiPrefix+"/" {
		return nil, fmt.Errorf("asana: path %q is just the API prefix; supply an endpoint path after it", path)
	}
	if strings.HasPrefix(path, apiPrefix+"/") {
		path = strings.TrimPrefix(path, apiPrefix)
	}

	var q url.Values
	if qs := getString(params, "query"); qs != "" {
		parsed, perr := url.ParseQuery(qs)
		if perr != nil {
			return nil, fmt.Errorf("asana: parse query: %w", perr)
		}
		q = parsed
	}

	var body any
	if b := getString(params, "body"); strings.TrimSpace(b) != "" {
		if !json.Valid([]byte(b)) {
			return nil, fmt.Errorf("asana: param %q is not valid JSON", "body")
		}
		body = json.RawMessage(b)
	}

	return a.doRequest(ctx, method, path, q, body)
}

func (a *Connector) opListWorkspaces(ctx context.Context, params map[string]any) (any, error) {
	return a.doRequest(ctx, http.MethodGet, "/workspaces", pagingQuery(params), nil)
}

func (a *Connector) opListProjects(ctx context.Context, params map[string]any) (any, error) {
	q := pagingQuery(params)
	if ws := getString(params, "workspace"); ws != "" {
		q.Set("workspace", ws)
	}
	if v, ok := params["archived"].(bool); ok {
		q.Set("archived", strconv.FormatBool(v))
	}
	return a.doRequest(ctx, http.MethodGet, "/projects", q, nil)
}

func (a *Connector) opGetProject(ctx context.Context, params map[string]any) (any, error) {
	gid, err := requireString(params, "project_gid")
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if f := getString(params, "opt_fields"); f != "" {
		q.Set("opt_fields", f)
	}
	return a.doRequest(ctx, http.MethodGet, idPath("/projects/", gid, ""), q, nil)
}

func (a *Connector) opListTasks(ctx context.Context, params map[string]any) (any, error) {
	q := pagingQuery(params)
	for _, k := range []string{"project", "assignee", "workspace", "completed_since"} {
		if v := getString(params, k); v != "" {
			q.Set(k, v)
		}
	}
	return a.doRequest(ctx, http.MethodGet, "/tasks", q, nil)
}

func (a *Connector) opGetTask(ctx context.Context, params map[string]any) (any, error) {
	gid, err := requireString(params, "task_gid")
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if f := getString(params, "opt_fields"); f != "" {
		q.Set("opt_fields", f)
	}
	return a.doRequest(ctx, http.MethodGet, idPath("/tasks/", gid, ""), q, nil)
}

func (a *Connector) opCreateTask(ctx context.Context, params map[string]any) (any, error) {
	name, err := requireString(params, "name")
	if err != nil {
		return nil, err
	}
	data := map[string]any{"name": name}
	if v := getString(params, "notes"); v != "" {
		data["notes"] = v
	}
	if v := getString(params, "project"); v != "" {
		data["projects"] = []string{v}
	}
	if v := getString(params, "workspace"); v != "" {
		data["workspace"] = v
	}
	if v := getString(params, "assignee"); v != "" {
		data["assignee"] = v
	}
	if v := getString(params, "due_on"); v != "" {
		data["due_on"] = v
	}
	if _, hasProject := data["projects"]; !hasProject {
		if _, hasWS := data["workspace"]; !hasWS {
			return nil, fmt.Errorf("asana: create_task needs a project or a workspace")
		}
	}
	return a.doRequest(ctx, http.MethodPost, "/tasks", nil, dataBody(data))
}

func (a *Connector) opUpdateTask(ctx context.Context, params map[string]any) (any, error) {
	gid, err := requireString(params, "task_gid")
	if err != nil {
		return nil, err
	}
	data := map[string]any{}
	for _, k := range []string{"name", "notes", "assignee", "due_on"} {
		if v := getString(params, k); v != "" {
			data[k] = v
		}
	}
	if v, ok := params["completed"].(bool); ok {
		data["completed"] = v
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("asana: update_task needs at least one field to change")
	}
	return a.doRequest(ctx, http.MethodPut, idPath("/tasks/", gid, ""), nil, dataBody(data))
}

func (a *Connector) opListStories(ctx context.Context, params map[string]any) (any, error) {
	gid, err := requireString(params, "task_gid")
	if err != nil {
		return nil, err
	}
	return a.doRequest(ctx, http.MethodGet, idPath("/tasks/", gid, "/stories"), pagingQuery(params), nil)
}

func (a *Connector) opCreateStory(ctx context.Context, params map[string]any) (any, error) {
	gid, err := requireString(params, "task_gid")
	if err != nil {
		return nil, err
	}
	text, err := requireString(params, "text")
	if err != nil {
		return nil, err
	}
	return a.doRequest(ctx, http.MethodPost, idPath("/tasks/", gid, "/stories"), nil, dataBody(map[string]any{"text": text}))
}

func (a *Connector) opListUsers(ctx context.Context, params map[string]any) (any, error) {
	q := pagingQuery(params)
	if ws := getString(params, "workspace"); ws != "" {
		q.Set("workspace", ws)
	}
	return a.doRequest(ctx, http.MethodGet, "/users", q, nil)
}
