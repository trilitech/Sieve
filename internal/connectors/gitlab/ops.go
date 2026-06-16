package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
)

// encodeProject percent-encodes a GitLab project identifier for use as
// a single path segment. GitLab accepts either a numeric ID or a
// URL-encoded namespace path: "group/sub/project" must be sent as
// "group%2Fsub%2Fproject". url.PathEscape encodes the literal '/'
// correctly. We do NOT split the identifier on '/' beforehand because
// that would change the semantics — the entire namespaced path is one
// API segment.
func encodeProject(p string) string {
	return url.PathEscape(p)
}

// encodeRefOrPath percent-encodes a path that may contain '/', preserving
// the slashes (used for repository file paths where the API expects the
// embedded slashes to be percent-encoded to %2F so the URL parses as a
// single segment).
func encodeRefOrPath(p string) string {
	// GitLab's files endpoint expects the file path to be ONE segment
	// with embedded slashes encoded as %2F, same convention as project
	// identifiers.
	return url.PathEscape(p)
}

// operations is the catalog the connector exposes to the registry / UI /
// MCP layer. gitlab_request appears first so the escape hatch is
// prominent for agents and policy authors.
var operations = []connector.OperationDef{
	{
		Name:        "gitlab_request",
		Description: "Send a raw GitLab REST API request. Path must start with '/' (e.g. /projects). Body is JSON-encoded.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"method": {Type: "string", Required: true, Description: "HTTP method (GET, POST, PUT, PATCH, DELETE)."},
			"path":   {Type: "string", Required: true, Description: "API path beginning with '/' (relative to /api/v4)."},
			"query":  {Type: "string", Required: false, Description: "Query string without leading '?'."},
			"body":   {Type: "string", Required: false, Description: "JSON request body, as a string."},
		},
	},
	{
		Name:        "gitlab_list_projects",
		Description: "List projects visible to the authenticated user. Defaults to membership=true (just the user's own projects).",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"search":     {Type: "string", Required: false, Description: "Free-text filter on project name and path."},
			"owned":      {Type: "bool", Required: false, Description: "If true, restrict to projects owned by the authenticated user."},
			"membership": {Type: "bool", Required: false, Description: "If true (default), list projects the user is a member of. Set false to list all visible projects."},
			"per_page":   {Type: "int", Required: false},
			"page":       {Type: "int", Required: false},
		},
	},
	{
		Name:        "gitlab_get_file",
		Description: "Get a file's contents from a project's repository.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"project": {Type: "string", Required: true, Description: "Project ID (numeric) or namespaced path (group/project)."},
			"path":    {Type: "string", Required: true, Description: "File path within the repo."},
			"ref":     {Type: "string", Required: true, Description: "Branch, tag, or commit SHA."},
		},
	},
	{
		Name:        "gitlab_put_file",
		Description: "Create or update a file in a project's repository. Uses POST for create, PUT for update (selected by the `update` param).",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"project":        {Type: "string", Required: true, Description: "Project ID or namespaced path."},
			"path":           {Type: "string", Required: true, Description: "File path within the repo."},
			"branch":         {Type: "string", Required: true, Description: "Branch to commit against."},
			"content":        {Type: "string", Required: true, Description: "File content. UTF-8 unless encoding=base64."},
			"commit_message": {Type: "string", Required: true},
			"encoding":       {Type: "string", Required: false, Description: "text (default) or base64."},
			"update":         {Type: "bool", Required: false, Description: "If true, update an existing file (PUT). If false (default), create new (POST)."},
		},
	},
	{
		Name:        "gitlab_list_issues",
		Description: "List issues in a project.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"project":  {Type: "string", Required: true},
			"state":    {Type: "string", Required: false, Description: "opened, closed, or all."},
			"labels":   {Type: "string", Required: false, Description: "Comma-separated label names."},
			"per_page": {Type: "int", Required: false},
			"page":     {Type: "int", Required: false},
		},
	},
	{
		Name:        "gitlab_create_issue",
		Description: "Open a new issue in a project.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"project":     {Type: "string", Required: true},
			"title":       {Type: "string", Required: true},
			"description": {Type: "string", Required: false, Description: "Markdown body."},
			"labels":      {Type: "string", Required: false, Description: "Comma-separated."},
			"assignee_id": {Type: "int", Required: false},
		},
	},
	{
		Name:        "gitlab_comment_issue",
		Description: "Post a comment (note) on an issue.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"project":   {Type: "string", Required: true},
			"issue_iid": {Type: "int", Required: true, Description: "Project-relative issue ID (the iid)."},
			"body":      {Type: "string", Required: true},
		},
	},
	{
		Name:        "gitlab_list_mrs",
		Description: "List merge requests in a project.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"project":      {Type: "string", Required: true},
			"state":        {Type: "string", Required: false, Description: "opened, closed, merged, locked, or all."},
			"target_branch": {Type: "string", Required: false},
			"source_branch": {Type: "string", Required: false},
			"per_page":     {Type: "int", Required: false},
			"page":         {Type: "int", Required: false},
		},
	},
	{
		Name:        "gitlab_get_mr",
		Description: "Get a single merge request by iid.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"project": {Type: "string", Required: true},
			"mr_iid":  {Type: "int", Required: true, Description: "Project-relative MR ID."},
		},
	},
	{
		Name:        "gitlab_create_mr",
		Description: "Open a new merge request.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"project":       {Type: "string", Required: true},
			"source_branch": {Type: "string", Required: true},
			"target_branch": {Type: "string", Required: true},
			"title":         {Type: "string", Required: true},
			"description":   {Type: "string", Required: false, Description: "Markdown body."},
			"labels":        {Type: "string", Required: false, Description: "Comma-separated."},
			"remove_source_branch": {Type: "bool", Required: false},
		},
	},
	{
		Name:        "gitlab_search_blobs",
		Description: "Search file contents within a project's repository (Elasticsearch-backed where available; falls back to basic search otherwise).",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"project":  {Type: "string", Required: true},
			"search":   {Type: "string", Required: true, Description: "Search query."},
			"per_page": {Type: "int", Required: false},
			"page":     {Type: "int", Required: false},
		},
	},
}

// --- operation implementations ---

func (g *Connector) opRequest(ctx context.Context, params map[string]any) (any, error) {
	method, err := requireString(params, "method")
	if err != nil {
		return nil, err
	}
	method = strings.ToUpper(method)
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
	default:
		return nil, fmt.Errorf("gitlab: unsupported method %q", method)
	}

	path, err := requireString(params, "path")
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("gitlab: path must start with '/', got %q", path)
	}

	var q url.Values
	if qs := getString(params, "query"); qs != "" {
		parsed, err := url.ParseQuery(qs)
		if err != nil {
			return nil, fmt.Errorf("gitlab: parse query: %w", err)
		}
		q = parsed
	}

	var body any
	if b := getString(params, "body"); b != "" {
		var obj any
		if err := json.Unmarshal([]byte(b), &obj); err != nil {
			return nil, fmt.Errorf("gitlab: parse body as JSON: %w", err)
		}
		body = obj
	}

	return g.doRequest(ctx, method, path, q, body)
}

func (g *Connector) opListProjects(ctx context.Context, params map[string]any) (any, error) {
	q := url.Values{}
	qFromString(q, "search", getString(params, "search"))
	qFromInt(q, "per_page", getInt(params, "per_page"))
	qFromInt(q, "page", getInt(params, "page"))

	// membership defaults to true (current user's projects only). The
	// agent must explicitly opt out to list every visible project,
	// which on a large instance can be enormous.
	membership := true
	if v, ok := params["membership"].(bool); ok {
		membership = v
	}
	if membership {
		q.Set("membership", "true")
	}
	if v, ok := params["owned"].(bool); ok && v {
		q.Set("owned", "true")
	}

	return g.doRequest(ctx, http.MethodGet, "/projects", q, nil)
}

func (g *Connector) opGetFile(ctx context.Context, params map[string]any) (any, error) {
	project, err := requireString(params, "project")
	if err != nil {
		return nil, err
	}
	path, err := requireString(params, "path")
	if err != nil {
		return nil, err
	}
	ref, err := requireString(params, "ref")
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("ref", ref)
	apiPath := fmt.Sprintf("/projects/%s/repository/files/%s",
		encodeProject(project), encodeRefOrPath(path))
	return g.doRequest(ctx, http.MethodGet, apiPath, q, nil)
}

func (g *Connector) opPutFile(ctx context.Context, params map[string]any) (any, error) {
	project, err := requireString(params, "project")
	if err != nil {
		return nil, err
	}
	path, err := requireString(params, "path")
	if err != nil {
		return nil, err
	}
	branch, err := requireString(params, "branch")
	if err != nil {
		return nil, err
	}
	content, err := requireString(params, "content")
	if err != nil {
		return nil, err
	}
	commitMessage, err := requireString(params, "commit_message")
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"branch":         branch,
		"content":        content,
		"commit_message": commitMessage,
	}
	if enc := getString(params, "encoding"); enc != "" {
		body["encoding"] = enc
	}

	method := http.MethodPost
	if v, ok := params["update"].(bool); ok && v {
		method = http.MethodPut
	}
	apiPath := fmt.Sprintf("/projects/%s/repository/files/%s",
		encodeProject(project), encodeRefOrPath(path))
	return g.doRequest(ctx, method, apiPath, nil, body)
}

func (g *Connector) opListIssues(ctx context.Context, params map[string]any) (any, error) {
	project, err := requireString(params, "project")
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	qFromString(q, "state", getString(params, "state"))
	qFromString(q, "labels", getString(params, "labels"))
	qFromInt(q, "per_page", getInt(params, "per_page"))
	qFromInt(q, "page", getInt(params, "page"))
	apiPath := fmt.Sprintf("/projects/%s/issues", encodeProject(project))
	return g.doRequest(ctx, http.MethodGet, apiPath, q, nil)
}

func (g *Connector) opCreateIssue(ctx context.Context, params map[string]any) (any, error) {
	project, err := requireString(params, "project")
	if err != nil {
		return nil, err
	}
	title, err := requireString(params, "title")
	if err != nil {
		return nil, err
	}
	body := map[string]any{"title": title}
	if d := getString(params, "description"); d != "" {
		body["description"] = d
	}
	if l := getString(params, "labels"); l != "" {
		body["labels"] = l
	}
	if a := getInt(params, "assignee_id"); a > 0 {
		body["assignee_id"] = a
	}
	apiPath := fmt.Sprintf("/projects/%s/issues", encodeProject(project))
	return g.doRequest(ctx, http.MethodPost, apiPath, nil, body)
}

func (g *Connector) opCommentIssue(ctx context.Context, params map[string]any) (any, error) {
	project, err := requireString(params, "project")
	if err != nil {
		return nil, err
	}
	iid := getInt(params, "issue_iid")
	if iid <= 0 {
		return nil, fmt.Errorf("gitlab: param %q required and must be > 0", "issue_iid")
	}
	body, err := requireString(params, "body")
	if err != nil {
		return nil, err
	}
	apiPath := fmt.Sprintf("/projects/%s/issues/%d/notes", encodeProject(project), iid)
	return g.doRequest(ctx, http.MethodPost, apiPath, nil, map[string]any{"body": body})
}

func (g *Connector) opListMRs(ctx context.Context, params map[string]any) (any, error) {
	project, err := requireString(params, "project")
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	qFromString(q, "state", getString(params, "state"))
	qFromString(q, "target_branch", getString(params, "target_branch"))
	qFromString(q, "source_branch", getString(params, "source_branch"))
	qFromInt(q, "per_page", getInt(params, "per_page"))
	qFromInt(q, "page", getInt(params, "page"))
	apiPath := fmt.Sprintf("/projects/%s/merge_requests", encodeProject(project))
	return g.doRequest(ctx, http.MethodGet, apiPath, q, nil)
}

func (g *Connector) opGetMR(ctx context.Context, params map[string]any) (any, error) {
	project, err := requireString(params, "project")
	if err != nil {
		return nil, err
	}
	iid := getInt(params, "mr_iid")
	if iid <= 0 {
		return nil, fmt.Errorf("gitlab: param %q required and must be > 0", "mr_iid")
	}
	apiPath := fmt.Sprintf("/projects/%s/merge_requests/%d", encodeProject(project), iid)
	return g.doRequest(ctx, http.MethodGet, apiPath, nil, nil)
}

func (g *Connector) opCreateMR(ctx context.Context, params map[string]any) (any, error) {
	project, err := requireString(params, "project")
	if err != nil {
		return nil, err
	}
	source, err := requireString(params, "source_branch")
	if err != nil {
		return nil, err
	}
	target, err := requireString(params, "target_branch")
	if err != nil {
		return nil, err
	}
	title, err := requireString(params, "title")
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"source_branch": source,
		"target_branch": target,
		"title":         title,
	}
	if d := getString(params, "description"); d != "" {
		body["description"] = d
	}
	if l := getString(params, "labels"); l != "" {
		body["labels"] = l
	}
	if v, ok := params["remove_source_branch"].(bool); ok {
		body["remove_source_branch"] = v
	}
	apiPath := fmt.Sprintf("/projects/%s/merge_requests", encodeProject(project))
	return g.doRequest(ctx, http.MethodPost, apiPath, nil, body)
}

func (g *Connector) opSearchBlobs(ctx context.Context, params map[string]any) (any, error) {
	project, err := requireString(params, "project")
	if err != nil {
		return nil, err
	}
	search, err := requireString(params, "search")
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("scope", "blobs")
	q.Set("search", search)
	qFromInt(q, "per_page", getInt(params, "per_page"))
	qFromInt(q, "page", getInt(params, "page"))
	apiPath := fmt.Sprintf("/projects/%s/search", encodeProject(project))
	return g.doRequest(ctx, http.MethodGet, apiPath, q, nil)
}
