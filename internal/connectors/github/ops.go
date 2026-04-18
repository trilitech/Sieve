package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/murbard/Sieve/internal/connector"
)

// escapeRepoPath percent-escapes each path segment while preserving '/'
// separators. Needed because GitHub's /contents/{path} endpoint doesn't
// accept unencoded spaces, '#', '?', etc.
func escapeRepoPath(p string) string {
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		parts[i] = url.PathEscape(seg)
	}
	return strings.Join(parts, "/")
}

// operations is the catalog the connector exposes to the registry / UI / MCP
// layer. The escape-hatch `github_request` is listed first so it's prominent.
var operations = []connector.OperationDef{
	{
		Name:        "github_request",
		Description: "Send a raw GitHub REST API request. Path must start with '/'. Body is JSON-encoded.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"method": {Type: "string", Required: true, Description: "HTTP method (GET, POST, PATCH, PUT, DELETE)."},
			"path":   {Type: "string", Required: true, Description: "API path beginning with '/', e.g. /repos/o/r/issues."},
			"query":  {Type: "string", Required: false, Description: "Query string (without leading '?')."},
			"body":   {Type: "string", Required: false, Description: "JSON request body, as a string."},
		},
	},
	{
		Name:        "github_list_repos",
		Description: "List repositories for an org or for the authenticated user.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"owner":    {Type: "string", Required: false, Description: "Org login. Omit to list the authenticated user's repos."},
			"per_page": {Type: "int", Required: false},
			"page":     {Type: "int", Required: false},
		},
	},
	{
		Name:        "github_get_file",
		Description: "Get a file's contents from a repo.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"owner": {Type: "string", Required: true},
			"repo":  {Type: "string", Required: true},
			"path":  {Type: "string", Required: true, Description: "File path within the repo."},
			"ref":   {Type: "string", Required: false, Description: "Branch, tag, or commit SHA."},
		},
	},
	{
		Name:        "github_put_file",
		Description: "Create or update a file in a repo.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"owner":   {Type: "string", Required: true},
			"repo":    {Type: "string", Required: true},
			"path":    {Type: "string", Required: true},
			"message": {Type: "string", Required: true, Description: "Commit message."},
			"content": {Type: "string", Required: true, Description: "Base64-encoded file content."},
			"branch":  {Type: "string", Required: false},
			"sha":     {Type: "string", Required: false, Description: "Required when updating an existing file."},
		},
	},
	{
		Name:        "github_list_issues",
		Description: "List issues in a repo.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"owner":    {Type: "string", Required: true},
			"repo":     {Type: "string", Required: true},
			"state":    {Type: "string", Required: false, Description: "open, closed, or all."},
			"labels":   {Type: "string", Required: false, Description: "Comma-separated list of label names."},
			"per_page": {Type: "int", Required: false},
			"page":     {Type: "int", Required: false},
		},
	},
	{
		Name:        "github_create_issue",
		Description: "Open a new issue in a repo.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"owner":     {Type: "string", Required: true},
			"repo":      {Type: "string", Required: true},
			"title":     {Type: "string", Required: true},
			"body":      {Type: "string", Required: false},
			"labels":    {Type: "[]string", Required: false},
			"assignees": {Type: "[]string", Required: false},
		},
	},
	{
		Name:        "github_comment_issue",
		Description: "Post a comment on an issue or pull request.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"owner":  {Type: "string", Required: true},
			"repo":   {Type: "string", Required: true},
			"number": {Type: "int", Required: true, Description: "Issue or PR number."},
			"body":   {Type: "string", Required: true},
		},
	},
	{
		Name:        "github_list_prs",
		Description: "List pull requests in a repo.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"owner":    {Type: "string", Required: true},
			"repo":     {Type: "string", Required: true},
			"state":    {Type: "string", Required: false, Description: "open, closed, or all."},
			"per_page": {Type: "int", Required: false},
			"page":     {Type: "int", Required: false},
		},
	},
	{
		Name:        "github_get_pr",
		Description: "Get a pull request, including diff stats and merge state.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"owner":  {Type: "string", Required: true},
			"repo":   {Type: "string", Required: true},
			"number": {Type: "int", Required: true},
		},
	},
	{
		Name:        "github_create_pr",
		Description: "Open a new pull request.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"owner": {Type: "string", Required: true},
			"repo":  {Type: "string", Required: true},
			"title": {Type: "string", Required: true},
			"head":  {Type: "string", Required: true, Description: "Branch with changes (use 'user:branch' for cross-fork PRs)."},
			"base":  {Type: "string", Required: true, Description: "Branch to merge into."},
			"body":  {Type: "string", Required: false},
			"draft": {Type: "bool", Required: false},
		},
	},
	{
		Name:        "github_search_code",
		Description: "Search code across GitHub. Use the GitHub code-search query syntax.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"q":        {Type: "string", Required: true, Description: "Search query, e.g. 'addClass repo:jquery/jquery'."},
			"per_page": {Type: "int", Required: false},
			"page":     {Type: "int", Required: false},
		},
	},
}

// --- handlers ---

func (g *Connector) opRequest(ctx context.Context, p map[string]any) (any, error) {
	method, err := requireString(p, "method")
	if err != nil {
		return nil, err
	}
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete:
	default:
		return nil, fmt.Errorf("github: method %q not allowed", method)
	}
	path, err := requireString(p, "path")
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if qs := getString(p, "query"); qs != "" {
		parsed, err := url.ParseQuery(qs)
		if err != nil {
			return nil, fmt.Errorf("github: invalid query: %w", err)
		}
		q = parsed
	}
	var body any
	if bodyStr := getString(p, "body"); bodyStr != "" {
		var decoded any
		if err := json.Unmarshal([]byte(bodyStr), &decoded); err != nil {
			return nil, fmt.Errorf("github: body must be valid JSON: %w", err)
		}
		body = decoded
	}
	return g.doRequest(ctx, method, path, q, body)
}

func (g *Connector) opListRepos(ctx context.Context, p map[string]any) (any, error) {
	q := url.Values{}
	qFromInt(q, "per_page", getInt(p, "per_page"))
	qFromInt(q, "page", getInt(p, "page"))

	owner := getString(p, "owner")
	if owner != "" {
		return g.doRequest(ctx, http.MethodGet, fmt.Sprintf("/orgs/%s/repos", owner), q, nil)
	}
	return g.doRequest(ctx, http.MethodGet, "/user/repos", q, nil)
}

func (g *Connector) opGetFile(ctx context.Context, p map[string]any) (any, error) {
	owner, err := requireString(p, "owner")
	if err != nil {
		return nil, err
	}
	repo, err := requireString(p, "repo")
	if err != nil {
		return nil, err
	}
	path, err := requireString(p, "path")
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	qFromString(q, "ref", getString(p, "ref"))
	return g.doRequest(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, escapeRepoPath(path)), q, nil)
}

func (g *Connector) opPutFile(ctx context.Context, p map[string]any) (any, error) {
	owner, err := requireString(p, "owner")
	if err != nil {
		return nil, err
	}
	repo, err := requireString(p, "repo")
	if err != nil {
		return nil, err
	}
	path, err := requireString(p, "path")
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"message": getString(p, "message"),
		"content": getString(p, "content"),
	}
	if v := getString(p, "branch"); v != "" {
		body["branch"] = v
	}
	if v := getString(p, "sha"); v != "" {
		body["sha"] = v
	}
	return g.doRequest(ctx, http.MethodPut, fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, escapeRepoPath(path)), nil, body)
}

func (g *Connector) opListIssues(ctx context.Context, p map[string]any) (any, error) {
	owner, err := requireString(p, "owner")
	if err != nil {
		return nil, err
	}
	repo, err := requireString(p, "repo")
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	qFromString(q, "state", getString(p, "state"))
	qFromString(q, "labels", getString(p, "labels"))
	qFromInt(q, "per_page", getInt(p, "per_page"))
	qFromInt(q, "page", getInt(p, "page"))
	return g.doRequest(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/issues", owner, repo), q, nil)
}

func (g *Connector) opCreateIssue(ctx context.Context, p map[string]any) (any, error) {
	owner, err := requireString(p, "owner")
	if err != nil {
		return nil, err
	}
	repo, err := requireString(p, "repo")
	if err != nil {
		return nil, err
	}
	title, err := requireString(p, "title")
	if err != nil {
		return nil, err
	}
	body := map[string]any{"title": title}
	if v := getString(p, "body"); v != "" {
		body["body"] = v
	}
	if v, ok := p["labels"]; ok {
		body["labels"] = v
	}
	if v, ok := p["assignees"]; ok {
		body["assignees"] = v
	}
	return g.doRequest(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/issues", owner, repo), nil, body)
}

func (g *Connector) opCommentIssue(ctx context.Context, p map[string]any) (any, error) {
	owner, err := requireString(p, "owner")
	if err != nil {
		return nil, err
	}
	repo, err := requireString(p, "repo")
	if err != nil {
		return nil, err
	}
	number := getInt(p, "number")
	if number <= 0 {
		return nil, fmt.Errorf("github: param %q required", "number")
	}
	body, err := requireString(p, "body")
	if err != nil {
		return nil, err
	}
	return g.doRequest(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/issues/%d/comments", owner, repo, number), nil,
		map[string]any{"body": body})
}

func (g *Connector) opListPRs(ctx context.Context, p map[string]any) (any, error) {
	owner, err := requireString(p, "owner")
	if err != nil {
		return nil, err
	}
	repo, err := requireString(p, "repo")
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	qFromString(q, "state", getString(p, "state"))
	qFromInt(q, "per_page", getInt(p, "per_page"))
	qFromInt(q, "page", getInt(p, "page"))
	return g.doRequest(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/pulls", owner, repo), q, nil)
}

func (g *Connector) opGetPR(ctx context.Context, p map[string]any) (any, error) {
	owner, err := requireString(p, "owner")
	if err != nil {
		return nil, err
	}
	repo, err := requireString(p, "repo")
	if err != nil {
		return nil, err
	}
	number := getInt(p, "number")
	if number <= 0 {
		return nil, fmt.Errorf("github: param %q required", "number")
	}
	return g.doRequest(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, number), nil, nil)
}

func (g *Connector) opCreatePR(ctx context.Context, p map[string]any) (any, error) {
	owner, err := requireString(p, "owner")
	if err != nil {
		return nil, err
	}
	repo, err := requireString(p, "repo")
	if err != nil {
		return nil, err
	}
	title, err := requireString(p, "title")
	if err != nil {
		return nil, err
	}
	head, err := requireString(p, "head")
	if err != nil {
		return nil, err
	}
	base, err := requireString(p, "base")
	if err != nil {
		return nil, err
	}
	body := map[string]any{"title": title, "head": head, "base": base}
	if v := getString(p, "body"); v != "" {
		body["body"] = v
	}
	if v, ok := p["draft"].(bool); ok {
		body["draft"] = v
	}
	return g.doRequest(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/pulls", owner, repo), nil, body)
}

func (g *Connector) opSearchCode(ctx context.Context, p map[string]any) (any, error) {
	q, err := requireString(p, "q")
	if err != nil {
		return nil, err
	}
	qv := url.Values{}
	qv.Set("q", q)
	qFromInt(qv, "per_page", getInt(p, "per_page"))
	qFromInt(qv, "page", getInt(p, "page"))
	return g.doRequest(ctx, http.MethodGet, "/search/code", qv, nil)
}
