package notion

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
// IAM taxonomy. notion_request appears first so the escape hatch is prominent.
//
// Rich request bodies (page properties, block children, database-query
// filters, comment rich_text) are declared as JSON-STRING params: the ParamDef
// type system is scalar-only, and this mirrors gitlab_request's `body`. Each
// such param is validated as JSON and forwarded byte-exact.
var operations = []connector.OperationDef{
	{
		Name:        "notion_request",
		Description: "Send a raw Notion API request. Path must start with '/' (relative to /v1, e.g. /search). Body is a JSON string.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"method": {Type: "string", Required: true, Description: "HTTP method (GET, POST, PATCH, DELETE). Case-insensitive."},
			"path":   {Type: "string", Required: true, Description: "API path beginning with '/' (relative to /v1)."},
			"query":  {Type: "string", Required: false, Description: "Query string without leading '?'."},
			"body":   {Type: "string", Required: false, Description: "JSON request body, as a string."},
		},
	},
	{
		Name:        "notion_search",
		Description: "Search pages and databases shared with the integration.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"query":        {Type: "string", Required: false, Description: "Free-text query over titles. Empty returns everything shared with the integration."},
			"filter":       {Type: "string", Required: false, Description: `Restrict object type: "page" or "database".`},
			"page_size":    {Type: "int", Required: false, Description: "1-100 (Notion default 100)."},
			"start_cursor": {Type: "string", Required: false, Description: "Pagination cursor from a prior response's next_cursor."},
		},
	},
	{
		Name:        "notion_get_page",
		Description: "Retrieve a page's properties by id.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"page_id": {Type: "string", Required: true, Description: "Notion page id (UUID)."},
		},
	},
	{
		Name:        "notion_create_page",
		Description: "Create a page under a parent page or database.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"parent":     {Type: "string", Required: true, Description: `JSON parent object, e.g. {"database_id":"..."} or {"page_id":"..."}.`},
			"properties": {Type: "string", Required: true, Description: "JSON properties object matching the parent database schema (or {\"title\":...} for a page parent)."},
			"children":   {Type: "string", Required: false, Description: "JSON array of block objects for the page body."},
		},
	},
	{
		Name:        "notion_update_page",
		Description: "Update a page's properties or archive/restore it.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"page_id":    {Type: "string", Required: true, Description: "Notion page id (UUID)."},
			"properties": {Type: "string", Required: false, Description: "JSON properties object to update."},
			"archived":   {Type: "bool", Required: false, Description: "true to archive (move to trash), false to restore."},
		},
	},
	{
		Name:        "notion_get_block_children",
		Description: "List the child blocks of a page or block (its content).",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"block_id":     {Type: "string", Required: true, Description: "Parent block or page id (UUID)."},
			"page_size":    {Type: "int", Required: false},
			"start_cursor": {Type: "string", Required: false},
		},
	},
	{
		Name:        "notion_append_block_children",
		Description: "Append blocks to a page or block's content.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"block_id": {Type: "string", Required: true, Description: "Parent block or page id (UUID)."},
			"children": {Type: "string", Required: true, Description: "JSON array of block objects to append."},
			"after":    {Type: "string", Required: false, Description: "Existing block id to append after."},
		},
	},
	{
		Name:        "notion_query_database",
		Description: "Query a database's rows (pages) with optional filter and sorts.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"database_id":  {Type: "string", Required: true, Description: "Notion database id (UUID)."},
			"filter":       {Type: "string", Required: false, Description: "JSON filter object (Notion database filter syntax)."},
			"sorts":        {Type: "string", Required: false, Description: "JSON array of sort objects."},
			"page_size":    {Type: "int", Required: false},
			"start_cursor": {Type: "string", Required: false},
		},
	},
	{
		Name:        "notion_get_database",
		Description: "Retrieve a database's schema and metadata by id.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"database_id": {Type: "string", Required: true, Description: "Notion database id (UUID)."},
		},
	},
	{
		Name:        "notion_list_users",
		Description: "List all users in the workspace.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"page_size":    {Type: "int", Required: false},
			"start_cursor": {Type: "string", Required: false},
		},
	},
	{
		Name:        "notion_get_comments",
		Description: "List unresolved comments on a page or block.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"block_id":     {Type: "string", Required: true, Description: "Page or block id (UUID) to read comments from."},
			"page_size":    {Type: "int", Required: false},
			"start_cursor": {Type: "string", Required: false},
		},
	},
	{
		Name:        "notion_create_comment",
		Description: "Add a comment to a page or an existing discussion thread.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"parent":        {Type: "string", Required: false, Description: `JSON parent object, e.g. {"page_id":"..."}. Provide this OR discussion_id.`},
			"discussion_id": {Type: "string", Required: false, Description: "Existing discussion thread id (alternative to parent)."},
			"rich_text":     {Type: "string", Required: true, Description: "JSON array of rich text objects (the comment body)."},
		},
	},
}

// --- body/query helpers ---

// jsonField reads a JSON-string param and returns it as json.RawMessage so it
// is forwarded byte-exact (preserving key order, large integers, and null).
// present is false when the param is absent/empty.
func jsonField(p map[string]any, key string) (raw json.RawMessage, present bool, err error) {
	s := getString(p, key)
	if strings.TrimSpace(s) == "" {
		return nil, false, nil
	}
	if !json.Valid([]byte(s)) {
		return nil, false, fmt.Errorf("notion: param %q is not valid JSON", key)
	}
	return json.RawMessage(s), true, nil
}

// pagingQuery builds the common page_size / start_cursor query params.
func pagingQuery(p map[string]any) url.Values {
	q := url.Values{}
	if n, ok := getIntPresent(p, "page_size"); ok {
		q.Set("page_size", strconv.Itoa(n))
	}
	if c := getString(p, "start_cursor"); c != "" {
		q.Set("start_cursor", c)
	}
	return q
}

// idPath builds a '/'-prefixed path with a single percent-encoded id segment.
func idPath(prefix, id, suffix string) string {
	return prefix + url.PathEscape(id) + suffix
}

// --- operation handlers ---

func (n *Connector) opRequest(ctx context.Context, params map[string]any) (any, error) {
	method, err := requireString(params, "method")
	if err != nil {
		return nil, err
	}
	method = strings.ToUpper(method)
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
	default:
		return nil, fmt.Errorf("notion: unsupported method %q", method)
	}

	path, err := requireString(params, "path")
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("notion: path must start with '/', got %q", path)
	}
	// Agents reading the Notion docs naturally type "/v1/pages"; doRequest
	// prepends apiPrefix unconditionally, which would produce "/v1/v1/pages".
	// Normalize so both conventions work; reject the bare prefix.
	if path == apiPrefix || path == apiPrefix+"/" {
		return nil, fmt.Errorf("notion: path %q is just the API prefix; supply an endpoint path after it", path)
	}
	if strings.HasPrefix(path, apiPrefix+"/") {
		path = strings.TrimPrefix(path, apiPrefix)
	}

	var q url.Values
	if qs := getString(params, "query"); qs != "" {
		parsed, perr := url.ParseQuery(qs)
		if perr != nil {
			return nil, fmt.Errorf("notion: parse query: %w", perr)
		}
		q = parsed
	}

	var body any
	if raw, present, jerr := jsonField(params, "body"); jerr != nil {
		return nil, jerr
	} else if present {
		body = raw
	}

	return n.doRequest(ctx, method, path, q, body)
}

func (n *Connector) opSearch(ctx context.Context, params map[string]any) (any, error) {
	body := map[string]any{}
	if q := getString(params, "query"); q != "" {
		body["query"] = q
	}
	if f := strings.TrimSpace(getString(params, "filter")); f != "" {
		if f != "page" && f != "database" {
			return nil, fmt.Errorf(`notion: filter must be "page" or "database", got %q`, f)
		}
		body["filter"] = map[string]any{"property": "object", "value": f}
	}
	if n2, ok := getIntPresent(params, "page_size"); ok {
		body["page_size"] = n2
	}
	if c := getString(params, "start_cursor"); c != "" {
		body["start_cursor"] = c
	}
	return n.doRequest(ctx, http.MethodPost, "/search", nil, body)
}

func (n *Connector) opGetPage(ctx context.Context, params map[string]any) (any, error) {
	id, err := requireString(params, "page_id")
	if err != nil {
		return nil, err
	}
	return n.doRequest(ctx, http.MethodGet, idPath("/pages/", id, ""), nil, nil)
}

func (n *Connector) opCreatePage(ctx context.Context, params map[string]any) (any, error) {
	parent, present, err := jsonField(params, "parent")
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, fmt.Errorf("notion: param %q required", "parent")
	}
	props, present, err := jsonField(params, "properties")
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, fmt.Errorf("notion: param %q required", "properties")
	}
	body := map[string]any{"parent": parent, "properties": props}
	if children, ok, cerr := jsonField(params, "children"); cerr != nil {
		return nil, cerr
	} else if ok {
		body["children"] = children
	}
	return n.doRequest(ctx, http.MethodPost, "/pages", nil, body)
}

func (n *Connector) opUpdatePage(ctx context.Context, params map[string]any) (any, error) {
	id, err := requireString(params, "page_id")
	if err != nil {
		return nil, err
	}
	body := map[string]any{}
	if props, ok, perr := jsonField(params, "properties"); perr != nil {
		return nil, perr
	} else if ok {
		body["properties"] = props
	}
	if v, ok := params["archived"].(bool); ok {
		body["archived"] = v
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("notion: notion_update_page needs at least one of properties/archived")
	}
	return n.doRequest(ctx, http.MethodPatch, idPath("/pages/", id, ""), nil, body)
}

func (n *Connector) opGetBlockChildren(ctx context.Context, params map[string]any) (any, error) {
	id, err := requireString(params, "block_id")
	if err != nil {
		return nil, err
	}
	return n.doRequest(ctx, http.MethodGet, idPath("/blocks/", id, "/children"), pagingQuery(params), nil)
}

func (n *Connector) opAppendBlockChildren(ctx context.Context, params map[string]any) (any, error) {
	id, err := requireString(params, "block_id")
	if err != nil {
		return nil, err
	}
	children, present, err := jsonField(params, "children")
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, fmt.Errorf("notion: param %q required", "children")
	}
	body := map[string]any{"children": children}
	if after := getString(params, "after"); after != "" {
		body["after"] = after
	}
	return n.doRequest(ctx, http.MethodPatch, idPath("/blocks/", id, "/children"), nil, body)
}

func (n *Connector) opQueryDatabase(ctx context.Context, params map[string]any) (any, error) {
	id, err := requireString(params, "database_id")
	if err != nil {
		return nil, err
	}
	body := map[string]any{}
	if filter, ok, ferr := jsonField(params, "filter"); ferr != nil {
		return nil, ferr
	} else if ok {
		body["filter"] = filter
	}
	if sorts, ok, serr := jsonField(params, "sorts"); serr != nil {
		return nil, serr
	} else if ok {
		body["sorts"] = sorts
	}
	if size, ok := getIntPresent(params, "page_size"); ok {
		body["page_size"] = size
	}
	if c := getString(params, "start_cursor"); c != "" {
		body["start_cursor"] = c
	}
	return n.doRequest(ctx, http.MethodPost, idPath("/databases/", id, "/query"), nil, body)
}

func (n *Connector) opGetDatabase(ctx context.Context, params map[string]any) (any, error) {
	id, err := requireString(params, "database_id")
	if err != nil {
		return nil, err
	}
	return n.doRequest(ctx, http.MethodGet, idPath("/databases/", id, ""), nil, nil)
}

func (n *Connector) opListUsers(ctx context.Context, params map[string]any) (any, error) {
	return n.doRequest(ctx, http.MethodGet, "/users", pagingQuery(params), nil)
}

func (n *Connector) opGetComments(ctx context.Context, params map[string]any) (any, error) {
	id, err := requireString(params, "block_id")
	if err != nil {
		return nil, err
	}
	q := pagingQuery(params)
	q.Set("block_id", id)
	return n.doRequest(ctx, http.MethodGet, "/comments", q, nil)
}

func (n *Connector) opCreateComment(ctx context.Context, params map[string]any) (any, error) {
	richText, present, err := jsonField(params, "rich_text")
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, fmt.Errorf("notion: param %q required", "rich_text")
	}
	body := map[string]any{"rich_text": richText}
	parent, parentOK, err := jsonField(params, "parent")
	if err != nil {
		return nil, err
	}
	discussionID := getString(params, "discussion_id")
	switch {
	case parentOK && discussionID != "":
		return nil, fmt.Errorf("notion: provide exactly one of parent / discussion_id")
	case parentOK:
		body["parent"] = parent
	case discussionID != "":
		body["discussion_id"] = discussionID
	default:
		return nil, fmt.Errorf("notion: notion_create_comment needs parent or discussion_id")
	}
	return n.doRequest(ctx, http.MethodPost, "/comments", nil, body)
}
