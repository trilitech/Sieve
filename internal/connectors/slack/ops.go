package slack

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
)

// operations is the curated list per contracts/slack.md. Names match
// the contract verbatim; agents see them through MCP as
// `slack_<name>` (multi-connection token) or `<name>` (single-conn).
var operations = []connector.OperationDef{
	{
		Name:        "list_channels",
		Description: "List channels accessible to the bot.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"types":     {Type: "string", Description: "public_channel,private_channel,mpim,im (default public_channel,private_channel)"},
			"cursor":    {Type: "string", Description: "Pagination cursor from a previous response's next_cursor."},
			"page_size": {Type: "int", Description: "Page size 1-100 (default 100)."},
		},
	},
	{
		Name:        "list_users",
		Description: "List members of the workspace.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"cursor":    {Type: "string", Description: "Pagination cursor."},
			"page_size": {Type: "int", Description: "Page size 1-100 (default 100)."},
		},
	},
	{
		Name:        "read_user_profile",
		Description: "Get profile info for a user.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"user": {Type: "string", Description: "Slack user ID (Uxxxxx).", Required: true},
		},
	},
	{
		Name:        "read_channel_history",
		Description: "Read messages from a channel.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"channel":   {Type: "string", Description: "Channel ID (Cxxxxx).", Required: true},
			"cursor":    {Type: "string"},
			"page_size": {Type: "int"},
		},
	},
	{
		Name:        "read_thread",
		Description: "Read a thread of messages.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"channel": {Type: "string", Required: true},
			"ts":      {Type: "string", Description: "Thread parent ts.", Required: true},
		},
	},
	{
		Name:        "search_messages",
		Description: "Search messages across the workspace. Requires a user-token connection (auth_kind=user_token); bot-token connections return operation_not_enabled because Slack's search.messages only accepts user tokens.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"query":     {Type: "string", Description: "Slack search query, e.g. \"in:#general from:@alice deploy\".", Required: true},
			"cursor":    {Type: "string", Description: "Pagination cursor from a previous response's next_cursor."},
			"page_size": {Type: "int", Description: "Page size 1-100 (default 100)."},
		},
	},
	{
		Name:        "post_message",
		Description: "Post a message to a channel.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"channel": {Type: "string", Required: true},
			"text":    {Type: "string", Required: true},
		},
	},
}

// execute dispatches to the per-op implementation. Unknown operations
// return a clear error rather than panicking — the API and MCP layers
// turn that into a 4xx for the agent.
func (c *Connector) execute(ctx context.Context, op string, params map[string]any) (any, error) {
	switch op {
	case "list_channels":
		return c.opListChannels(ctx, params)
	case "list_users":
		return c.opListUsers(ctx, params)
	case "read_user_profile":
		return c.opReadUserProfile(ctx, params)
	case "read_channel_history":
		return c.opReadChannelHistory(ctx, params)
	case "read_thread":
		return c.opReadThread(ctx, params)
	case "search_messages":
		return c.opSearchMessages(ctx, params)
	case "post_message":
		return c.opPostMessage(ctx, params)
	default:
		return nil, fmt.Errorf("slack: unknown operation %q", op)
	}
}

// listValues builds the form for a paginated list_* call. Centralised
// so cursor + page_size translation lives in exactly one place.
func listValues(params map[string]any) url.Values {
	v := url.Values{}
	v.Set("limit", strconv.Itoa(pageSizeFrom(params)))
	if cur := cursorFrom(params); cur != "" {
		v.Set("cursor", cur)
	}
	return v
}

func (c *Connector) opListChannels(ctx context.Context, params map[string]any) (any, error) {
	v := listValues(params)
	if t, ok := params["types"].(string); ok && t != "" {
		v.Set("types", t)
	} else {
		v.Set("types", "public_channel,private_channel")
	}
	resp, err := c.client.post(ctx, "conversations.list", v)
	if err != nil {
		return nil, err
	}
	chans, _ := resp["channels"].([]any)
	return map[string]any{
		"items":       chans,
		"next_cursor": nextCursorFrom(resp),
	}, nil
}

func (c *Connector) opListUsers(ctx context.Context, params map[string]any) (any, error) {
	resp, err := c.client.post(ctx, "users.list", listValues(params))
	if err != nil {
		return nil, err
	}
	members, _ := resp["members"].([]any)
	return map[string]any{
		"items":       members,
		"next_cursor": nextCursorFrom(resp),
	}, nil
}

func (c *Connector) opReadUserProfile(ctx context.Context, params map[string]any) (any, error) {
	user, _ := params["user"].(string)
	if user == "" {
		return nil, fmt.Errorf("slack: read_user_profile requires user")
	}
	v := url.Values{}
	v.Set("user", user)
	resp, err := c.client.post(ctx, "users.profile.get", v)
	if err != nil {
		return nil, err
	}
	return resp["profile"], nil
}

func (c *Connector) opReadChannelHistory(ctx context.Context, params map[string]any) (any, error) {
	channel, _ := params["channel"].(string)
	if channel == "" {
		return nil, fmt.Errorf("slack: read_channel_history requires channel")
	}
	v := listValues(params)
	v.Set("channel", channel)
	resp, err := c.client.post(ctx, "conversations.history", v)
	if err != nil {
		return nil, err
	}
	msgs, _ := resp["messages"].([]any)
	return map[string]any{
		"items":       msgs,
		"next_cursor": nextCursorFrom(resp),
	}, nil
}

func (c *Connector) opReadThread(ctx context.Context, params map[string]any) (any, error) {
	channel, _ := params["channel"].(string)
	ts, _ := params["ts"].(string)
	if channel == "" || ts == "" {
		return nil, fmt.Errorf("slack: read_thread requires channel and ts")
	}
	v := listValues(params)
	v.Set("channel", channel)
	v.Set("ts", ts)
	resp, err := c.client.post(ctx, "conversations.replies", v)
	if err != nil {
		return nil, err
	}
	msgs, _ := resp["messages"].([]any)
	return map[string]any{
		"items":       msgs,
		"next_cursor": nextCursorFrom(resp),
	}, nil
}

// opSearchMessages runs Slack's search.messages — but ONLY for
// connections that authenticate as a user (auth_kind=user_token). Slack's
// search.messages API rejects bot tokens (not_allowed_token_type), so for
// bot-identity connections we short-circuit with the typed
// connector.ErrOperationNotEnabled sentinel. The API layer maps that to
// HTTP 501 and the MCP layer to a tool-error result, so agent SDKs branch
// on the status code / prefix without inspecting response bodies.
//
// The operation is exposed for every Slack connection (not just user-token
// ones) so the operation surface stays stable and policies that mention
// `search_messages` keep binding regardless of how a given connection
// authenticates.
//
// Pagination: search.messages is page-numbered, not cursor-based, so we
// translate the normalized cursor to/from a 1-based page index. The first
// call omits cursor (page 1); next_cursor is the next page number as a
// decimal string, empty once the last page is reached.
func (c *Connector) opSearchMessages(ctx context.Context, params map[string]any) (any, error) {
	if c.cfg.AuthKind != KindUserToken {
		return nil, fmt.Errorf("%w: slack search.messages requires a user-token connection (auth_kind=user_token); this connection authenticates as a bot", connector.ErrOperationNotEnabled)
	}
	query, _ := params["query"].(string)
	if query == "" {
		return nil, fmt.Errorf("slack: search_messages requires query")
	}
	v := url.Values{}
	v.Set("query", query)
	v.Set("count", strconv.Itoa(pageSizeFrom(params)))
	page := 1
	if cur := cursorFrom(params); cur != "" {
		if n, err := strconv.Atoi(cur); err == nil && n > 0 {
			page = n
		}
	}
	v.Set("page", strconv.Itoa(page))

	resp, err := c.client.get(ctx, "search.messages", v)
	if err != nil {
		return nil, err
	}
	messages, _ := resp["messages"].(map[string]any)
	matches, _ := messages["matches"].([]any)
	return map[string]any{
		"items":       matches,
		"next_cursor": searchNextCursor(messages, page),
	}, nil
}

// searchNextCursor derives the normalized next_cursor for a
// search.messages response. search.messages reports paging as
// {paging: {page, pages}}; the next cursor is the next page number when
// more pages remain, else "".
func searchNextCursor(messages map[string]any, page int) string {
	paging, ok := messages["paging"].(map[string]any)
	if !ok {
		return ""
	}
	pages := 0
	switch p := paging["pages"].(type) {
	case float64:
		pages = int(p)
	case int:
		pages = p
	}
	if page < pages {
		return strconv.Itoa(page + 1)
	}
	return ""
}

func (c *Connector) opPostMessage(ctx context.Context, params map[string]any) (any, error) {
	channel, _ := params["channel"].(string)
	text, _ := params["text"].(string)
	if channel == "" || text == "" {
		return nil, fmt.Errorf("slack: post_message requires channel and text")
	}
	// Tolerate "#general" / "general" / "C012345" — Slack's
	// chat.postMessage accepts any of the three. Strip a leading "#"
	// so the agent doesn't have to think about it.
	channel = strings.TrimPrefix(channel, "#")

	v := url.Values{}
	v.Set("channel", channel)
	v.Set("text", text)
	resp, err := c.client.post(ctx, "chat.postMessage", v)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
