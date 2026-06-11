package anthropic

import (
	"context"
	"fmt"

	"github.com/trilitech/Sieve/internal/connector"
)

// operations is the v1 catalog. messages_create and messages_count_tokens
// cover the primary policy-binding surface today; streaming and batches
// are tracked separately and will add operations to this list when they
// land.
var operations = []connector.OperationDef{
	{
		Name:        "messages_create",
		Description: "Create a message via Anthropic's /v1/messages endpoint. Non-streaming. Accepts the standard Messages API params (model, messages, max_tokens, system, temperature, tools, etc.) and returns the API response verbatim.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"model":          {Type: "string", Description: "Model identifier (e.g. claude-sonnet-4-5).", Required: true},
			"messages":       {Type: "[]string", Description: "Conversation messages as Anthropic Messages API shapes.", Required: true},
			"max_tokens":     {Type: "int", Description: "Maximum tokens to generate (required by Anthropic API).", Required: true},
			"system":         {Type: "string", Description: "System prompt.", Required: false},
			"temperature":    {Type: "string", Description: "Sampling temperature (0 to 1).", Required: false},
			"top_p":          {Type: "string", Description: "Nucleus sampling top-p.", Required: false},
			"top_k":          {Type: "int", Description: "Top-k sampling.", Required: false},
			"stop_sequences": {Type: "[]string", Description: "Custom stop sequences.", Required: false},
			"metadata":       {Type: "string", Description: "Anthropic metadata object (e.g. {\"user_id\":...}).", Required: false},
			"tools":          {Type: "[]string", Description: "Tool definitions for tool-use flows.", Required: false},
			"tool_choice":    {Type: "string", Description: "Tool choice strategy.", Required: false},
			"max_cost":       {Type: "string", Description: "Caller-declared cost budget for policy enforcement (not forwarded to Anthropic).", Required: false},
		},
	},
	{
		Name:        "messages_count_tokens",
		Description: "Count input tokens for a Messages API request without generating any output. Useful for pre-flight cost estimation. Same params as messages_create except max_tokens is not required.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"model":       {Type: "string", Description: "Model identifier.", Required: true},
			"messages":    {Type: "[]string", Description: "Conversation messages.", Required: true},
			"system":      {Type: "string", Description: "System prompt.", Required: false},
			"tools":       {Type: "[]string", Description: "Tool definitions.", Required: false},
			"tool_choice": {Type: "string", Description: "Tool choice strategy.", Required: false},
		},
	},
}

// Execute dispatches an operation to the corresponding Anthropic endpoint.
// Unknown ops return an explicit error so the API/MCP layers can surface
// a clean "not supported" message instead of a 500.
func (a *Connector) Execute(ctx context.Context, op string, params map[string]any) (any, error) {
	switch op {
	case "messages_create":
		return a.executeMessagesCreate(ctx, params)
	case "messages_count_tokens":
		return a.executeMessagesCountTokens(ctx, params)
	default:
		return nil, fmt.Errorf("anthropic: unknown operation %q", op)
	}
}

// executeMessagesCreate enforces the Anthropic API's required-field
// contract (model, messages, max_tokens), strips Sieve-internal fields
// that shouldn't be forwarded (max_cost is for policy gating only),
// and POSTs to /v1/messages.
func (a *Connector) executeMessagesCreate(ctx context.Context, params map[string]any) (any, error) {
	for _, req := range []string{"model", "messages", "max_tokens"} {
		if err := ensureNonEmpty(params, req); err != nil {
			return nil, err
		}
	}
	// stream: true on this op is a policy error — streaming has its own
	// operation. Refuse loudly rather than silently changing the response
	// shape under callers.
	if v, ok := params["stream"]; ok {
		if b, ok := v.(bool); ok && b {
			return nil, fmt.Errorf("anthropic: messages_create does not support stream=true; use messages_create_streaming when available")
		}
	}
	return a.doRequest(ctx, "POST", "/v1/messages", sanitizeForAnthropic(params))
}

// executeMessagesCountTokens validates required fields and POSTs to
// /v1/messages/count_tokens.
func (a *Connector) executeMessagesCountTokens(ctx context.Context, params map[string]any) (any, error) {
	for _, req := range []string{"model", "messages"} {
		if err := ensureNonEmpty(params, req); err != nil {
			return nil, err
		}
	}
	return a.doRequest(ctx, "POST", "/v1/messages/count_tokens", sanitizeForAnthropic(params))
}

// sanitizeForAnthropic returns a copy of params with Sieve-internal
// fields stripped so they don't leak into the upstream request body.
// max_cost is the only one today (used for policy gating, meaningless
// to Anthropic), but isolating this in a helper keeps the list visible.
func sanitizeForAnthropic(params map[string]any) map[string]any {
	out := make(map[string]any, len(params))
	for k, v := range params {
		switch k {
		case "max_cost":
			// Policy-only field; never forwarded.
			continue
		}
		out[k] = v
	}
	return out
}
