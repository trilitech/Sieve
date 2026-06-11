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
//
// Param Type values use the extended vocabulary supported by
// internal/mcp/server.go::buildInputSchema — `object` and `[]object` for
// the structured Messages API shapes that don't reduce to scalars or
// arrays of strings, `float` for the sampling knobs, and `int` for
// integer counts. The MCP schema layer renders these into the correct
// JSON Schema types so agent tool catalogs reflect what Anthropic
// actually expects on the wire.
var operations = []connector.OperationDef{
	{
		Name:        "messages_create",
		Description: "Create a message via Anthropic's /v1/messages endpoint. Non-streaming. Accepts the standard Messages API params (model, messages, max_tokens, system, temperature, tools, etc.) and returns the API response verbatim.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"model":          {Type: "string", Description: "Model identifier (e.g. claude-sonnet-4-5).", Required: true},
			"messages":       {Type: "[]object", Description: "Conversation messages: array of {role, content} objects per the Messages API.", Required: true},
			"max_tokens":     {Type: "int", Description: "Maximum tokens to generate (required by Anthropic API; must be > 0).", Required: true},
			"system":         {Type: "string", Description: "System prompt.", Required: false},
			"temperature":    {Type: "float", Description: "Sampling temperature (0 to 1).", Required: false},
			"top_p":          {Type: "float", Description: "Nucleus sampling top-p (0 to 1).", Required: false},
			"top_k":          {Type: "int", Description: "Top-k sampling.", Required: false},
			"stop_sequences": {Type: "[]string", Description: "Custom stop sequences.", Required: false},
			"metadata":       {Type: "object", Description: "Anthropic metadata object (e.g. {\"user_id\": \"...\"}).", Required: false},
			"tools":          {Type: "[]object", Description: "Tool definitions for tool-use flows: array of {name, description, input_schema}.", Required: false},
			"tool_choice":    {Type: "object", Description: "Tool choice strategy, e.g. {\"type\":\"auto\"}.", Required: false},
			"max_cost":       {Type: "float", Description: "Caller-declared cost budget for policy enforcement (not forwarded to Anthropic).", Required: false},
		},
	},
	{
		Name:        "messages_count_tokens",
		Description: "Count input tokens for a Messages API request without generating any output. Useful for pre-flight cost estimation. Same shape as messages_create minus max_tokens.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"model":       {Type: "string", Description: "Model identifier.", Required: true},
			"messages":    {Type: "[]object", Description: "Conversation messages: array of {role, content} objects.", Required: true},
			"system":      {Type: "string", Description: "System prompt.", Required: false},
			"tools":       {Type: "[]object", Description: "Tool definitions for tool-use flows.", Required: false},
			"tool_choice": {Type: "object", Description: "Tool choice strategy.", Required: false},
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
// that shouldn't be forwarded (max_cost is for policy gating only;
// stream is stripped since this op is non-streaming by definition),
// and POSTs to /v1/messages.
func (a *Connector) executeMessagesCreate(ctx context.Context, params map[string]any) (any, error) {
	for _, req := range []string{"model", "messages", "max_tokens"} {
		if err := ensureNonEmpty(params, req); err != nil {
			return nil, err
		}
	}
	// stream: true is a policy error — streaming has its own (not-yet-
	// implemented) operation. Refuse loudly rather than silently
	// changing the response shape under callers. stream=false / stream
	// unset is fine and gets stripped by sanitizeForAnthropic so the
	// outbound body shape is consistent.
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
// fields and the stream flag stripped so they don't leak into the
// upstream request body.
//
//   - max_cost is policy-gating only and means nothing to Anthropic.
//   - stream is stripped unconditionally on this connector: the op is
//     non-streaming by contract, stream=true is rejected upstream of
//     this helper, and stream=false is meaningless noise — dropping it
//     keeps the outbound body shape deterministic regardless of caller
//     habits.
func sanitizeForAnthropic(params map[string]any) map[string]any {
	out := make(map[string]any, len(params))
	for k, v := range params {
		switch k {
		case "max_cost", "stream":
			continue
		}
		out[k] = v
	}
	return out
}
