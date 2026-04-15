package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractDecisionFromText(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		action string
		err    bool
	}{
		{"clean json", `{"action": "allow", "reason": "looks good"}`, "allow", false},
		{"json in text", `I think this is fine. {"action": "deny", "reason": "blocked"} That's my answer.`, "deny", false},
		{"no json", `Just some random text`, "", true},
		{"missing action", `{"reason": "no action here"}`, "", true},
		{"nested braces", `Here: {"action": "allow", "meta": {"x": 1}}`, "allow", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec, err := extractDecisionFromText(tt.text)
			if tt.err {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dec.Action != tt.action {
				t.Fatalf("expected action %q, got %q", tt.action, dec.Action)
			}
		})
	}
}

func TestLLMEvaluatorAnthropic(t *testing.T) {
	// Mock Anthropic API.
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("anthropic-version") == "" {
			http.Error(w, "missing anthropic-version", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]string{
				{"type": "text", "text": `Based on the request, {"action": "allow", "reason": "operation is safe"}`},
			},
		})
	}))
	defer mock.Close()

	eval, err := NewLLMEvaluator(map[string]any{
		"provider": "anthropic",
		"model":    "test-model",
		"prompt":   "Evaluate this: {{request_json}}",
	}, map[string]LLMProviderConfig{
		"anthropic": {Endpoint: mock.URL, Model: "test-model"},
	})
	if err != nil {
		t.Fatalf("create evaluator: %v", err)
	}

	dec, err := eval.Evaluate(context.Background(), &PolicyRequest{
		Operation: "send_email",
		Params:    map[string]any{"to": "test@test.com"},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if dec.Action != "allow" {
		t.Fatalf("expected allow, got %s", dec.Action)
	}
}

func TestLLMEvaluatorOpenAI(t *testing.T) {
	// Mock OpenAI API.
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": `{"action": "deny", "reason": "too risky"}`}},
			},
		})
	}))
	defer mock.Close()

	eval, err := NewLLMEvaluator(map[string]any{
		"provider": "openai",
		"model":    "test-model",
		"prompt":   "Evaluate this: {{request_json}}",
	}, map[string]LLMProviderConfig{
		"openai": {Endpoint: mock.URL, Model: "test-model"},
	})
	if err != nil {
		t.Fatalf("create evaluator: %v", err)
	}

	dec, err := eval.Evaluate(context.Background(), &PolicyRequest{
		Operation: "list_emails",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if dec.Action != "deny" {
		t.Fatalf("expected deny, got %s", dec.Action)
	}
	if dec.Reason != "too risky" {
		t.Fatalf("expected reason 'too risky', got %q", dec.Reason)
	}
}

func TestLLMEvaluatorFallbackOnError(t *testing.T) {
	// Mock that returns 500.
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", 500)
	}))
	defer mock.Close()

	eval, err := NewLLMEvaluator(map[string]any{
		"provider": "anthropic",
		"prompt":   "Evaluate: {{request_json}}",
	}, map[string]LLMProviderConfig{
		"anthropic": {Endpoint: mock.URL},
	})
	if err != nil {
		t.Fatalf("create evaluator: %v", err)
	}

	dec, err := eval.Evaluate(context.Background(), &PolicyRequest{Operation: "test"})
	if err != nil {
		t.Fatalf("should not error, should fallback: %v", err)
	}
	// Fallback is always "deny" (fail-closed).
	if dec.Action != "deny" {
		t.Fatalf("expected deny fallback, got %s", dec.Action)
	}
}

func TestLLMEvaluatorMissingProvider(t *testing.T) {
	_, err := NewLLMEvaluator(map[string]any{
		"prompt": "test",
	}, nil)
	if err == nil {
		t.Fatal("expected error for missing provider")
	}
}

func TestLLMEvaluatorMissingPrompt(t *testing.T) {
	_, err := NewLLMEvaluator(map[string]any{
		"provider": "anthropic",
	}, nil)
	if err == nil {
		t.Fatal("expected error for missing prompt")
	}
}
