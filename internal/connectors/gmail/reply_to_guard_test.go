package gmail

import (
	"context"
	"strings"
	"testing"
)

// TestCheckLegacyReplyTo covers the reported footgun: `reply_to` is the
// deprecated THREADING alias (a Gmail message id), so an email address there
// produced a 200 with a fabricated In-Reply-To and no Reply-To header.
func TestCheckLegacyReplyTo(t *testing.T) {
	rejected := []string{
		"someone@example.com",
		"  someone@example.com  ",
		"Name <someone@example.com>",
	}
	for _, v := range rejected {
		err := checkLegacyReplyTo(map[string]any{"reply_to": v})
		if err == nil {
			t.Errorf("reply_to=%q should be rejected (it is an address, not a message id)", v)
			continue
		}
		// The error must name both fields the caller might have meant.
		for _, want := range []string{"reply_to_address", "in_reply_to_message_id"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("reply_to=%q: error should mention %q; got %v", v, want, err)
			}
		}
	}

	accepted := []string{
		"",                     // absent
		"1a1397bf2659b67c",     // a real Gmail message id (legacy use)
		"<abc@mail.gmail.com>", // a bracketed RFC 5322 Message-ID
	}
	for _, v := range accepted {
		if err := checkLegacyReplyTo(map[string]any{"reply_to": v}); err != nil {
			t.Errorf("reply_to=%q should be accepted, got %v", v, err)
		}
	}
}

// TestExecute_RejectsReplyToAddressMisuse pins that the guard runs on the
// dispatch path (so REST, MCP and generic ops all get it), and that it fires
// before any network call.
func TestExecute_RejectsReplyToAddressMisuse(t *testing.T) {
	g := &GoogleConnector{} // no client: a passing guard would nil-panic, a failing one returns
	_, err := g.Execute(context.Background(), "create_draft", map[string]any{
		"to":       []any{"x@example.com"},
		"body":     "hi",
		"reply_to": "someone@example.com",
	})
	if err == nil || !strings.Contains(err.Error(), "reply_to_address") {
		t.Fatalf("Execute should reject the misuse before dispatch; got %v", err)
	}
}
