package gmail

import (
	"strings"
	"testing"
)

// hasHeader reports whether raw carries a header line starting with name.
// A plain substring check is wrong here: "Reply-To:" is a substring of
// "In-Reply-To:", which is exactly the confusion this file is about.
func hasHeader(raw, name string) bool {
	return strings.HasPrefix(raw, name+":") || strings.Contains(raw, "\r\n"+name+":")
}

// TestBuildMIMEMessage_ReplyToHeader: reply_to_address sets a real RFC 5322
// Reply-To header. Previously there was no way to set one at all.
func TestBuildMIMEMessage_ReplyToHeader(t *testing.T) {
	raw, err := buildMIMEMessage(DraftRequest{
		To:               []string{"a@example.com"},
		Subject:          "s",
		Body:             "b",
		ReplyToAddresses: []string{"replies@example.com", "Team <team@example.com>"},
	})
	if err != nil {
		t.Fatalf("buildMIMEMessage: %v", err)
	}
	got := string(raw)
	if !strings.Contains(got, "Reply-To: replies@example.com, Team <team@example.com>\r\n") {
		t.Errorf("missing/incorrect Reply-To header\n--- got ---\n%s", got)
	}
}

// TestBuildMIMEMessage_ReplyToIsNotThreading: the Reply-To header and the
// legacy threading alias are independent — setting an address must not produce
// an In-Reply-To, and threading must not produce a Reply-To.
func TestBuildMIMEMessage_ReplyToIsNotThreading(t *testing.T) {
	addrOnly, _ := buildMIMEMessage(DraftRequest{
		To: []string{"a@example.com"}, Body: "b",
		ReplyToAddresses: []string{"replies@example.com"},
	})
	if hasHeader(string(addrOnly), "In-Reply-To") {
		t.Errorf("reply_to_address must not emit In-Reply-To\n%s", addrOnly)
	}
	threadOnly, _ := buildMIMEMessage(DraftRequest{
		To: []string{"a@example.com"}, Body: "b",
		InReplyTo: "<parent@mail.example.com>",
	})
	if hasHeader(string(threadOnly), "Reply-To") {
		t.Errorf("threading must not emit Reply-To\n%s", threadOnly)
	}
}

// TestBuildMIMEMessage_NoReplyToByDefault pins that ordinary messages are
// byte-identical to before (no stray header).
func TestBuildMIMEMessage_NoReplyToByDefault(t *testing.T) {
	raw, _ := buildMIMEMessage(DraftRequest{To: []string{"a@example.com"}, Subject: "s", Body: "b"})
	if hasHeader(string(raw), "Reply-To") {
		t.Errorf("unexpected Reply-To header: %s", raw)
	}
}
