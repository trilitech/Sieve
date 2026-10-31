package gmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	gmailapi "google.golang.org/api/gmail/v1"
)

// TestCreateDraft_BodyHTML is the reported bug: body_html was declared nowhere
// and never read, so the generic ops route accepted it with a 200 and stored a
// plain-text draft. The draft must now be multipart/alternative carrying BOTH
// the plain and the HTML part.
func TestCreateDraft_BodyHTML(t *testing.T) {
	var captured gmailapi.Draft
	g := newConnectorWithMock(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/drafts") {
			_ = json.NewDecoder(r.Body).Decode(&captured)
			_ = json.NewEncoder(w).Encode(&gmailapi.Draft{
				Id: "d1", Message: &gmailapi.Message{Id: "m1", ThreadId: "t1"},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(&gmailapi.Message{Id: "m1", ThreadId: "t1"})
	})

	const htmlBody = `<p>hi <span style="background-color:#fff176">highlighted</span></p>`
	if _, err := g.Execute(context.Background(), "create_draft", map[string]any{
		"to":        []any{"x@example.com"},
		"subject":   "html test",
		"body":      "plain fallback",
		"body_html": htmlBody,
	}); err != nil {
		t.Fatalf("Execute create_draft: %v", err)
	}
	if captured.Message == nil {
		t.Fatal("no draft captured")
	}
	raw, err := base64.URLEncoding.DecodeString(captured.Message.Raw)
	if err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	mime := string(raw)

	if !strings.Contains(mime, "multipart/alternative") {
		t.Errorf("draft is not multipart/alternative — HTML was dropped\n--- got ---\n%s", mime)
	}
	if !strings.Contains(mime, "text/html") {
		t.Errorf("no text/html part\n%s", mime)
	}
	if !strings.Contains(mime, htmlBody) {
		t.Errorf("HTML body not carried verbatim (markup is the whole point)\n%s", mime)
	}
	if !strings.Contains(mime, "plain fallback") {
		t.Errorf("plain-text alternative lost\n%s", mime)
	}
}

// TestCreateDraft_NoBodyHTMLStaysPlain pins that an ordinary draft is still a
// bare text/plain message (no gratuitous multipart).
func TestCreateDraft_NoBodyHTMLStaysPlain(t *testing.T) {
	var captured gmailapi.Draft
	g := newConnectorWithMock(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/drafts") {
			_ = json.NewDecoder(r.Body).Decode(&captured)
			_ = json.NewEncoder(w).Encode(&gmailapi.Draft{Id: "d1", Message: &gmailapi.Message{Id: "m1"}})
			return
		}
		_ = json.NewEncoder(w).Encode(&gmailapi.Message{Id: "m1"})
	})
	if _, err := g.Execute(context.Background(), "create_draft", map[string]any{
		"to": []any{"x@example.com"}, "subject": "s", "body": "b",
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	raw, _ := base64.URLEncoding.DecodeString(captured.Message.Raw)
	if strings.Contains(string(raw), "multipart/") {
		t.Errorf("plain draft should not be multipart:\n%s", raw)
	}
}

// TestForwardDraft_CallerHTMLNote: a caller's body_html on a forward is used as
// the note verbatim rather than being overwritten by the assembled forward.
func TestForwardDraft_CallerHTMLNote(t *testing.T) {
	var captured gmailapi.Draft
	g := forwardMock(t, []byte("PDF"), &captured)
	const note = `<b>Please action</b>`
	if _, err := g.Execute(context.Background(), "forward_draft", map[string]any{
		"message_id": "src-1",
		"to":         []any{"x@example.com"},
		"body_html":  note,
	}); err != nil {
		t.Fatalf("Execute forward_draft: %v", err)
	}
	raw, _ := base64.URLEncoding.DecodeString(captured.Message.Raw)
	if !strings.Contains(string(raw), note) {
		t.Errorf("caller's HTML note was dropped from the forward\n%s", raw)
	}
}
