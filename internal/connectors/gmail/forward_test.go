package gmail

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"strings"
	"testing"

	gmailapi "google.golang.org/api/gmail/v1"
)

// sourceMessage is the message under test that gets forwarded: it has genuine
// headers, a text and an HTML body part, and one attachment.
func sourceMessage() *gmailapi.Message {
	return &gmailapi.Message{
		Id:       "src-1",
		ThreadId: "thr-src",
		Payload: &gmailapi.MessagePart{
			MimeType: "multipart/mixed",
			Headers: []*gmailapi.MessagePartHeader{
				{Name: "From", Value: "Sender <sender@example.com>"},
				{Name: "Date", Value: "Mon, 08 Sep 2025 10:00:00 +0000"},
				{Name: "Subject", Value: "Capital call"},
				{Name: "To", Value: "owner@example.com"},
			},
			Parts: []*gmailapi.MessagePart{
				{MimeType: "text/plain", Body: &gmailapi.MessagePartBody{Data: base64.URLEncoding.EncodeToString([]byte("original text body"))}},
				{MimeType: "text/html", Body: &gmailapi.MessagePartBody{Data: base64.URLEncoding.EncodeToString([]byte(`<p>original <a href="http://wire.example/call">View capital call</a></p>`))}},
				{Filename: "doc.pdf", MimeType: "application/pdf", Body: &gmailapi.MessagePartBody{AttachmentId: "att-1", Size: 3}},
			},
		},
	}
}

// forwardMock wires a connector whose Gmail service answers the reads a forward
// performs (source full-get, attachment fetch) and captures the created draft.
func forwardMock(t *testing.T, attBytes []byte, captured *gmailapi.Draft) *GoogleConnector {
	return newConnectorWithMock(t, func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/drafts"):
			_ = json.NewDecoder(r.Body).Decode(captured)
			_ = json.NewEncoder(w).Encode(&gmailapi.Draft{
				Id: "d-1", Message: &gmailapi.Message{Id: "m-new", ThreadId: "thr-new"},
			})
		case strings.Contains(path, "/attachments/att-1"):
			_ = json.NewEncoder(w).Encode(&gmailapi.MessagePartBody{
				AttachmentId: "att-1",
				Size:         int64(len(attBytes)),
				Data:         base64.URLEncoding.EncodeToString(attBytes),
			})
		case strings.Contains(path, "/messages/src-1"):
			_ = json.NewEncoder(w).Encode(sourceMessage())
		default: // follow-up full-get of the created message
			_ = json.NewEncoder(w).Encode(&gmailapi.Message{Id: "m-new", ThreadId: "thr-new"})
		}
	})
}

// decodeForwardMIME pulls apart the RFC822 the draft carried in Message.Raw,
// returning the top-level media type/params and the raw body bytes (so callers
// can build their own multipart readers — a multipart.Part is only valid until
// the next NextPart, so parts can't be collected into a slice for later use).
func decodeForwardMIME(t *testing.T, raw string) (topType string, params map[string]string, body []byte) {
	t.Helper()
	decoded, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode Raw: %v", err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("ReadMessage: %v\n%s", err, decoded)
	}
	topType, params, err = mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("ParseMediaType: %v", err)
	}
	body, err = io.ReadAll(msg.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return topType, params, body
}

// TestForwardDraft_AssemblesFaithfulForward is the headline test for the
// trustmatters P1: forwarding must produce a real forward (genuine headers, the
// original text AND html, the original attachment) — not a hand-typed imitation.
func TestForwardDraft_AssemblesFaithfulForward(t *testing.T) {
	attBytes := []byte("PDF")
	var captured gmailapi.Draft
	g := forwardMock(t, attBytes, &captured)

	_, err := g.Execute(context.Background(), "forward_draft", map[string]any{
		"message_id": "src-1",
		"to":         []any{"trustee@example.com"},
		"body":       "please action before Monday",
	})
	if err != nil {
		t.Fatalf("Execute forward_draft: %v", err)
	}
	if captured.Message == nil {
		t.Fatal("no draft captured")
	}

	topType, params, body := decodeForwardMIME(t, captured.Message.Raw)
	if topType != "multipart/mixed" {
		t.Fatalf("top type = %q, want multipart/mixed (attachment must ride along)", topType)
	}

	var text, html string
	var sawAttachment bool
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		ct := p.Header.Get("Content-Type")
		switch {
		case strings.HasPrefix(ct, "multipart/alternative"):
			_, ap, _ := mime.ParseMediaType(ct)
			data, _ := io.ReadAll(p)
			amr := multipart.NewReader(bytes.NewReader(data), ap["boundary"])
			for {
				sub, err := amr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("alt NextPart: %v", err)
				}
				sdata, _ := io.ReadAll(sub)
				sct := sub.Header.Get("Content-Type")
				if strings.HasPrefix(sct, "text/plain") {
					text = string(sdata)
				}
				if strings.HasPrefix(sct, "text/html") {
					html = string(sdata)
				}
			}
		case p.FileName() == "doc.pdf":
			sawAttachment = true
			enc, _ := io.ReadAll(p)
			got, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(enc)), ""))
			if err != nil {
				t.Fatalf("decode attachment: %v", err)
			}
			if !bytes.Equal(got, attBytes) {
				t.Errorf("attachment bytes = %q, want %q", got, attBytes)
			}
		}
	}

	// Subject defaulted to Fwd: <source subject>.
	rawStr := mustDecode(t, captured.Message.Raw)
	if !strings.Contains(rawStr, "Subject: Fwd: Capital call") {
		t.Errorf("missing Fwd: subject\n%s", rawStr)
	}
	// Threading must NOT be set — a forward starts a new thread, not a reply.
	if captured.Message.ThreadId != "" {
		t.Errorf("forward set threadId %q; a forward must start a new thread", captured.Message.ThreadId)
	}

	for _, want := range []string{
		"please action before Monday",                 // the caller's note
		"---------- Forwarded message ----------",     // the forwarded separator
		"From: Sender <sender@example.com>",           // genuine From
		"Subject: Capital call",                       // genuine Subject
		"original text body",                          // the original text
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text body missing %q\n--- text ---\n%s", want, text)
		}
	}
	// The actionable link — the whole reason to keep HTML — must survive.
	if !strings.Contains(html, `href="http://wire.example/call"`) {
		t.Errorf("HTML body lost the actionable link\n--- html ---\n%s", html)
	}
	if !sawAttachment {
		t.Error("original attachment doc.pdf was not carried into the forward")
	}
}

// TestForwardDraft_SubjectOverride: an explicit subject is used verbatim (no
// Fwd: prefix forced).
func TestForwardDraft_SubjectOverride(t *testing.T) {
	var captured gmailapi.Draft
	g := forwardMock(t, []byte("PDF"), &captured)
	_, err := g.Execute(context.Background(), "forward_draft", map[string]any{
		"message_id": "src-1",
		"to":         []any{"x@example.com"},
		"subject":    "FYI: the call",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	raw := mustDecode(t, captured.Message.Raw)
	if !strings.Contains(raw, "Subject: FYI: the call") {
		t.Errorf("subject override not honored\n%s", raw)
	}
	if strings.Contains(raw, "Fwd: FYI") {
		t.Errorf("Fwd: prefix wrongly forced onto an explicit subject")
	}
}

func mustDecode(t *testing.T, raw string) string {
	t.Helper()
	b, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return string(b)
}

func TestEnsureFwdPrefix(t *testing.T) {
	cases := map[string]string{
		"Capital call":      "Fwd: Capital call",
		"Fwd: Capital call": "Fwd: Capital call",
		"fwd: x":            "fwd: x",
		"Fw: x":             "Fw: x",
		"":                  "Fwd: ",
	}
	for in, want := range cases {
		if got := ensureFwdPrefix(in); got != want {
			t.Errorf("ensureFwdPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGetAttachmentsParam(t *testing.T) {
	// Happy path: base64 std content decodes to the original bytes.
	content := base64.StdEncoding.EncodeToString([]byte("hello"))
	atts, err := getAttachmentsParam(map[string]any{
		"attachments": []any{
			map[string]any{"filename": "a.txt", "mime_type": "text/plain", "content": content},
		},
	})
	if err != nil {
		t.Fatalf("getAttachmentsParam: %v", err)
	}
	if len(atts) != 1 || atts[0].Filename != "a.txt" || string(atts[0].Data) != "hello" {
		t.Fatalf("parsed = %+v", atts)
	}

	// Absent → nil, no error.
	if got, err := getAttachmentsParam(map[string]any{}); err != nil || got != nil {
		t.Fatalf("absent: got %v, %v", got, err)
	}

	// Missing filename → error (not silent drop).
	if _, err := getAttachmentsParam(map[string]any{
		"attachments": []any{map[string]any{"content": content}},
	}); err == nil {
		t.Error("expected error for missing filename")
	}

	// Bad base64 → error.
	if _, err := getAttachmentsParam(map[string]any{
		"attachments": []any{map[string]any{"filename": "a", "content": "!!!not base64!!!"}},
	}); err == nil {
		t.Error("expected error for invalid base64 content")
	}

	// Wrong shape → error.
	if _, err := getAttachmentsParam(map[string]any{"attachments": "nope"}); err == nil {
		t.Error("expected error for non-array attachments")
	}
}

func TestDecodeBase64_Tolerant(t *testing.T) {
	want := []byte("hi there\x00")
	for name, enc := range map[string]string{
		"std":    base64.StdEncoding.EncodeToString(want),
		"url":    base64.URLEncoding.EncodeToString(want),
		"rawStd": base64.RawStdEncoding.EncodeToString(want),
		"rawURL": base64.RawURLEncoding.EncodeToString(want),
	} {
		got, err := decodeBase64(enc)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: decodeBase64 = %q, %v", name, got, err)
		}
	}
}
