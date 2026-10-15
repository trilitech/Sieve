package gmail

import (
	"encoding/base64"
	"testing"

	gmailapi "google.golang.org/api/gmail/v1"
)

// b64 encodes part data the way the Gmail API returns it (base64url).
func b64(s string) string { return base64.URLEncoding.EncodeToString([]byte(s)) }

func textPart(mime, body string) *gmailapi.MessagePart {
	return &gmailapi.MessagePart{MimeType: mime, Body: &gmailapi.MessagePartBody{Data: b64(body)}}
}

// replyWithAttachedEmail models the real Gmail shape of a reply that carries a
// forwarded .eml: the outer body sits in a multipart/alternative, and the
// attached message is a message/rfc822 part whose OWN alternative parts appear
// later in the walk. That ordering is what made the nested text win.
func replyWithAttachedEmail() *gmailapi.MessagePart {
	return &gmailapi.MessagePart{
		MimeType: "multipart/mixed",
		Headers: []*gmailapi.MessagePartHeader{
			{Name: "Subject", Value: "Re: the actual reply"},
		},
		Parts: []*gmailapi.MessagePart{
			{
				MimeType: "multipart/alternative",
				Parts: []*gmailapi.MessagePart{
					textPart("text/plain", "OUTER reply body"),
					textPart("text/html", "<p>OUTER reply body</p>"),
				},
			},
			{
				MimeType: "message/rfc822",
				Filename: "Fwd Invoice.eml",
				Body:     &gmailapi.MessagePartBody{AttachmentId: "att-eml", Size: 4096},
				Parts: []*gmailapi.MessagePart{
					{
						MimeType: "multipart/mixed",
						Parts: []*gmailapi.MessagePart{
							{
								MimeType: "multipart/alternative",
								Parts: []*gmailapi.MessagePart{
									textPart("text/plain", "NESTED original message"),
									textPart("text/html", "<p>NESTED original message</p>"),
								},
							},
							{
								MimeType: "application/pdf",
								Filename: "inner.pdf",
								Body:     &gmailapi.MessagePartBody{AttachmentId: "att-inner", Size: 10},
							},
						},
					},
				},
			},
		},
	}
}

// TestParseEmail_AttachedMessageDoesNotHijackBody is the reported bug:
// GET /messages/{id} returned the ATTACHED email's text as the message body.
func TestParseEmail_AttachedMessageDoesNotHijackBody(t *testing.T) {
	email := parseEmail(&gmailapi.Message{
		Id: "m1", ThreadId: "t1", Payload: replyWithAttachedEmail(),
	})

	if email.Body != "OUTER reply body" {
		t.Errorf("body = %q, want the OUTER message's own text (%q); the attached\n"+
			"message/rfc822 must not supply the body", email.Body, "OUTER reply body")
	}
	if email.BodyHTML != "<p>OUTER reply body</p>" {
		t.Errorf("body_html = %q, want %q", email.BodyHTML, "<p>OUTER reply body</p>")
	}
}

// TestParseEmail_AttachedMessageIsAnAttachment: the nested email is surfaced as
// an attachment (so it is still reachable), but the attachments INSIDE it are
// not flattened into the outer message's list — they belong to the .eml.
func TestParseEmail_AttachedMessageIsAnAttachment(t *testing.T) {
	email := parseEmail(&gmailapi.Message{Id: "m1", Payload: replyWithAttachedEmail()})

	if !email.HasAttachment {
		t.Error("has_attachment = false, want true")
	}
	var ids []string
	for _, a := range email.Attachments {
		ids = append(ids, a.ID)
	}
	if len(email.Attachments) != 1 || email.Attachments[0].ID != "att-eml" {
		t.Errorf("attachments = %v, want exactly the attached message [att-eml]; "+
			"attachments nested inside the .eml must not be flattened out", ids)
	}
	if email.Attachments[0].Filename != "Fwd Invoice.eml" {
		t.Errorf("attachment filename = %q", email.Attachments[0].Filename)
	}
}

// TestParseEmail_AttachedTextFileIsNotTheBody: the same class of bug for a
// plain .txt attachment — a part with a filename is an attachment, not a body.
func TestParseEmail_AttachedTextFileIsNotTheBody(t *testing.T) {
	payload := &gmailapi.MessagePart{
		MimeType: "multipart/mixed",
		Parts: []*gmailapi.MessagePart{
			textPart("text/plain", "the real body"),
			{
				MimeType: "text/plain",
				Filename: "notes.txt",
				Body:     &gmailapi.MessagePartBody{Data: b64("ATTACHED FILE CONTENTS"), AttachmentId: "att-txt"},
			},
		},
	}
	email := parseEmail(&gmailapi.Message{Id: "m2", Payload: payload})
	if email.Body != "the real body" {
		t.Errorf("body = %q, want %q (an attached .txt must not become the body)", email.Body, "the real body")
	}
}

// TestParseEmail_SimpleMessagesUnchanged pins the ordinary shapes so the fix
// doesn't regress them.
func TestParseEmail_SimpleMessagesUnchanged(t *testing.T) {
	// Single text/plain payload (no parts at all).
	flat := parseEmail(&gmailapi.Message{Id: "a", Payload: textPart("text/plain", "hello")})
	if flat.Body != "hello" {
		t.Errorf("flat body = %q, want hello", flat.Body)
	}
	// text + html alternative.
	alt := parseEmail(&gmailapi.Message{Id: "b", Payload: &gmailapi.MessagePart{
		MimeType: "multipart/alternative",
		Parts: []*gmailapi.MessagePart{
			textPart("text/plain", "plain"),
			textPart("text/html", "<p>rich</p>"),
		},
	}})
	if alt.Body != "plain" || alt.BodyHTML != "<p>rich</p>" {
		t.Errorf("alt body=%q html=%q", alt.Body, alt.BodyHTML)
	}
	// html-only falls back into Body (pre-existing behaviour).
	htmlOnly := parseEmail(&gmailapi.Message{Id: "c", Payload: textPart("text/html", "<p>only</p>")})
	if htmlOnly.Body != "<p>only</p>" {
		t.Errorf("html-only body = %q", htmlOnly.Body)
	}
}
