package gmail

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

// parseBuilt parses the bytes buildMIMEMessage produced into its top-level
// header set, media type, media-type params, and raw body (everything after the
// header/body separator).
func parseBuilt(t *testing.T, raw []byte) (mail.Header, string, map[string]string, []byte) {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadMessage: %v\n--- raw ---\n%s", err, raw)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("ParseMediaType(%q): %v", msg.Header.Get("Content-Type"), err)
	}
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return msg.Header, mediaType, params, body
}

// TestBuildMIMEMessage_Attachment: a body plus one attachment must assemble a
// multipart/mixed with a text/plain body part and a base64 attachment part that
// round-trips to the original bytes, carrying filename + disposition.
func TestBuildMIMEMessage_Attachment(t *testing.T) {
	payload := []byte("PDF-BYTES-\x00\x01\x02here")
	raw, err := buildMIMEMessage(DraftRequest{
		To:      []string{"a@example.com"},
		Subject: "with file",
		Body:    "see attached",
		Attachments: []Attachment{
			{Filename: "report.pdf", MimeType: "application/pdf", Data: payload},
		},
	})
	if err != nil {
		t.Fatalf("buildMIMEMessage: %v", err)
	}

	_, mediaType, params, body := parseBuilt(t, raw)
	if mediaType != "multipart/mixed" {
		t.Fatalf("top-level media type = %q, want multipart/mixed", mediaType)
	}

	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	var sawBody, sawAttachment bool
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		ct := part.Header.Get("Content-Type")
		switch {
		case strings.HasPrefix(ct, "text/plain"):
			sawBody = true
			data, _ := io.ReadAll(part)
			if string(data) != "see attached" {
				t.Errorf("body part = %q, want %q", data, "see attached")
			}
		case strings.HasPrefix(ct, "application/pdf"):
			sawAttachment = true
			if part.FileName() != "report.pdf" {
				t.Errorf("attachment filename = %q, want report.pdf", part.FileName())
			}
			if cte := part.Header.Get("Content-Transfer-Encoding"); cte != "base64" {
				t.Errorf("Content-Transfer-Encoding = %q, want base64", cte)
			}
			// The multipart reader does NOT base64-decode; do it ourselves and
			// confirm the bytes survived intact.
			encoded, _ := io.ReadAll(part)
			decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.ReplaceAll(string(encoded), "\r\n", ""), "\n", ""))
			if err != nil {
				t.Fatalf("decoding attachment base64: %v", err)
			}
			if !bytes.Equal(decoded, payload) {
				t.Errorf("attachment bytes = %q, want %q", decoded, payload)
			}
			if cd := part.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
				t.Errorf("Content-Disposition = %q, want attachment", cd)
			}
		}
	}
	if !sawBody || !sawAttachment {
		t.Fatalf("missing parts: sawBody=%v sawAttachment=%v", sawBody, sawAttachment)
	}
}

// TestBuildMIMEMessage_HTMLAlternative: a body with BodyHTML and no attachments
// must be a multipart/alternative carrying both text/plain and text/html.
func TestBuildMIMEMessage_HTMLAlternative(t *testing.T) {
	raw, err := buildMIMEMessage(DraftRequest{
		To:       []string{"a@example.com"},
		Subject:  "html",
		Body:     "plain version",
		BodyHTML: "<p>html <a href=\"http://x\">version</a></p>",
	})
	if err != nil {
		t.Fatalf("buildMIMEMessage: %v", err)
	}
	_, mediaType, params, body := parseBuilt(t, raw)
	if mediaType != "multipart/alternative" {
		t.Fatalf("media type = %q, want multipart/alternative", mediaType)
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	var text, html string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		data, _ := io.ReadAll(part)
		ct := part.Header.Get("Content-Type")
		switch {
		case strings.HasPrefix(ct, "text/plain"):
			text = string(data)
		case strings.HasPrefix(ct, "text/html"):
			html = string(data)
		}
	}
	if text != "plain version" {
		t.Errorf("text part = %q", text)
	}
	if !strings.Contains(html, "href=\"http://x\"") {
		t.Errorf("html part lost the link: %q", html)
	}
}

// TestBuildMIMEMessage_HTMLWithAttachment: html + attachment nests a
// multipart/alternative inside the multipart/mixed alongside the file part.
func TestBuildMIMEMessage_HTMLWithAttachment(t *testing.T) {
	raw, err := buildMIMEMessage(DraftRequest{
		To:          []string{"a@example.com"},
		Subject:     "both",
		Body:        "plain",
		BodyHTML:    "<p>rich</p>",
		Attachments: []Attachment{{Filename: "a.txt", MimeType: "text/plain", Data: []byte("filedata")}},
	})
	if err != nil {
		t.Fatalf("buildMIMEMessage: %v", err)
	}
	_, mediaType, params, body := parseBuilt(t, raw)
	if mediaType != "multipart/mixed" {
		t.Fatalf("media type = %q, want multipart/mixed", mediaType)
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	var sawAlt, sawFile bool
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		ct := part.Header.Get("Content-Type")
		if strings.HasPrefix(ct, "multipart/alternative") {
			sawAlt = true
		}
		if part.FileName() == "a.txt" {
			sawFile = true
		}
	}
	if !sawAlt || !sawFile {
		t.Fatalf("sawAlt=%v sawFile=%v", sawAlt, sawFile)
	}
}

// TestBuildMIMEMessage_PlainUnchanged: with neither HTML nor attachments the
// message is a bare text/plain — the pre-existing shape, unchanged.
func TestBuildMIMEMessage_PlainUnchanged(t *testing.T) {
	raw, err := buildMIMEMessage(DraftRequest{To: []string{"a@example.com"}, Subject: "s", Body: "b"})
	if err != nil {
		t.Fatalf("buildMIMEMessage: %v", err)
	}
	_, mediaType, _, body := parseBuilt(t, raw)
	if mediaType != "text/plain" {
		t.Fatalf("media type = %q, want text/plain", mediaType)
	}
	if string(body) != "b" {
		t.Errorf("body = %q, want b", body)
	}
}
