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
	"strings"
	"sync"
	"testing"

	gmailapi "google.golang.org/api/gmail/v1"
)

// sourceWithAttachmentID is the i20-shaped source message: a real body plus a
// named PDF attachment, parameterised by the attachmentId Gmail reports.
func sourceWithAttachmentID(attID string) *gmailapi.Message {
	return &gmailapi.Message{
		Id:       "src-1",
		ThreadId: "thr-src",
		Payload: &gmailapi.MessagePart{
			MimeType: "multipart/mixed",
			Headers: []*gmailapi.MessagePartHeader{
				{Name: "From", Value: "Wissam <wissam@example.com>"},
				{Name: "Subject", Value: "i20 Summit speaker invite"},
				{Name: "To", Value: "arthur@example.com"},
			},
			Parts: []*gmailapi.MessagePart{
				{MimeType: "text/plain", Body: &gmailapi.MessagePartBody{
					Data: base64.URLEncoding.EncodeToString([]byte("original body"))}},
				{
					Filename: "i20-agenda.pdf",
					MimeType: "application/pdf",
					Body:     &gmailapi.MessagePartBody{AttachmentId: attID, Size: 3},
				},
			},
		},
	}
}

// TestForward_PreservesAttachmentMetadataAcrossIDRegeneration reproduces the
// reported defect. Gmail does not guarantee that the attachmentId in a fresh
// messages.get matches the one you already hold: the held id keeps working for
// attachments.get, but a re-walk of the new payload looking for it finds
// nothing. buildForward used to rely on exactly that re-walk, so the bytes
// arrived while the filename and Content-Type did not — every forwarded
// attachment became an unnamed application/octet-stream.
//
// The mock serves the FIRST messages.get with the original id and every later
// one with a regenerated id, while attachments.get keeps honouring the
// original. The forward must still name the file and type it correctly.
func TestForward_PreservesAttachmentMetadataAcrossIDRegeneration(t *testing.T) {
	const heldID = "att-original"
	attBytes := []byte("PDF")

	var mu sync.Mutex
	messageGets := 0

	var captured gmailapi.Draft
	g := newConnectorWithMock(t, func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/drafts"):
			_ = json.NewDecoder(r.Body).Decode(&captured)
			_ = json.NewEncoder(w).Encode(&gmailapi.Draft{
				Id: "d-1", Message: &gmailapi.Message{Id: "m-new"},
			})
		case strings.Contains(path, "/attachments/"+heldID):
			// The id we hold still resolves to the bytes.
			_ = json.NewEncoder(w).Encode(&gmailapi.MessagePartBody{
				AttachmentId: heldID, Size: int64(len(attBytes)),
				Data: base64.URLEncoding.EncodeToString(attBytes),
			})
		case strings.Contains(path, "/messages/src-1"):
			mu.Lock()
			messageGets++
			n := messageGets
			mu.Unlock()
			id := heldID
			if n > 1 {
				id = "att-REGENERATED" // Gmail handed back a different id
			}
			_ = json.NewEncoder(w).Encode(sourceWithAttachmentID(id))
		default:
			_ = json.NewEncoder(w).Encode(&gmailapi.Message{Id: "m-new"})
		}
	})

	if _, err := g.Execute(context.Background(), "forward_draft", map[string]any{
		"message_id": "src-1",
		"to":         []any{"eoin@example.com"},
		"body":       "Forwarding the invite.",
	}); err != nil {
		t.Fatalf("Execute forward_draft: %v", err)
	}
	if captured.Message == nil {
		t.Fatal("no draft captured")
	}

	raw, err := base64.URLEncoding.DecodeString(captured.Message.Raw)
	if err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	filename, ctype, data := findForwardedAttachment(t, raw)

	if filename != "i20-agenda.pdf" {
		t.Errorf("attachment filename = %q, want %q (metadata lost on re-attach)", filename, "i20-agenda.pdf")
	}
	if !strings.HasPrefix(ctype, "application/pdf") {
		t.Errorf("attachment Content-Type = %q, want application/pdf (not octet-stream)", ctype)
	}
	if !bytes.Equal(data, attBytes) {
		t.Errorf("attachment bytes = %q, want %q", data, attBytes)
	}
	if strings.Contains(string(raw), `name=""`) {
		t.Errorf("emitted an empty name parameter; omit it instead\n%s", raw)
	}
}

// findForwardedAttachment walks the built message and returns the first
// attachment part's filename, Content-Type and decoded bytes.
func findForwardedAttachment(t *testing.T, raw []byte) (filename, ctype string, data []byte) {
	t.Helper()
	topType, params, body := decodeForwardMIME(t, base64.URLEncoding.EncodeToString(raw))
	if !strings.HasPrefix(topType, "multipart/") {
		t.Fatalf("expected multipart, got %q", topType)
	}
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
		mt, _, _ := mime.ParseMediaType(ct)
		if strings.HasPrefix(mt, "multipart/") {
			continue // the body alternative
		}
		if p.Header.Get("Content-Disposition") == "" {
			continue
		}
		enc, _ := io.ReadAll(p)
		decoded, derr := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(enc)), ""))
		if derr != nil {
			t.Fatalf("decode attachment base64: %v", derr)
		}
		return p.FileName(), ct, decoded
	}
	t.Fatal("no attachment part found in the forward")
	return "", "", nil
}
