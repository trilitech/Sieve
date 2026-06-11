package gmail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	gmailapi "google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

// newTestClient spins up an httptest.Server with the given handler and
// returns a Client wired to it.
func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	svc, err := gmailapi.NewService(context.Background(),
		option.WithEndpoint(srv.URL),
		option.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatalf("gmailapi.NewService: %v", err)
	}
	return NewClient(svc, "me@example.com"), srv
}

// TestListEmails_ReturnsStubsOnly is the regression test for issue #3:
// list responses must NOT contain bodies, body_html, or attachments,
// regardless of what's in the underlying mailbox.
func TestListEmails_ReturnsStubsOnly(t *testing.T) {
	var fetchedFormats []string
	var fetchedHeaders [][]string

	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/users/me/messages"):
			// List call — return two message IDs.
			json.NewEncoder(w).Encode(gmailapi.ListMessagesResponse{
				Messages: []*gmailapi.Message{
					{Id: "msg-1", ThreadId: "thr-1"},
					{Id: "msg-2", ThreadId: "thr-2"},
				},
				ResultSizeEstimate: 2,
			})
		case strings.Contains(r.URL.Path, "/users/me/messages/"):
			// Per-message Get — record the format + metadataHeaders so the
			// test can assert we asked for the metadata shape.
			fetchedFormats = append(fetchedFormats, r.URL.Query().Get("format"))
			fetchedHeaders = append(fetchedHeaders, r.URL.Query()["metadataHeaders"])

			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			// Even if the upstream were to return body data, our metadata
			// call shouldn't include parts. We deliberately return some
			// text/plain body data here to prove the *client* drops it.
			resp := &gmailapi.Message{
				Id:       id,
				ThreadId: "thr-" + id,
				Snippet:  "snippet for " + id,
				LabelIds: []string{"INBOX"},
				Payload: &gmailapi.MessagePart{
					Headers: []*gmailapi.MessagePartHeader{
						{Name: "From", Value: "alice@example.com"},
						{Name: "To", Value: "me@example.com"},
						{Name: "Subject", Value: "Re: " + id},
						{Name: "Date", Value: "Mon, 02 Jan 2026 15:04:05 -0700"},
					},
					// Even if Gmail returned this (it shouldn't, with
					// format=metadata), the stub parser must ignore it.
					MimeType: "text/plain",
					Body: &gmailapi.MessagePartBody{
						Data: "U2hvdWxkLW5vdC1hcHBlYXItaW4tYS1zdHViLg==", // "Should-not-appear-in-a-stub."
						Size: 26,
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	result, err := client.ListEmails(context.Background(), SearchQuery{MaxResults: 10})
	if err != nil {
		t.Fatalf("ListEmails: %v", err)
	}
	if len(result.Emails) != 2 {
		t.Fatalf("expected 2 stubs, got %d", len(result.Emails))
	}

	// Per-message calls must use Format("metadata") + the header allowlist.
	for i, fmt := range fetchedFormats {
		if fmt != "metadata" {
			t.Errorf("call %d: expected format=metadata, got %q", i, fmt)
		}
		got := append([]string(nil), fetchedHeaders[i]...)
		sort.Strings(got)
		want := append([]string(nil), stubMetadataHeaders...)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("call %d: metadataHeaders=%v, want %v", i, got, want)
		}
	}

	// Round-trip the stubs through JSON to assert the wire shape carries no
	// `body`, `body_html`, `attachments`, or `has_attachment` key. (omitempty
	// alone isn't enough — the EmailStub type must not have the fields at
	// all so a typed caller can't accidentally read a stale empty value.)
	bytes, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{`"body"`, `"body_html"`, `"attachments"`, `"has_attachment"`} {
		if strings.Contains(string(bytes), forbidden) {
			t.Errorf("list response contains %s — list is supposed to return stubs only:\n%s",
				forbidden, string(bytes))
		}
	}

	// Header allowlist actually populated the stub.
	first := result.Emails[0]
	if first.From != "alice@example.com" {
		t.Errorf("From = %q, want alice@example.com", first.From)
	}
	if first.Subject != "Re: msg-1" {
		t.Errorf("Subject = %q, want Re: msg-1", first.Subject)
	}
	if first.Snippet != "snippet for msg-1" {
		t.Errorf("Snippet = %q", first.Snippet)
	}
	if len(first.Labels) != 1 || first.Labels[0] != "INBOX" {
		t.Errorf("Labels = %v, want [INBOX]", first.Labels)
	}
}

// TestGetEmailRaw_PassesRawFormatAndReturnsGoogleShape verifies that
// GetEmailRaw requests format=raw from Gmail and returns the `raw` field
// verbatim along with the camelCase Google-shaped envelope (id, threadId,
// labelIds, internalDate). The byte-for-byte fidelity of `raw` matters for
// archival pipelines that need to reconstruct .eml on disk.
func TestGetEmailRaw_PassesRawFormatAndReturnsGoogleShape(t *testing.T) {
	var fetchedFormat string
	const rawPayload = "RnJvbTogYWxpY2VAZXhhbXBsZS5jb20NCk1lc3NhZ2UtSUQ6IDxhYmNAeD4NCg0KaGk="
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		fetchedFormat = r.URL.Query().Get("format")
		json.NewEncoder(w).Encode(&gmailapi.Message{
			Id:           "msg-raw",
			ThreadId:     "thr-raw",
			LabelIds:     []string{"INBOX", "UNREAD"},
			Snippet:      "hi",
			HistoryId:    424242,
			InternalDate: 1735689600000,
			SizeEstimate: 1024,
			Raw:          rawPayload,
		})
	})

	got, err := client.GetEmailRaw(context.Background(), "msg-raw")
	if err != nil {
		t.Fatalf("GetEmailRaw: %v", err)
	}
	if fetchedFormat != "raw" {
		t.Errorf("Gmail format = %q, want raw", fetchedFormat)
	}
	if got.Raw != rawPayload {
		t.Errorf("Raw = %q, want %q (must round-trip unmodified)", got.Raw, rawPayload)
	}
	if got.ID != "msg-raw" || got.ThreadID != "thr-raw" {
		t.Errorf("ID/ThreadID = %q/%q", got.ID, got.ThreadID)
	}
	if got.InternalDate != 1735689600000 {
		t.Errorf("InternalDate = %d", got.InternalDate)
	}
	if len(got.LabelIDs) != 2 || got.LabelIDs[0] != "INBOX" || got.LabelIDs[1] != "UNREAD" {
		t.Errorf("LabelIDs = %v", got.LabelIDs)
	}

	// JSON-marshalled shape must use Google's camelCase field names so a
	// REST consumer written against the Gmail API sees the same wire format.
	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	wire := string(blob)
	for _, key := range []string{`"id":`, `"threadId":`, `"labelIds":`, `"internalDate":`, `"raw":`} {
		if !strings.Contains(wire, key) {
			t.Errorf("Marshal output missing %s, got: %s", key, wire)
		}
	}
	for _, snake := range []string{`"thread_id":`, `"label_ids":`, `"internal_date":`} {
		if strings.Contains(wire, snake) {
			t.Errorf("Marshal output should not contain snake_case key %s; got: %s", snake, wire)
		}
	}
}

// TestGetEmail_ReturnsFullBody verifies read_email still fetches the full
// payload, including the parsed plain-text body.
func TestGetEmail_ReturnsFullBody(t *testing.T) {
	var fetchedFormat string
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		fetchedFormat = r.URL.Query().Get("format")
		json.NewEncoder(w).Encode(&gmailapi.Message{
			Id:       "msg-1",
			ThreadId: "thr-1",
			Snippet:  "Hello",
			LabelIds: []string{"INBOX"},
			Payload: &gmailapi.MessagePart{
				Headers: []*gmailapi.MessagePartHeader{
					{Name: "From", Value: "alice@example.com"},
					{Name: "Subject", Value: "Hi"},
				},
				MimeType: "text/plain",
				Body: &gmailapi.MessagePartBody{
					// "Hello, body here." base64-url-encoded.
					Data: "SGVsbG8sIGJvZHkgaGVyZS4=",
					Size: 17,
				},
			},
		})
	})

	email, err := client.GetEmail(context.Background(), "msg-1")
	if err != nil {
		t.Fatalf("GetEmail: %v", err)
	}
	if fetchedFormat != "full" {
		t.Errorf("GetEmail used format=%q, want full", fetchedFormat)
	}
	if email.Body != "Hello, body here." {
		t.Errorf("Body = %q, want %q", email.Body, "Hello, body here.")
	}
	if email.From != "alice@example.com" {
		t.Errorf("From = %q", email.From)
	}
}
