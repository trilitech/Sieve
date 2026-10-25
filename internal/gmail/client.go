package gmail

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"google.golang.org/api/gmail/v1"
)

// Email represents a parsed Gmail message with full body and attachment data.
// Returned by GetEmail and GetThread (the read-style operations).
type Email struct {
	ID            string           `json:"id"`
	ThreadID      string           `json:"thread_id"`
	From          string           `json:"from"`
	To            []string         `json:"to"`
	Cc            []string         `json:"cc,omitempty"`
	Subject       string           `json:"subject"`
	Body          string           `json:"body"`
	BodyHTML      string           `json:"body_html,omitempty"`
	Date          time.Time        `json:"date"`
	Labels        []string         `json:"labels"`
	Snippet       string           `json:"snippet"`
	HasAttachment bool             `json:"has_attachment"`
	Attachments   []AttachmentMeta `json:"attachments,omitempty"`
}

// EmailStub is the lightweight shape returned by ListEmails. It deliberately
// omits body, body_html, and attachment data so list responses fit in agent
// context windows. Mirrors the convention used by every popular Gmail MCP
// server: list returns stubs, get returns the full payload. To read a body,
// follow up with GetEmail (the "read_email" operation).
type EmailStub struct {
	ID       string    `json:"id"`
	ThreadID string    `json:"thread_id"`
	From     string    `json:"from,omitempty"`
	To       []string  `json:"to,omitempty"`
	Cc       []string  `json:"cc,omitempty"`
	Subject  string    `json:"subject,omitempty"`
	Date     time.Time `json:"date,omitempty"`
	Labels   []string  `json:"labels,omitempty"`
	Snippet  string    `json:"snippet,omitempty"`
}

// AttachmentMeta is lightweight attachment info included in email responses
// so agents can discover what's attached without a separate API call.
type AttachmentMeta struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	MimeType string `json:"mime_type"`
	Size     int64  `json:"size"`
}

// Attachment represents an email attachment.
type Attachment struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	MimeType string `json:"mime_type"`
	Size     int64  `json:"size"`
	Data     []byte `json:"data,omitempty"`
}

// Thread represents a Gmail thread with its messages.
type Thread struct {
	ID       string  `json:"id"`
	Messages []Email `json:"messages"`
}

// Label represents a Gmail label.
type Label struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// DraftRequest contains the fields needed to create or update a draft.
type DraftRequest struct {
	To      []string `json:"to"`
	Cc      []string `json:"cc,omitempty"`
	Bcc     []string `json:"bcc,omitempty"`
	Subject string   `json:"subject"`
	Body    string   `json:"body"`

	// BodyHTML is an optional text/html alternative to Body. When set, the
	// message is assembled as multipart/alternative (text/plain + text/html) so
	// clients can render either. Used by forward assembly to preserve the
	// original message's HTML part (and its actionable links) rather than
	// flattening the message to plain text. Empty ⇒ a plain-text message.
	BodyHTML string `json:"body_html,omitempty"`

	// Attachments are files to include in the outgoing message. Each carries a
	// filename, MIME type, and raw bytes (Data); the connector decodes the
	// caller's base64 into Data before building the message. When present, the
	// message is assembled as multipart/mixed with one part per attachment.
	// Every attachment stays fully inspectable by policy (filename, type, size,
	// bytes) — this is the structured alternative to an opaque `raw` MIME blob.
	Attachments []Attachment `json:"attachments,omitempty"`

	// ReplyToAddresses populate the RFC 5322 Reply-To header: where replies to
	// this message should be directed. This is a genuine address header and has
	// nothing to do with the legacy ReplyTo threading field below — the two are
	// unrelated despite the similar name.
	ReplyToAddresses []string `json:"reply_to_address,omitempty"`

	// ReplyTo is the LEGACY threading field: a Gmail message id that was
	// (incorrectly) used both as the draft's threadId and as the In-Reply-To
	// header. Retained for backward compatibility; new callers should use the
	// fields below, which separate the two distinct identifiers Gmail needs.
	ReplyTo string `json:"reply_to,omitempty"`

	// Threading (proper). To draft/send a reply INTO an existing conversation
	// Gmail needs BOTH of these, and they are different identifiers:
	//   - ThreadID: the Gmail *thread* id (e.g. "19feb7fece7ad70d"). Sets the
	//     message's threadId so Gmail files it in the same conversation.
	//   - InReplyTo: the parent message's RFC 5322 *Message-ID* header value
	//     (e.g. "<CANrf...@mail.gmail.com>"). Written as In-Reply-To so the
	//     recipient's client and downstream ticketing systems can thread on it.
	//   - References: the RFC 5322 References chain (parent's References plus the
	//     parent's Message-ID). Written verbatim as the References header.
	// Angle brackets are optional on input — normalizeMessageIDs adds them.
	ThreadID   string `json:"thread_id,omitempty"`
	InReplyTo  string `json:"in_reply_to,omitempty"`
	References string `json:"references,omitempty"`
}

// threadID returns the Gmail thread id to attach a message to: the explicit
// ThreadID when set, else the legacy ReplyTo value (preserving old behavior).
func (r DraftRequest) threadID() string {
	if r.ThreadID != "" {
		return r.ThreadID
	}
	return r.ReplyTo
}

// Draft represents a Gmail draft.
type Draft struct {
	ID      string `json:"id"`
	Message Email  `json:"message"`
}

// DraftStub is the lightweight shape returned by ListDrafts: the draft id plus
// a stub of its message (no body), mirroring EmailStub for list_emails.
type DraftStub struct {
	ID      string    `json:"id"`
	Message EmailStub `json:"message"`
}

// SearchQuery defines parameters for searching emails.
type SearchQuery struct {
	Query      string // Gmail search query string
	MaxResults int64
	PageToken  string
	// LabelIds restricts results to messages carrying ALL of these label ids
	// (Gmail's messages.list labelIds). IncludeSpamTrash includes SPAM/TRASH.
	LabelIds         []string
	IncludeSpamTrash bool
}

// SearchResult contains the results of an email search. Emails are returned
// as stubs (no body) — call GetEmail to fetch a single message in full.
type SearchResult struct {
	Emails        []EmailStub `json:"emails"`
	NextPageToken string      `json:"next_page_token,omitempty"`
	Total         int64       `json:"total"`
}

// Client wraps the Gmail API for a single account.
type Client struct {
	service   *gmail.Service
	userEmail string
}

// NewClient creates a Client from an existing Gmail API service.
func NewClient(service *gmail.Service, userEmail string) *Client {
	return &Client{
		service:   service,
		userEmail: userEmail,
	}
}

// stubMetadataHeaders is the allowlist of headers fetched per message in
// ListEmails. Gmail's `metadata` format returns ALL headers by default,
// which on noisy mailboxes (DKIM, ARC, Received chains) can still be 5–10 KB
// per message. Restricting to this allowlist keeps each stub well under 1 KB
// while preserving every field an agent typically needs to triage results.
var stubMetadataHeaders = []string{"From", "To", "Cc", "Subject", "Date", "Message-ID"}

// ListEmails searches/lists emails using the Gmail API. The returned stubs
// contain only id, thread_id, snippet, labels, and the headers in
// stubMetadataHeaders — no body, no body_html, no attachments. To fetch the
// full content of a single message, call GetEmail.
func (c *Client) ListEmails(ctx context.Context, query SearchQuery) (*SearchResult, error) {
	maxResults := query.MaxResults
	if maxResults == 0 {
		maxResults = 100
	}
	if maxResults > 500 {
		maxResults = 500
	}

	call := c.service.Users.Messages.List("me").Context(ctx).MaxResults(maxResults)
	if query.Query != "" {
		call = call.Q(query.Query)
	}
	if query.PageToken != "" {
		call = call.PageToken(query.PageToken)
	}
	if len(query.LabelIds) > 0 {
		call = call.LabelIds(query.LabelIds...)
	}
	if query.IncludeSpamTrash {
		call = call.IncludeSpamTrash(true)
	}

	resp, err := call.Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: listing messages: %w", err)
	}

	result := &SearchResult{
		NextPageToken: resp.NextPageToken,
		Total:         int64(resp.ResultSizeEstimate),
	}

	for _, msg := range resp.Messages {
		stub, err := c.service.Users.Messages.Get("me", msg.Id).
			Context(ctx).
			Format("metadata").
			MetadataHeaders(stubMetadataHeaders...).
			Do()
		if err != nil {
			return nil, fmt.Errorf("gmail: getting message %s: %w", msg.Id, err)
		}
		result.Emails = append(result.Emails, parseEmailStub(stub))
	}

	return result, nil
}

// GetEmail returns a single email by message ID with full content.
func (c *Client) GetEmail(ctx context.Context, messageID string) (*Email, error) {
	msg, err := c.service.Users.Messages.Get("me", messageID).Context(ctx).Format("full").Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: getting message %s: %w", messageID, err)
	}
	email := parseEmail(msg)
	return &email, nil
}

// RawEmail mirrors the Google REST shape returned by users.messages.get with
// format=RAW: id, threadId, labelIds, internalDate, and the base64url-encoded
// RFC822 message in `raw`. JSON field names are camelCase to match the Gmail
// API verbatim — clients written against the Google API can consume this
// without a translation layer.
//
// internalDate and historyId carry the `,string` JSON tag because Google's
// REST schema declares them as "string (int64/uint64 format)" — the wire
// format is a JSON string wrapping the number, not a bare number. Emitting
// bare numbers would round-trip through encoding/json fine but would break
// downstream consumers that feed the response into Google's own client
// libraries.
type RawEmail struct {
	ID           string   `json:"id"`
	ThreadID     string   `json:"threadId"`
	LabelIDs     []string `json:"labelIds,omitempty"`
	Snippet      string   `json:"snippet,omitempty"`
	HistoryID    uint64   `json:"historyId,omitempty,string"`
	InternalDate int64    `json:"internalDate,omitempty,string"`
	SizeEstimate int64    `json:"sizeEstimate,omitempty"`
	Raw          string   `json:"raw"`
}

// GetEmailRaw returns the message with format=RAW. The `raw` field is the
// base64url-encoded RFC822 byte stream (full headers, all MIME parts,
// attachments inline). Use this for byte-faithful archival; for interactive
// reading prefer GetEmail (smaller payload, parsed body/attachments).
func (c *Client) GetEmailRaw(ctx context.Context, messageID string) (*RawEmail, error) {
	msg, err := c.service.Users.Messages.Get("me", messageID).Context(ctx).Format("raw").Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: getting raw message %s: %w", messageID, err)
	}
	return &RawEmail{
		ID:           msg.Id,
		ThreadID:     msg.ThreadId,
		LabelIDs:     msg.LabelIds,
		Snippet:      msg.Snippet,
		HistoryID:    msg.HistoryId,
		InternalDate: msg.InternalDate,
		SizeEstimate: msg.SizeEstimate,
		Raw:          msg.Raw,
	}, nil
}

// GetThread returns a full thread by thread ID.
func (c *Client) GetThread(ctx context.Context, threadID string) (*Thread, error) {
	t, err := c.service.Users.Threads.Get("me", threadID).Context(ctx).Format("full").Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: getting thread %s: %w", threadID, err)
	}

	thread := &Thread{
		ID: t.Id,
	}
	for _, msg := range t.Messages {
		thread.Messages = append(thread.Messages, parseEmail(msg))
	}
	return thread, nil
}

// CreateDraft creates a new draft message.
func (c *Client) CreateDraft(ctx context.Context, req DraftRequest) (*Draft, error) {
	raw, err := buildMIMEMessage(req)
	if err != nil {
		return nil, fmt.Errorf("gmail: building MIME message: %w", err)
	}

	gmailMsg := &gmail.Message{
		Raw: base64.URLEncoding.EncodeToString(raw),
	}
	if tid := req.threadID(); tid != "" {
		gmailMsg.ThreadId = tid
	}

	draft := &gmail.Draft{
		Message: gmailMsg,
	}

	created, err := c.service.Users.Drafts.Create("me", draft).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: creating draft: %w", err)
	}

	result := &Draft{
		ID: created.Id,
	}
	if created.Message != nil {
		// Fetch the full message to populate the Email struct.
		full, err := c.service.Users.Messages.Get("me", created.Message.Id).Context(ctx).Format("full").Do()
		if err == nil {
			result.Message = parseEmail(full)
		}
	}
	return result, nil
}

// UpdateDraft updates an existing draft.
func (c *Client) UpdateDraft(ctx context.Context, draftID string, req DraftRequest) (*Draft, error) {
	raw, err := buildMIMEMessage(req)
	if err != nil {
		return nil, fmt.Errorf("gmail: building MIME message: %w", err)
	}

	gmailMsg := &gmail.Message{
		Raw: base64.URLEncoding.EncodeToString(raw),
	}
	if tid := req.threadID(); tid != "" {
		gmailMsg.ThreadId = tid
	}

	draft := &gmail.Draft{
		Message: gmailMsg,
	}

	updated, err := c.service.Users.Drafts.Update("me", draftID, draft).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: updating draft %s: %w", draftID, err)
	}

	result := &Draft{
		ID: updated.Id,
	}
	if updated.Message != nil {
		full, err := c.service.Users.Messages.Get("me", updated.Message.Id).Context(ctx).Format("full").Do()
		if err == nil {
			result.Message = parseEmail(full)
		}
	}
	return result, nil
}

// SendEmail sends an email directly (not from a draft).
func (c *Client) SendEmail(ctx context.Context, req DraftRequest) (*Email, error) {
	raw, err := buildMIMEMessage(req)
	if err != nil {
		return nil, fmt.Errorf("gmail: building MIME message: %w", err)
	}

	gmailMsg := &gmail.Message{
		Raw: base64.URLEncoding.EncodeToString(raw),
	}
	if tid := req.threadID(); tid != "" {
		gmailMsg.ThreadId = tid
	}

	sent, err := c.service.Users.Messages.Send("me", gmailMsg).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: sending email: %w", err)
	}

	full, err := c.service.Users.Messages.Get("me", sent.Id).Context(ctx).Format("full").Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: getting sent message %s: %w", sent.Id, err)
	}
	email := parseEmail(full)
	return &email, nil
}

// SendDraft sends an existing draft.
func (c *Client) SendDraft(ctx context.Context, draftID string) (*Email, error) {
	draft := &gmail.Draft{
		Id: draftID,
	}

	sent, err := c.service.Users.Drafts.Send("me", draft).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: sending draft %s: %w", draftID, err)
	}

	if sent.Id != "" {
		full, err := c.service.Users.Messages.Get("me", sent.Id).Context(ctx).Format("full").Do()
		if err != nil {
			return nil, fmt.Errorf("gmail: getting sent draft message: %w", err)
		}
		email := parseEmail(full)
		return &email, nil
	}

	return &Email{}, nil
}

// ReplyContext carries everything needed to draft/send a reply that threads
// correctly into an existing conversation, derived from a parent message.
type ReplyContext struct {
	ThreadID  string `json:"thread_id"`  // Gmail thread id of the conversation
	MessageID string `json:"message_id"` // parent's RFC 5322 Message-ID header
	// References is the RFC 5322 References chain to carry forward: the parent's
	// own References (if any) followed by the parent's Message-ID.
	References string `json:"references"`
	Subject    string `json:"subject"` // parent subject (for "Re:" derivation)
}

// GetReplyContext fetches the metadata a caller needs to reply into the thread
// containing messageID: the Gmail threadId plus the parent's Message-ID,
// References, and Subject headers. This is the lookup behind the
// in_reply_to_message_id convenience — the one call an agent making a reply
// actually wants, so it doesn't have to fetch the parent and assemble headers
// itself. Only the four threading headers are requested (format=metadata), so
// the body is never pulled into the response.
func (c *Client) GetReplyContext(ctx context.Context, messageID string) (*ReplyContext, error) {
	msg, err := c.service.Users.Messages.Get("me", messageID).
		Context(ctx).
		Format("metadata").
		MetadataHeaders("Message-ID", "References", "Subject").
		Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: getting reply context for %s: %w", messageID, err)
	}
	rc := &ReplyContext{ThreadID: msg.ThreadId}
	var parentMsgID, parentRefs string
	if msg.Payload != nil {
		for _, h := range msg.Payload.Headers {
			switch strings.ToLower(h.Name) {
			case "message-id":
				parentMsgID = strings.TrimSpace(h.Value)
			case "references":
				parentRefs = strings.TrimSpace(h.Value)
			case "subject":
				rc.Subject = h.Value
			}
		}
	}
	rc.MessageID = parentMsgID
	// RFC 5322 §3.6.4: the reply's References is the parent's References (if
	// present) with the parent's Message-ID appended.
	switch {
	case parentRefs != "" && parentMsgID != "":
		rc.References = parentRefs + " " + parentMsgID
	case parentMsgID != "":
		rc.References = parentMsgID
	default:
		rc.References = parentRefs
	}
	return rc, nil
}

// ListDrafts returns the account's drafts as lightweight stubs (draft id plus
// the draft message's id/threadId and its From/To/Cc/Subject/Date/Snippet
// headers) — no body, mirroring ListEmails. maxResults defaults to 100 and is
// capped at 500. Without this, a caller can neither find nor verify the drafts
// it previously created.
func (c *Client) ListDrafts(ctx context.Context, maxResults int64) ([]DraftStub, error) {
	if maxResults <= 0 {
		maxResults = 100
	}
	if maxResults > 500 {
		maxResults = 500
	}
	resp, err := c.service.Users.Drafts.List("me").Context(ctx).MaxResults(maxResults).Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: listing drafts: %w", err)
	}
	stubs := make([]DraftStub, 0, len(resp.Drafts))
	for _, d := range resp.Drafts {
		stub := DraftStub{ID: d.Id}
		if d.Message != nil {
			meta, err := c.service.Users.Messages.Get("me", d.Message.Id).
				Context(ctx).
				Format("metadata").
				MetadataHeaders(stubMetadataHeaders...).
				Do()
			if err != nil {
				return nil, fmt.Errorf("gmail: getting draft message %s: %w", d.Message.Id, err)
			}
			stub.Message = parseEmailStub(meta)
		}
		stubs = append(stubs, stub)
	}
	return stubs, nil
}

// DeleteDraft permanently removes a draft by id. Pairs with ListDrafts so a bad
// draft can be cleaned up programmatically rather than by hand in the Gmail UI.
func (c *Client) DeleteDraft(ctx context.Context, draftID string) error {
	if err := c.service.Users.Drafts.Delete("me", draftID).Context(ctx).Do(); err != nil {
		return fmt.Errorf("gmail: deleting draft %s: %w", draftID, err)
	}
	return nil
}

// AddLabel adds a label to a message.
func (c *Client) AddLabel(ctx context.Context, messageID string, labelID string) error {
	req := &gmail.ModifyMessageRequest{
		AddLabelIds: []string{labelID},
	}
	_, err := c.service.Users.Messages.Modify("me", messageID, req).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("gmail: adding label %s to message %s: %w", labelID, messageID, err)
	}
	return nil
}

// RemoveLabel removes a label from a message.
func (c *Client) RemoveLabel(ctx context.Context, messageID string, labelID string) error {
	req := &gmail.ModifyMessageRequest{
		RemoveLabelIds: []string{labelID},
	}
	_, err := c.service.Users.Messages.Modify("me", messageID, req).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("gmail: removing label %s from message %s: %w", labelID, messageID, err)
	}
	return nil
}

// Archive removes the INBOX label from a message.
func (c *Client) Archive(ctx context.Context, messageID string) error {
	return c.RemoveLabel(ctx, messageID, "INBOX")
}

// ListLabels returns all labels for the account.
func (c *Client) ListLabels(ctx context.Context) ([]Label, error) {
	resp, err := c.service.Users.Labels.List("me").Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: listing labels: %w", err)
	}

	labels := make([]Label, 0, len(resp.Labels))
	for _, l := range resp.Labels {
		labels = append(labels, Label{
			ID:   l.Id,
			Name: l.Name,
			Type: l.Type,
		})
	}
	return labels, nil
}

// GetAttachment retrieves an attachment by message and attachment ID.
func (c *Client) GetAttachment(ctx context.Context, messageID, attachmentID string) (*Attachment, error) {
	att, err := c.service.Users.Messages.Attachments.Get("me", messageID, attachmentID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: getting attachment %s from message %s: %w", attachmentID, messageID, err)
	}

	data, err := base64.URLEncoding.DecodeString(att.Data)
	if err != nil {
		return nil, fmt.Errorf("gmail: decoding attachment data: %w", err)
	}

	// Look up the message to get filename and mime type for this attachment.
	msg, err := c.service.Users.Messages.Get("me", messageID).Context(ctx).Format("full").Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: getting message %s for attachment metadata: %w", messageID, err)
	}

	result := &Attachment{
		ID:   attachmentID,
		Size: att.Size,
		Data: data,
	}

	// Walk message parts to find the matching attachment.
	findAttachmentMeta(msg.Payload, attachmentID, result)

	return result, nil
}

// findAttachmentMeta walks message parts to populate filename and mime type.
func findAttachmentMeta(part *gmail.MessagePart, attachmentID string, att *Attachment) {
	if part == nil {
		return
	}
	if part.Body != nil && part.Body.AttachmentId == attachmentID {
		att.Filename = part.Filename
		att.MimeType = part.MimeType
		return
	}
	for _, p := range part.Parts {
		findAttachmentMeta(p, attachmentID, att)
	}
}

// parseEmailStub extracts only the fields an EmailStub carries — id,
// thread_id, the allowlisted headers, snippet, and label IDs. Skips body
// extraction and attachment walking; the Gmail API call that produced `msg`
// uses Format("metadata") so part data isn't present anyway.
func parseEmailStub(msg *gmail.Message) EmailStub {
	stub := EmailStub{
		ID:       msg.Id,
		ThreadID: msg.ThreadId,
		Labels:   msg.LabelIds,
		Snippet:  msg.Snippet,
	}
	if msg.Payload != nil {
		for _, h := range msg.Payload.Headers {
			switch strings.ToLower(h.Name) {
			case "from":
				stub.From = h.Value
			case "to":
				stub.To = parseAddressList(h.Value)
			case "cc":
				stub.Cc = parseAddressList(h.Value)
			case "subject":
				stub.Subject = h.Value
			case "date":
				if t, err := mail.ParseDate(h.Value); err == nil {
					stub.Date = t
				}
			}
		}
	}
	return stub
}

// parseEmail extracts headers and body from a Gmail API message.
func parseEmail(msg *gmail.Message) Email {
	email := Email{
		ID:       msg.Id,
		ThreadID: msg.ThreadId,
		Labels:   msg.LabelIds,
		Snippet:  msg.Snippet,
	}

	if msg.Payload != nil {
		for _, h := range msg.Payload.Headers {
			switch strings.ToLower(h.Name) {
			case "from":
				email.From = h.Value
			case "to":
				email.To = parseAddressList(h.Value)
			case "cc":
				email.Cc = parseAddressList(h.Value)
			case "subject":
				email.Subject = h.Value
			case "date":
				if t, err := mail.ParseDate(h.Value); err == nil {
					email.Date = t
				}
			}
		}

		// Extract body from parts.
		var textBody, htmlBody string
		extractBody(msg.Payload, &textBody, &htmlBody)
		email.Body = textBody
		email.BodyHTML = htmlBody
		if email.Body == "" && email.BodyHTML != "" {
			email.Body = email.BodyHTML
		}

		// Collect attachment metadata.
		email.Attachments = collectAttachments(msg.Payload)
		email.HasAttachment = len(email.Attachments) > 0
	}

	return email
}

// baseMimeType returns a part's media type lowercased and without parameters
// ("text/plain; charset=UTF-8" → "text/plain"), so comparisons are robust to
// the parameters some servers include.
func baseMimeType(part *gmail.MessagePart) string {
	if part == nil {
		return ""
	}
	mt := part.MimeType
	if i := strings.IndexByte(mt, ';'); i >= 0 {
		mt = mt[:i]
	}
	return strings.ToLower(strings.TrimSpace(mt))
}

// isAttachedMessage reports whether a part is an attached email (a forwarded
// .eml and friends). Its sub-parts describe that message, not the one carrying
// it, so neither body extraction nor attachment collection may descend into it.
func isAttachedMessage(part *gmail.MessagePart) bool {
	return baseMimeType(part) == "message/rfc822"
}

// extractBody walks a message's OWN body parts, filling textBody/htmlBody with
// the first text/plain and text/html it finds. Two rules keep it on the outer
// message:
//
//   - Attachment subtrees are skipped. A part carrying a filename is an
//     attached file, and a message/rfc822 part is an attached email; the text
//     inside either is not this message's body. Without this, a reply with a
//     forwarded .eml reported the FORWARDED message's text as its body.
//   - The first match per type wins. The old code assigned on every match, so
//     whichever text part came last in the walk silently overwrote the real
//     body — which is exactly what an attached message's parts did.
//
// Content inside an attached message stays reachable: the .eml is reported as
// an attachment, and ?format=raw still returns the byte-faithful MIME.
func extractBody(part *gmail.MessagePart, textBody, htmlBody *string) {
	if part == nil {
		return
	}
	// Never treat an attachment's contents as the message body.
	if part.Filename != "" || isAttachedMessage(part) {
		return
	}

	if part.Body != nil && part.Body.Data != "" {
		switch baseMimeType(part) {
		case "text/plain":
			if *textBody == "" {
				if decoded, err := base64.URLEncoding.DecodeString(part.Body.Data); err == nil {
					*textBody = string(decoded)
				}
			}
		case "text/html":
			if *htmlBody == "" {
				if decoded, err := base64.URLEncoding.DecodeString(part.Body.Data); err == nil {
					*htmlBody = string(decoded)
				}
			}
		}
	}

	for _, p := range part.Parts {
		extractBody(p, textBody, htmlBody)
	}
}


// collectAttachments recursively walks message parts to find attachments
// and returns their metadata (ID, filename, MIME type, size).
func collectAttachments(part *gmail.MessagePart) []AttachmentMeta {
	if part == nil {
		return nil
	}
	var attachments []AttachmentMeta
	// An attached email is ONE attachment. Its own parts (its body, and any
	// files it carries) belong to it, so we record it and stop: flattening them
	// into this message's list would misreport which message they came from.
	// Fetch the .eml by its attachment id to see inside it.
	if isAttachedMessage(part) {
		if part.Body != nil && part.Body.AttachmentId != "" {
			filename := part.Filename
			if filename == "" {
				filename = "attached-message.eml"
			}
			attachments = append(attachments, AttachmentMeta{
				ID:       part.Body.AttachmentId,
				Filename: filename,
				MimeType: part.MimeType,
				Size:     part.Body.Size,
			})
		}
		return attachments
	}
	if part.Filename != "" && part.Body != nil && part.Body.AttachmentId != "" {
		attachments = append(attachments, AttachmentMeta{
			ID:       part.Body.AttachmentId,
			Filename: part.Filename,
			MimeType: part.MimeType,
			Size:     part.Body.Size,
		})
	}
	for _, p := range part.Parts {
		attachments = append(attachments, collectAttachments(p)...)
	}
	return attachments
}

// parseAddressList splits a comma-separated list of email addresses.
func parseAddressList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// encodeAddressList renders recipients for an address header, RFC 2047-encoding
// any non-ASCII display name while leaving the address literal. A pure-ASCII
// entry (a bare address or "Name <addr>") is passed through unchanged, so the
// common case is byte-identical to before. A non-ASCII entry is parsed and
// re-emitted via mail.Address.String() (which encodes only the display name);
// if it can't be parsed, the whole entry is word-encoded as a 7-bit-safe
// fallback rather than emitting raw UTF-8 bytes into the header.
func encodeAddressList(addrs []string) string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		switch {
		case isASCII(a):
			out = append(out, a)
		default:
			if parsed, err := mail.ParseAddress(a); err == nil {
				out = append(out, parsed.String())
			} else {
				out = append(out, mime.QEncoding.Encode("utf-8", a))
			}
		}
	}
	return strings.Join(out, ", ")
}

// isASCII reports whether s contains only 7-bit bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// buildMIMEMessage creates an RFC 2822 message from a DraftRequest. The body
// section adapts to the request's shape:
//   - plain body only            → text/plain
//   - body + BodyHTML            → multipart/alternative
//   - + Attachments              → multipart/mixed wrapping the above + each file
//
// The top-level address/subject/threading headers are identical in every case;
// only the content section differs, so a plain-text send is byte-for-byte what
// it was before attachments/HTML existed.
func buildMIMEMessage(req DraftRequest) ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteString("MIME-Version: 1.0\r\n")

	if len(req.To) > 0 {
		buf.WriteString(fmt.Sprintf("To: %s\r\n", encodeAddressList(req.To)))
	}
	if len(req.Cc) > 0 {
		buf.WriteString(fmt.Sprintf("Cc: %s\r\n", encodeAddressList(req.Cc)))
	}
	if len(req.Bcc) > 0 {
		buf.WriteString(fmt.Sprintf("Bcc: %s\r\n", encodeAddressList(req.Bcc)))
	}
	if len(req.ReplyToAddresses) > 0 {
		buf.WriteString(fmt.Sprintf("Reply-To: %s\r\n", encodeAddressList(req.ReplyToAddresses)))
	}
	// RFC 2047-encode the Subject. A header is ASCII-only (RFC 5322); writing raw
	// UTF-8 bytes makes downstream clients reinterpret them as latin1/cp1252 (the
	// "â€“" mojibake). QEncoding returns pure-ASCII input unchanged, so ASCII
	// subjects are byte-identical to before.
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", mime.QEncoding.Encode("utf-8", req.Subject)))

	// Threading headers. Prefer the explicit InReplyTo/References; fall back to
	// the legacy ReplyTo (a Gmail message id used as a stand-in Message-ID).
	inReplyTo := req.InReplyTo
	references := req.References
	if inReplyTo == "" && req.ReplyTo != "" {
		inReplyTo = req.ReplyTo
		if references == "" {
			references = req.ReplyTo
		}
	}
	if inReplyTo != "" {
		buf.WriteString(fmt.Sprintf("In-Reply-To: %s\r\n", normalizeMessageIDs(inReplyTo)))
	}
	if references != "" {
		buf.WriteString(fmt.Sprintf("References: %s\r\n", normalizeMessageIDs(references)))
	}

	if err := writeBodySection(&buf, req); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeBodySection appends the Content-Type header for the message body, the
// blank line ending the header block, and the body content itself.
func writeBodySection(buf *bytes.Buffer, req DraftRequest) error {
	if len(req.Attachments) == 0 {
		// No attachments: the body IS the top-level entity.
		ct, content, err := renderBodyEntity(req.Body, req.BodyHTML)
		if err != nil {
			return err
		}
		buf.WriteString("Content-Type: " + ct + "\r\n\r\n")
		buf.Write(content)
		return nil
	}

	// Attachments present: multipart/mixed of [body entity][file, file, ...].
	var mixed bytes.Buffer
	mw := multipart.NewWriter(&mixed)

	bodyCT, bodyContent, err := renderBodyEntity(req.Body, req.BodyHTML)
	if err != nil {
		return err
	}
	bodyPart, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {bodyCT}})
	if err != nil {
		return err
	}
	if _, err := bodyPart.Write(bodyContent); err != nil {
		return err
	}
	for _, att := range req.Attachments {
		if err := writeAttachmentPart(mw, att); err != nil {
			return err
		}
	}
	if err := mw.Close(); err != nil {
		return err
	}

	buf.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=%q\r\n\r\n", mw.Boundary()))
	buf.Write(mixed.Bytes())
	return nil
}

// renderBodyEntity produces the Content-Type value and byte content for the
// message body: a bare text/plain part when there is no HTML, otherwise a
// multipart/alternative (text/plain + text/html) so clients pick a rendering.
func renderBodyEntity(text, html string) (contentType string, content []byte, err error) {
	if html == "" {
		return "text/plain; charset=\"UTF-8\"", []byte(text), nil
	}
	var alt bytes.Buffer
	aw := multipart.NewWriter(&alt)
	tp, err := aw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=\"UTF-8\""}})
	if err != nil {
		return "", nil, err
	}
	if _, err := tp.Write([]byte(text)); err != nil {
		return "", nil, err
	}
	hp, err := aw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/html; charset=\"UTF-8\""}})
	if err != nil {
		return "", nil, err
	}
	if _, err := hp.Write([]byte(html)); err != nil {
		return "", nil, err
	}
	if err := aw.Close(); err != nil {
		return "", nil, err
	}
	return fmt.Sprintf("multipart/alternative; boundary=%q", aw.Boundary()), alt.Bytes(), nil
}

// writeAttachmentPart writes one base64-encoded attachment part into mw, with
// Content-Type (carrying the filename), a base64 Content-Transfer-Encoding, and
// an attachment Content-Disposition. Non-ASCII filenames are RFC 2231-encoded by
// mime.FormatMediaType; if that fails the raw filename is used as a fallback.
func writeAttachmentPart(mw *multipart.Writer, att Attachment) error {
	ct := att.MimeType
	if ct == "" {
		ct = "application/octet-stream"
	}
	h := textproto.MIMEHeader{}
	if v := mime.FormatMediaType(ct, map[string]string{"name": att.Filename}); v != "" {
		h.Set("Content-Type", v)
	} else {
		h.Set("Content-Type", ct)
	}
	h.Set("Content-Transfer-Encoding", "base64")
	if v := mime.FormatMediaType("attachment", map[string]string{"filename": att.Filename}); v != "" {
		h.Set("Content-Disposition", v)
	} else {
		h.Set("Content-Disposition", "attachment")
	}
	pw, err := mw.CreatePart(h)
	if err != nil {
		return err
	}
	// RFC 2045 caps encoded lines at 76 chars; wrap so strict parsers accept it.
	enc := base64.StdEncoding.EncodeToString(att.Data)
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		if _, err := pw.Write([]byte(enc[i:end] + "\r\n")); err != nil {
			return err
		}
	}
	return nil
}

// normalizeMessageIDs ensures every whitespace-separated token in an
// In-Reply-To / References value is wrapped in angle brackets, so callers may
// pass ids with or without them. A token already shaped like "<...>" is left
// as-is; a bare "abc@host" becomes "<abc@host>". Empty tokens are dropped.
func normalizeMessageIDs(s string) string {
	fields := strings.Fields(s)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if !strings.HasPrefix(f, "<") {
			f = "<" + f
		}
		if !strings.HasSuffix(f, ">") {
			f = f + ">"
		}
		out = append(out, f)
	}
	return strings.Join(out, " ")
}
