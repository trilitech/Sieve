package gmail

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"google.golang.org/api/gmail/v1"
)

// Email represents a parsed Gmail message.
type Email struct {
	ID            string    `json:"id"`
	ThreadID      string    `json:"thread_id"`
	From          string    `json:"from"`
	To            []string  `json:"to"`
	Cc            []string  `json:"cc,omitempty"`
	Subject       string    `json:"subject"`
	Body          string    `json:"body"`
	BodyHTML      string    `json:"body_html,omitempty"`
	Date          time.Time `json:"date"`
	Labels        []string  `json:"labels"`
	Snippet       string    `json:"snippet"`
	HasAttachment bool              `json:"has_attachment"`
	Attachments   []AttachmentMeta  `json:"attachments,omitempty"`
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
	Subject string   `json:"subject"`
	Body    string   `json:"body"`
	ReplyTo string   `json:"reply_to,omitempty"` // message ID to reply to
}

// Draft represents a Gmail draft.
type Draft struct {
	ID      string `json:"id"`
	Message Email  `json:"message"`
}

// SearchQuery defines parameters for searching emails.
type SearchQuery struct {
	Query      string // Gmail search query string
	MaxResults int64
	PageToken  string
}

// SearchResult contains the results of an email search.
type SearchResult struct {
	Emails        []Email `json:"emails"`
	NextPageToken string  `json:"next_page_token,omitempty"`
	Total         int64   `json:"total"`
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

// ListEmails searches/lists emails using the Gmail API.
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

	resp, err := call.Do()
	if err != nil {
		return nil, fmt.Errorf("gmail: listing messages: %w", err)
	}

	result := &SearchResult{
		NextPageToken: resp.NextPageToken,
		Total:         int64(resp.ResultSizeEstimate),
	}

	for _, msg := range resp.Messages {
		full, err := c.service.Users.Messages.Get("me", msg.Id).Context(ctx).Format("full").Do()
		if err != nil {
			return nil, fmt.Errorf("gmail: getting message %s: %w", msg.Id, err)
		}
		result.Emails = append(result.Emails, parseEmail(full))
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
	if req.ReplyTo != "" {
		gmailMsg.ThreadId = req.ReplyTo
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
	if req.ReplyTo != "" {
		gmailMsg.ThreadId = req.ReplyTo
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
	if req.ReplyTo != "" {
		gmailMsg.ThreadId = req.ReplyTo
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

// extractBody recursively walks message parts to find text/plain and text/html content.
func extractBody(part *gmail.MessagePart, textBody, htmlBody *string) {
	if part == nil {
		return
	}

	if part.MimeType == "text/plain" && part.Body != nil && part.Body.Data != "" {
		decoded, err := base64.URLEncoding.DecodeString(part.Body.Data)
		if err == nil {
			*textBody = string(decoded)
		}
	}

	if part.MimeType == "text/html" && part.Body != nil && part.Body.Data != "" {
		decoded, err := base64.URLEncoding.DecodeString(part.Body.Data)
		if err == nil {
			*htmlBody = string(decoded)
		}
	}

	for _, p := range part.Parts {
		extractBody(p, textBody, htmlBody)
	}
}

// hasAttachment checks whether any part in the message is an attachment.
func hasAttachment(part *gmail.MessagePart) bool {
	if part == nil {
		return false
	}
	if part.Filename != "" && part.Body != nil && part.Body.AttachmentId != "" {
		return true
	}
	for _, p := range part.Parts {
		if hasAttachment(p) {
			return true
		}
	}
	return false
}

// collectAttachments recursively walks message parts to find attachments
// and returns their metadata (ID, filename, MIME type, size).
func collectAttachments(part *gmail.MessagePart) []AttachmentMeta {
	if part == nil {
		return nil
	}
	var attachments []AttachmentMeta
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

// buildMIMEMessage creates an RFC 2822 message from a DraftRequest.
func buildMIMEMessage(req DraftRequest) ([]byte, error) {
	var buf strings.Builder

	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n")

	if len(req.To) > 0 {
		buf.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(req.To, ", ")))
	}
	if len(req.Cc) > 0 {
		buf.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(req.Cc, ", ")))
	}
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", req.Subject))

	if req.ReplyTo != "" {
		buf.WriteString(fmt.Sprintf("In-Reply-To: <%s>\r\n", req.ReplyTo))
		buf.WriteString(fmt.Sprintf("References: <%s>\r\n", req.ReplyTo))
	}

	buf.WriteString("\r\n")
	buf.WriteString(req.Body)

	return []byte(buf.String()), nil
}
