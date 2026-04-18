// Package gmail implements the Google connector for Sieve. It wraps Google
// service APIs (Gmail, Drive, Calendar, Contacts, Sheets, and Docs) behind
// the connector.Connector interface so that the MCP server and REST API can
// invoke Google operations uniformly through the policy pipeline.
//
// The connector uses a Factory pattern: Factory(config) returns a ready-to-use
// GoogleConnector. The factory handles two OAuth token scenarios:
//
//  1. If client_id and client_secret are present in the config, it builds a
//     refreshing TokenSource via oauth2.Config.TokenSource. This means expired
//     access tokens are automatically refreshed using the refresh_token, which
//     is the normal production path after the web UI OAuth flow.
//
//  2. If client credentials are missing (e.g., CLI setup before OAuth), it
//     falls back to a StaticTokenSource that uses the access token as-is.
//     This won't refresh, so it will stop working once the token expires —
//     but it allows basic validation and testing.
//
// Token expiry handling: if the stored expiry is zero/missing, it is set to
// time.Now() so the oauth2 library treats the token as expired and immediately
// attempts a refresh. This ensures stale tokens from a database restore or
// manual config don't silently fail.
package gmail

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/murbard/Sieve/internal/connector"
	gmailclient "github.com/murbard/Sieve/internal/gmail"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	calendarapi "google.golang.org/api/calendar/v3"
	docsapi "google.golang.org/api/docs/v1"
	driveapi "google.golang.org/api/drive/v3"
	googleapi "google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
	peopleapi "google.golang.org/api/people/v1"
	sheetsapi "google.golang.org/api/sheets/v4"
)

// Meta describes the Google Account connector for the UI catalog.
var Meta = connector.ConnectorMeta{
	Type:        "google",
	Name:        "Google Account",
	Description: "Gmail, Drive, Calendar, Contacts, and Sheets via Google APIs",
	Category:    "Google",
	SetupFields: []connector.Field{
		{Name: "email", Label: "Google Account Email", Type: "text", Required: true, Placeholder: "you@gmail.com"},
		{Name: "oauth_token", Label: "OAuth Token", Type: "oauth", Required: true, HelpText: "Authenticate via Google OAuth"},
	},
}

// GoogleConnector implements the connector.Connector interface for Google services.
type GoogleConnector struct {
	client         *gmailclient.Client
	driveClient    *gmailclient.DriveClient
	calendarClient *gmailclient.CalendarClient
	peopleClient   *gmailclient.PeopleClient
	sheetsClient   *gmailclient.SheetsClient
	docsClient     *gmailclient.DocsClient
	email          string
}

// persistingTokenSource wraps an oauth2.TokenSource and calls a callback
// whenever a new token is obtained (i.e., after a refresh). This allows
// the refreshed credentials to be persisted back to the database so they
// survive server restarts without triggering another refresh cycle.
type persistingTokenSource struct {
	base     oauth2.TokenSource
	lastHash string // hash of last seen access_token to detect changes
	onRefresh func(token *oauth2.Token)
}

func (p *persistingTokenSource) Token() (*oauth2.Token, error) {
	tok, err := p.base.Token()
	if err != nil {
		return nil, err
	}
	// Detect if the token changed (refresh happened).
	if tok.AccessToken != p.lastHash {
		if p.lastHash != "" && p.onRefresh != nil {
			// Not the first call — a real refresh happened.
			p.onRefresh(tok)
		}
		p.lastHash = tok.AccessToken
	}
	return tok, nil
}

// Factory creates a new GoogleConnector from the provided config.
// Expected config keys:
//   - "email": string - the user's email address
//   - "oauth_token": map[string]any - OAuth2 token with keys: access_token, token_type, refresh_token, expiry
//   - "client_id", "client_secret": for token refresh
//   - "_on_token_refresh": func(*oauth2.Token) - optional callback for persisting refreshed tokens
func Factory(config map[string]any) (connector.Connector, error) {
	email, ok := config["email"].(string)
	if !ok || email == "" {
		return nil, fmt.Errorf("gmail connector: missing or invalid 'email' in config")
	}

	tokenMap, ok := config["oauth_token"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("gmail connector: missing or invalid 'oauth_token' in config")
	}

	token, err := tokenFromMap(tokenMap)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: parsing oauth_token: %w", err)
	}

	// Build a refreshing token source using client credentials if available,
	// otherwise fall back to a static (non-refreshing) token source.
	var tokenSource oauth2.TokenSource
	clientID, _ := config["client_id"].(string)
	clientSecret, _ := config["client_secret"].(string)
	if clientID != "" && clientSecret != "" {
		oauthConf := &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     google.Endpoint,
		}
		base := oauthConf.TokenSource(context.Background(), token)

		// Wrap with persistence callback if provided. This allows the
		// connections service to persist refreshed tokens back to the DB.
		onRefresh, _ := config["_on_token_refresh"].(func(*oauth2.Token))
		tokenSource = &persistingTokenSource{
			base:      base,
			lastHash:  token.AccessToken,
			onRefresh: onRefresh,
		}
	} else {
		tokenSource = oauth2.StaticTokenSource(token)
	}

	tsOpt := option.WithTokenSource(tokenSource)

	svc, err := googleapi.NewService(context.Background(), tsOpt)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: creating gmail service: %w", err)
	}

	driveSvc, err := driveapi.NewService(context.Background(), tsOpt)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: creating drive service: %w", err)
	}

	calendarSvc, err := calendarapi.NewService(context.Background(), tsOpt)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: creating calendar service: %w", err)
	}

	peopleSvc, err := peopleapi.NewService(context.Background(), tsOpt)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: creating people service: %w", err)
	}

	sheetsSvc, err := sheetsapi.NewService(context.Background(), tsOpt)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: creating sheets service: %w", err)
	}

	docsSvc, err := docsapi.NewService(context.Background(), tsOpt)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: creating docs service: %w", err)
	}

	client := gmailclient.NewClient(svc, email)

	return &GoogleConnector{
		client:         client,
		driveClient:    gmailclient.NewDriveClient(driveSvc),
		calendarClient: gmailclient.NewCalendarClient(calendarSvc),
		peopleClient:   gmailclient.NewPeopleClient(peopleSvc),
		sheetsClient:   gmailclient.NewSheetsClient(sheetsSvc),
		docsClient:     gmailclient.NewDocsClient(docsSvc, driveSvc),
		email:          email,
	}, nil
}

// tokenFromMap reconstructs an *oauth2.Token from a map[string]any.
func tokenFromMap(m map[string]any) (*oauth2.Token, error) {
	accessToken, _ := m["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("missing access_token")
	}

	token := &oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    getStringFromMap(m, "token_type"),
		RefreshToken: getStringFromMap(m, "refresh_token"),
	}

	if expiryStr, ok := m["expiry"].(string); ok && expiryStr != "" {
		t, err := time.Parse(time.RFC3339, expiryStr)
		if err != nil {
			return nil, fmt.Errorf("parsing expiry: %w", err)
		}
		token.Expiry = t
	}

	// If expiry is zero (missing or unparseable), set it to now. The oauth2
	// library checks token.Valid() which returns false when Expiry <= now,
	// triggering an automatic refresh via the refresh_token. Without this,
	// a missing expiry would make the token appear perpetually valid even
	// after the access token actually expires on Google's side.
	if token.Expiry.IsZero() {
		token.Expiry = time.Now().UTC()
	}

	return token, nil
}

func getStringFromMap(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// Type returns "google".
func (g *GoogleConnector) Type() string {
	return "google"
}

// Operations returns the list of supported Gmail operations.
func (g *GoogleConnector) Operations() []connector.OperationDef {
	return []connector.OperationDef{
		{
			Name:        "list_emails",
			Description: "Search and list emails using Gmail query syntax",
			Params: map[string]connector.ParamDef{
				"query":       {Type: "string", Description: "Gmail search query string", Required: false},
				"max_results": {Type: "int", Description: "Maximum number of results to return", Required: false},
				"page_token":  {Type: "string", Description: "Page token for pagination", Required: false},
			},
			ReadOnly: true,
		},
		{
			Name:        "read_email",
			Description: "Read a single email by message ID",
			Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Description: "The ID of the message to read", Required: true},
			},
			ReadOnly: true,
		},
		{
			Name:        "read_thread",
			Description: "Read all messages in a thread",
			Params: map[string]connector.ParamDef{
				"thread_id": {Type: "string", Description: "The ID of the thread to read", Required: true},
			},
			ReadOnly: true,
		},
		{
			Name:        "create_draft",
			Description: "Create a new email draft",
			Params: map[string]connector.ParamDef{
				"to":       {Type: "[]string", Description: "Recipient email addresses", Required: false},
				"cc":       {Type: "[]string", Description: "CC email addresses", Required: false},
				"subject":  {Type: "string", Description: "Email subject", Required: false},
				"body":     {Type: "string", Description: "Email body text", Required: false},
				"reply_to": {Type: "string", Description: "Message ID to reply to", Required: false},
			},
			ReadOnly: false,
		},
		{
			Name:        "update_draft",
			Description: "Update an existing email draft",
			Params: map[string]connector.ParamDef{
				"draft_id": {Type: "string", Description: "The ID of the draft to update", Required: true},
				"to":       {Type: "[]string", Description: "Recipient email addresses", Required: false},
				"cc":       {Type: "[]string", Description: "CC email addresses", Required: false},
				"subject":  {Type: "string", Description: "Email subject", Required: false},
				"body":     {Type: "string", Description: "Email body text", Required: false},
			},
			ReadOnly: false,
		},
		{
			Name:        "send_email",
			Description: "Send an email directly",
			Params: map[string]connector.ParamDef{
				"to":       {Type: "[]string", Description: "Recipient email addresses", Required: false},
				"cc":       {Type: "[]string", Description: "CC email addresses", Required: false},
				"subject":  {Type: "string", Description: "Email subject", Required: false},
				"body":     {Type: "string", Description: "Email body text", Required: false},
				"reply_to": {Type: "string", Description: "Message ID to reply to", Required: false},
			},
			ReadOnly: false,
		},
		{
			Name:        "send_draft",
			Description: "Send an existing draft",
			Params: map[string]connector.ParamDef{
				"draft_id": {Type: "string", Description: "The ID of the draft to send", Required: true},
			},
			ReadOnly: false,
		},
		{
			Name:        "reply",
			Description: "Reply to an existing email",
			Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Description: "The ID of the message to reply to", Required: true},
				"to":         {Type: "[]string", Description: "Recipient email addresses (defaults to original sender)", Required: false},
				"cc":         {Type: "[]string", Description: "CC email addresses", Required: false},
				"subject":    {Type: "string", Description: "Email subject (defaults to Re: original subject)", Required: false},
				"body":       {Type: "string", Description: "Reply body text", Required: true},
			},
			ReadOnly: false,
		},
		{
			Name:        "add_label",
			Description: "Add a label to a message",
			Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Description: "The ID of the message", Required: true},
				"label_id":   {Type: "string", Description: "The ID of the label to add", Required: true},
			},
			ReadOnly: false,
		},
		{
			Name:        "remove_label",
			Description: "Remove a label from a message",
			Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Description: "The ID of the message", Required: true},
				"label_id":   {Type: "string", Description: "The ID of the label to remove", Required: true},
			},
			ReadOnly: false,
		},
		{
			Name:        "archive",
			Description: "Archive a message by removing the INBOX label",
			Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Description: "The ID of the message to archive", Required: true},
			},
			ReadOnly: false,
		},
		{
			Name:        "list_labels",
			Description: "List all labels for the account",
			Params:      map[string]connector.ParamDef{},
			ReadOnly:    true,
		},
		{
			Name:        "get_attachment",
			Description: "Download an email attachment",
			Params: map[string]connector.ParamDef{
				"message_id":    {Type: "string", Description: "The ID of the message containing the attachment", Required: true},
				"attachment_id": {Type: "string", Description: "The ID of the attachment", Required: true},
			},
			ReadOnly: true,
		},

		// --- Google Drive ---
		{
			Name:        "drive.list_files",
			Description: "List files in Google Drive with optional search query",
			Params: map[string]connector.ParamDef{
				"query":      {Type: "string", Description: "Drive search query (e.g. \"name contains 'report'\")", Required: false},
				"page_size":  {Type: "int", Description: "Maximum number of results (default 100)", Required: false},
				"page_token": {Type: "string", Description: "Page token for pagination", Required: false},
			},
			ReadOnly: true,
		},
		{
			Name:        "drive.get_file",
			Description: "Get metadata for a single file in Google Drive",
			Params: map[string]connector.ParamDef{
				"file_id": {Type: "string", Description: "The ID of the file", Required: true},
			},
			ReadOnly: true,
		},
		{
			Name:        "drive.download_file",
			Description: "Download a file's content from Google Drive (returned as base64)",
			Params: map[string]connector.ParamDef{
				"file_id": {Type: "string", Description: "The ID of the file to download", Required: true},
			},
			ReadOnly: true,
		},
		{
			Name:        "drive.upload_file",
			Description: "Upload a file to Google Drive",
			Params: map[string]connector.ParamDef{
				"name":             {Type: "string", Description: "Filename", Required: true},
				"content":          {Type: "string", Description: "File content as base64", Required: true},
				"mime_type":        {Type: "string", Description: "MIME type of the file", Required: true},
				"parent_folder_id": {Type: "string", Description: "Parent folder ID (optional)", Required: false},
			},
			ReadOnly: false,
		},
		{
			Name:        "drive.share_file",
			Description: "Share a file with a user by email",
			Params: map[string]connector.ParamDef{
				"file_id": {Type: "string", Description: "The ID of the file to share", Required: true},
				"email":   {Type: "string", Description: "Email address to share with", Required: true},
				"role":    {Type: "string", Description: "Permission role: reader, writer, commenter (default: reader)", Required: false},
			},
			ReadOnly: false,
		},

		// --- Google Calendar ---
		{
			Name:        "calendar.list_events",
			Description: "List events from a Google Calendar",
			Params: map[string]connector.ParamDef{
				"calendar_id": {Type: "string", Description: "Calendar ID (default: primary)", Required: false},
				"time_min":    {Type: "string", Description: "Start time filter (RFC3339, e.g. 2024-01-01T00:00:00Z)", Required: false},
				"time_max":    {Type: "string", Description: "End time filter (RFC3339)", Required: false},
				"max_results": {Type: "int", Description: "Maximum number of events (default 100)", Required: false},
				"page_token":  {Type: "string", Description: "Page token for pagination", Required: false},
			},
			ReadOnly: true,
		},
		{
			Name:        "calendar.get_event",
			Description: "Get a single calendar event by ID",
			Params: map[string]connector.ParamDef{
				"calendar_id": {Type: "string", Description: "Calendar ID (default: primary)", Required: false},
				"event_id":    {Type: "string", Description: "The event ID", Required: true},
			},
			ReadOnly: true,
		},
		{
			Name:        "calendar.create_event",
			Description: "Create a new calendar event",
			Params: map[string]connector.ParamDef{
				"calendar_id": {Type: "string", Description: "Calendar ID (default: primary)", Required: false},
				"summary":     {Type: "string", Description: "Event title", Required: true},
				"start":       {Type: "string", Description: "Start time (RFC3339)", Required: true},
				"end":         {Type: "string", Description: "End time (RFC3339)", Required: true},
				"location":    {Type: "string", Description: "Event location", Required: false},
				"description": {Type: "string", Description: "Event description", Required: false},
				"attendees":   {Type: "[]string", Description: "Attendee email addresses", Required: false},
			},
			ReadOnly: false,
		},
		{
			Name:        "calendar.update_event",
			Description: "Update an existing calendar event",
			Params: map[string]connector.ParamDef{
				"calendar_id": {Type: "string", Description: "Calendar ID (default: primary)", Required: false},
				"event_id":    {Type: "string", Description: "The event ID", Required: true},
				"summary":     {Type: "string", Description: "Event title", Required: false},
				"start":       {Type: "string", Description: "Start time (RFC3339)", Required: false},
				"end":         {Type: "string", Description: "End time (RFC3339)", Required: false},
				"location":    {Type: "string", Description: "Event location", Required: false},
				"description": {Type: "string", Description: "Event description", Required: false},
				"attendees":   {Type: "[]string", Description: "Attendee email addresses", Required: false},
			},
			ReadOnly: false,
		},
		{
			Name:        "calendar.delete_event",
			Description: "Delete a calendar event",
			Params: map[string]connector.ParamDef{
				"calendar_id": {Type: "string", Description: "Calendar ID (default: primary)", Required: false},
				"event_id":    {Type: "string", Description: "The event ID to delete", Required: true},
			},
			ReadOnly: false,
		},

		// --- Google People/Contacts ---
		{
			Name:        "people.list_contacts",
			Description: "List the user's Google contacts",
			Params: map[string]connector.ParamDef{
				"page_size":  {Type: "int", Description: "Maximum number of contacts (default 100)", Required: false},
				"page_token": {Type: "string", Description: "Page token for pagination", Required: false},
			},
			ReadOnly: true,
		},
		{
			Name:        "people.get_contact",
			Description: "Get a single contact by resource name",
			Params: map[string]connector.ParamDef{
				"resource_name": {Type: "string", Description: "Resource name (e.g. people/c12345)", Required: true},
			},
			ReadOnly: true,
		},
		{
			Name:        "people.create_contact",
			Description: "Create a new contact",
			Params: map[string]connector.ParamDef{
				"name":  {Type: "string", Description: "Contact name", Required: false},
				"email": {Type: "string", Description: "Contact email address", Required: false},
				"phone": {Type: "string", Description: "Contact phone number", Required: false},
			},
			ReadOnly: false,
		},
		{
			Name:        "people.update_contact",
			Description: "Update an existing contact",
			Params: map[string]connector.ParamDef{
				"resource_name": {Type: "string", Description: "Resource name (e.g. people/c12345)", Required: true},
				"name":          {Type: "string", Description: "Contact name", Required: false},
				"email":         {Type: "string", Description: "Contact email address", Required: false},
				"phone":         {Type: "string", Description: "Contact phone number", Required: false},
			},
			ReadOnly: false,
		},
		{
			Name:        "people.delete_contact",
			Description: "Delete a contact",
			Params: map[string]connector.ParamDef{
				"resource_name": {Type: "string", Description: "Resource name (e.g. people/c12345)", Required: true},
			},
			ReadOnly: false,
		},

		// --- Google Sheets ---
		{
			Name:        "sheets.get_spreadsheet",
			Description: "Get metadata about a spreadsheet (sheets, titles)",
			Params: map[string]connector.ParamDef{
				"spreadsheet_id": {Type: "string", Description: "The spreadsheet ID", Required: true},
			},
			ReadOnly: true,
		},
		{
			Name:        "sheets.read_range",
			Description: "Read values from a spreadsheet range",
			Params: map[string]connector.ParamDef{
				"spreadsheet_id": {Type: "string", Description: "The spreadsheet ID", Required: true},
				"range":          {Type: "string", Description: "A1 notation range (e.g. Sheet1!A1:D10)", Required: true},
			},
			ReadOnly: true,
		},
		{
			Name:        "sheets.write_range",
			Description: "Write values to a spreadsheet range",
			Params: map[string]connector.ParamDef{
				"spreadsheet_id": {Type: "string", Description: "The spreadsheet ID", Required: true},
				"range":          {Type: "string", Description: "A1 notation range (e.g. Sheet1!A1:D10)", Required: true},
				"values":         {Type: "string", Description: "JSON array of rows, e.g. [[\"a\",\"b\"],[\"c\",\"d\"]]", Required: true},
			},
			ReadOnly: false,
		},
		{
			Name:        "sheets.create_spreadsheet",
			Description: "Create a new Google Sheets spreadsheet",
			Params: map[string]connector.ParamDef{
				"title": {Type: "string", Description: "Spreadsheet title", Required: true},
			},
			ReadOnly: false,
		},

		// --- Google Docs ---
		{
			Name:        "docs.get_document",
			Description: "Get a Google Doc with its plain text content",
			Params: map[string]connector.ParamDef{
				"document_id": {Type: "string", Description: "The document ID", Required: true},
			},
			ReadOnly: true,
		},
		{
			Name:        "docs.list_documents",
			Description: "List Google Docs from Drive",
			Params: map[string]connector.ParamDef{
				"page_size":  {Type: "int", Description: "Maximum number of results (default 100)", Required: false},
				"page_token": {Type: "string", Description: "Page token for pagination", Required: false},
			},
			ReadOnly: true,
		},
		{
			Name:        "docs.create_document",
			Description: "Create a new Google Doc",
			Params: map[string]connector.ParamDef{
				"title": {Type: "string", Description: "Document title", Required: true},
			},
			ReadOnly: false,
		},
		{
			Name:        "docs.update_document",
			Description: "Update a Google Doc using batch update requests",
			Params: map[string]connector.ParamDef{
				"document_id": {Type: "string", Description: "The document ID", Required: true},
				"requests":    {Type: "string", Description: "JSON array of Docs API request objects", Required: true},
			},
			ReadOnly: false,
		},
	}
}

// Execute routes an operation to the appropriate gmail.Client method.
func (g *GoogleConnector) Execute(ctx context.Context, op string, params map[string]any) (any, error) {
	switch op {
	case "list_emails":
		query := gmailclient.SearchQuery{
			Query:      getStringParam(params, "query"),
			MaxResults: int64(getIntParam(params, "max_results")),
			PageToken:  getStringParam(params, "page_token"),
		}
		return g.client.ListEmails(ctx, query)

	case "read_email":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		return g.client.GetEmail(ctx, messageID)

	case "read_thread":
		threadID, err := requireStringParam(params, "thread_id")
		if err != nil {
			return nil, err
		}
		return g.client.GetThread(ctx, threadID)

	case "create_draft":
		req := gmailclient.DraftRequest{
			To:      getStringSliceParam(params, "to"),
			Cc:      getStringSliceParam(params, "cc"),
			Subject: getStringParam(params, "subject"),
			Body:    getStringParam(params, "body"),
			ReplyTo: getStringParam(params, "reply_to"),
		}
		return g.client.CreateDraft(ctx, req)

	case "update_draft":
		draftID, err := requireStringParam(params, "draft_id")
		if err != nil {
			return nil, err
		}
		req := gmailclient.DraftRequest{
			To:      getStringSliceParam(params, "to"),
			Cc:      getStringSliceParam(params, "cc"),
			Subject: getStringParam(params, "subject"),
			Body:    getStringParam(params, "body"),
		}
		return g.client.UpdateDraft(ctx, draftID, req)

	case "send_email":
		req := gmailclient.DraftRequest{
			To:      getStringSliceParam(params, "to"),
			Cc:      getStringSliceParam(params, "cc"),
			Subject: getStringParam(params, "subject"),
			Body:    getStringParam(params, "body"),
			ReplyTo: getStringParam(params, "reply_to"),
		}
		return g.client.SendEmail(ctx, req)

	case "send_draft":
		draftID, err := requireStringParam(params, "draft_id")
		if err != nil {
			return nil, err
		}
		return g.client.SendDraft(ctx, draftID)

	case "add_label":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		labelID, err := requireStringParam(params, "label_id")
		if err != nil {
			return nil, err
		}
		return nil, g.client.AddLabel(ctx, messageID, labelID)

	case "remove_label":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		labelID, err := requireStringParam(params, "label_id")
		if err != nil {
			return nil, err
		}
		return nil, g.client.RemoveLabel(ctx, messageID, labelID)

	case "archive":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		return nil, g.client.Archive(ctx, messageID)

	case "list_labels":
		return g.client.ListLabels(ctx)

	case "reply":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		req := gmailclient.DraftRequest{
			To:      getStringSliceParam(params, "to"),
			Cc:      getStringSliceParam(params, "cc"),
			Subject: getStringParam(params, "subject"),
			Body:    getStringParam(params, "body"),
			ReplyTo: messageID,
		}
		return g.client.SendEmail(ctx, req)

	case "get_attachment":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		attachmentID, err := requireStringParam(params, "attachment_id")
		if err != nil {
			return nil, err
		}
		return g.client.GetAttachment(ctx, messageID, attachmentID)

	// --- Google Drive ---
	case "drive.list_files":
		return g.driveClient.ListFiles(ctx,
			getStringParam(params, "query"),
			int64(getIntParam(params, "page_size")),
			getStringParam(params, "page_token"),
		)

	case "drive.get_file":
		fileID, err := requireStringParam(params, "file_id")
		if err != nil {
			return nil, err
		}
		return g.driveClient.GetFile(ctx, fileID)

	case "drive.download_file":
		fileID, err := requireStringParam(params, "file_id")
		if err != nil {
			return nil, err
		}
		return g.driveClient.DownloadFile(ctx, fileID)

	case "drive.upload_file":
		name, err := requireStringParam(params, "name")
		if err != nil {
			return nil, err
		}
		content, err := requireStringParam(params, "content")
		if err != nil {
			return nil, err
		}
		mimeType, err := requireStringParam(params, "mime_type")
		if err != nil {
			return nil, err
		}
		parentFolderID := getStringParam(params, "parent_folder_id")
		return g.driveClient.UploadFile(ctx, name, content, mimeType, parentFolderID)

	case "drive.share_file":
		fileID, err := requireStringParam(params, "file_id")
		if err != nil {
			return nil, err
		}
		email, err := requireStringParam(params, "email")
		if err != nil {
			return nil, err
		}
		role := getStringParam(params, "role")
		return g.driveClient.ShareFile(ctx, fileID, email, role)

	// --- Google Calendar ---
	case "calendar.list_events":
		return g.calendarClient.ListEvents(ctx,
			getStringParam(params, "calendar_id"),
			getStringParam(params, "time_min"),
			getStringParam(params, "time_max"),
			int64(getIntParam(params, "max_results")),
			getStringParam(params, "page_token"),
		)

	case "calendar.get_event":
		eventID, err := requireStringParam(params, "event_id")
		if err != nil {
			return nil, err
		}
		return g.calendarClient.GetEvent(ctx, getStringParam(params, "calendar_id"), eventID)

	case "calendar.create_event":
		summary, err := requireStringParam(params, "summary")
		if err != nil {
			return nil, err
		}
		startTime, err := requireStringParam(params, "start")
		if err != nil {
			return nil, err
		}
		endTime, err := requireStringParam(params, "end")
		if err != nil {
			return nil, err
		}
		return g.calendarClient.CreateEvent(ctx,
			getStringParam(params, "calendar_id"),
			summary,
			getStringParam(params, "location"),
			getStringParam(params, "description"),
			startTime,
			endTime,
			getStringSliceParam(params, "attendees"),
		)

	case "calendar.update_event":
		eventID, err := requireStringParam(params, "event_id")
		if err != nil {
			return nil, err
		}
		return g.calendarClient.UpdateEvent(ctx,
			getStringParam(params, "calendar_id"),
			eventID,
			getStringParam(params, "summary"),
			getStringParam(params, "location"),
			getStringParam(params, "description"),
			getStringParam(params, "start"),
			getStringParam(params, "end"),
			getStringSliceParam(params, "attendees"),
		)

	case "calendar.delete_event":
		eventID, err := requireStringParam(params, "event_id")
		if err != nil {
			return nil, err
		}
		return nil, g.calendarClient.DeleteEvent(ctx, getStringParam(params, "calendar_id"), eventID)

	// --- Google People/Contacts ---
	case "people.list_contacts":
		return g.peopleClient.ListContacts(ctx,
			int64(getIntParam(params, "page_size")),
			getStringParam(params, "page_token"),
		)

	case "people.get_contact":
		resourceName, err := requireStringParam(params, "resource_name")
		if err != nil {
			return nil, err
		}
		return g.peopleClient.GetContact(ctx, resourceName)

	case "people.create_contact":
		return g.peopleClient.CreateContact(ctx,
			getStringParam(params, "name"),
			getStringParam(params, "email"),
			getStringParam(params, "phone"),
		)

	case "people.update_contact":
		resourceName, err := requireStringParam(params, "resource_name")
		if err != nil {
			return nil, err
		}
		return g.peopleClient.UpdateContact(ctx,
			resourceName,
			getStringParam(params, "name"),
			getStringParam(params, "email"),
			getStringParam(params, "phone"),
		)

	case "people.delete_contact":
		resourceName, err := requireStringParam(params, "resource_name")
		if err != nil {
			return nil, err
		}
		return nil, g.peopleClient.DeleteContact(ctx, resourceName)

	// --- Google Sheets ---
	case "sheets.get_spreadsheet":
		spreadsheetID, err := requireStringParam(params, "spreadsheet_id")
		if err != nil {
			return nil, err
		}
		return g.sheetsClient.GetSpreadsheet(ctx, spreadsheetID)

	case "sheets.read_range":
		spreadsheetID, err := requireStringParam(params, "spreadsheet_id")
		if err != nil {
			return nil, err
		}
		readRange, err := requireStringParam(params, "range")
		if err != nil {
			return nil, err
		}
		return g.sheetsClient.ReadRange(ctx, spreadsheetID, readRange)

	case "sheets.write_range":
		spreadsheetID, err := requireStringParam(params, "spreadsheet_id")
		if err != nil {
			return nil, err
		}
		writeRange, err := requireStringParam(params, "range")
		if err != nil {
			return nil, err
		}
		valuesJSON, err := requireStringParam(params, "values")
		if err != nil {
			return nil, err
		}
		var values [][]interface{}
		if err := json.Unmarshal([]byte(valuesJSON), &values); err != nil {
			return nil, fmt.Errorf("google connector: parsing values JSON: %w", err)
		}
		return g.sheetsClient.WriteRange(ctx, spreadsheetID, writeRange, values)

	case "sheets.create_spreadsheet":
		title, err := requireStringParam(params, "title")
		if err != nil {
			return nil, err
		}
		return g.sheetsClient.CreateSpreadsheet(ctx, title)

	// --- Google Docs ---
	case "docs.get_document":
		documentID, err := requireStringParam(params, "document_id")
		if err != nil {
			return nil, err
		}
		return g.docsClient.GetDocument(ctx, documentID)

	case "docs.list_documents":
		return g.docsClient.ListDocuments(ctx,
			int64(getIntParam(params, "page_size")),
			getStringParam(params, "page_token"),
		)

	case "docs.create_document":
		title, err := requireStringParam(params, "title")
		if err != nil {
			return nil, err
		}
		return g.docsClient.CreateDocument(ctx, title)

	case "docs.update_document":
		documentID, err := requireStringParam(params, "document_id")
		if err != nil {
			return nil, err
		}
		requestsJSON, err := requireStringParam(params, "requests")
		if err != nil {
			return nil, err
		}
		return g.docsClient.UpdateDocument(ctx, documentID, requestsJSON)

	default:
		return nil, fmt.Errorf("google connector: unknown operation %q", op)
	}
}

// Validate checks that the credentials are valid by listing 1 email.
func (g *GoogleConnector) Validate(ctx context.Context) error {
	_, err := g.client.ListEmails(ctx, gmailclient.SearchQuery{MaxResults: 1})
	if err != nil {
		return fmt.Errorf("gmail connector: validation failed: %w", err)
	}
	return nil
}

// --- param helper functions ---

func getStringParam(params map[string]any, key string) string {
	if params == nil {
		return ""
	}
	v, _ := params[key].(string)
	return v
}

func requireStringParam(params map[string]any, key string) (string, error) {
	v := getStringParam(params, key)
	if v == "" {
		return "", fmt.Errorf("gmail connector: missing required parameter %q", key)
	}
	return v, nil
}

func getIntParam(params map[string]any, key string) int {
	if params == nil {
		return 0
	}
	switch v := params[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

func getStringSliceParam(params map[string]any, key string) []string {
	if params == nil {
		return nil
	}
	// Direct []string assertion
	if v, ok := params[key].([]string); ok {
		return v
	}
	// Handle []any (common when decoded from JSON)
	if v, ok := params[key].([]any); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}
