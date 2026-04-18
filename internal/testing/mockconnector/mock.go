// Package mockconnector provides a configurable mock implementation of
// connector.Connector for use in tests. It returns canned responses and
// records calls for assertion.
package mockconnector

import (
	"context"
	"fmt"
	"sync"

	"github.com/murbard/Sieve/internal/connector"
)

// Call records a single operation invocation.
type Call struct {
	Operation string
	Params    map[string]any
}

// Mock implements connector.Connector with configurable behavior.
type Mock struct {
	ConnType   string
	Ops        []connector.OperationDef
	Responses  map[string]any   // operation -> response
	Errors     map[string]error // operation -> error
	Calls      []Call
	mu         sync.Mutex
}

// New creates a Mock with the given type and default Google-like operations
// covering Gmail, Drive, Calendar, People, Sheets, and Docs.
func New(connType string) *Mock {
	return &Mock{
		ConnType:  connType,
		Responses: make(map[string]any),
		Errors:    make(map[string]error),
		Ops: []connector.OperationDef{
			// --- Gmail (13 operations) ---
			{Name: "list_emails", Description: "List emails", ReadOnly: true, Params: map[string]connector.ParamDef{
				"query":       {Type: "string", Required: false},
				"max_results": {Type: "int", Required: false},
				"page_token":  {Type: "string", Required: false},
			}},
			{Name: "read_email", Description: "Read an email", ReadOnly: true, Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Required: true},
			}},
			{Name: "read_thread", Description: "Read all messages in a thread", ReadOnly: true, Params: map[string]connector.ParamDef{
				"thread_id": {Type: "string", Required: true},
			}},
			{Name: "create_draft", Description: "Create a new email draft", ReadOnly: false, Params: map[string]connector.ParamDef{
				"to":       {Type: "[]string", Required: false},
				"cc":       {Type: "[]string", Required: false},
				"subject":  {Type: "string", Required: false},
				"body":     {Type: "string", Required: false},
				"reply_to": {Type: "string", Required: false},
			}},
			{Name: "update_draft", Description: "Update an existing email draft", ReadOnly: false, Params: map[string]connector.ParamDef{
				"draft_id": {Type: "string", Required: true},
				"to":       {Type: "[]string", Required: false},
				"cc":       {Type: "[]string", Required: false},
				"subject":  {Type: "string", Required: false},
				"body":     {Type: "string", Required: false},
			}},
			{Name: "send_email", Description: "Send an email", ReadOnly: false, Params: map[string]connector.ParamDef{
				"to":       {Type: "[]string", Required: true},
				"subject":  {Type: "string", Required: true},
				"body":     {Type: "string", Required: true},
				"cc":       {Type: "[]string", Required: false},
				"reply_to": {Type: "string", Required: false},
			}},
			{Name: "send_draft", Description: "Send an existing draft", ReadOnly: false, Params: map[string]connector.ParamDef{
				"draft_id": {Type: "string", Required: true},
			}},
			{Name: "reply", Description: "Reply to an existing email", ReadOnly: false, Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Required: true},
				"body":       {Type: "string", Required: true},
				"to":         {Type: "[]string", Required: false},
				"cc":         {Type: "[]string", Required: false},
				"subject":    {Type: "string", Required: false},
			}},
			{Name: "add_label", Description: "Add a label to a message", ReadOnly: false, Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Required: true},
				"label_id":   {Type: "string", Required: true},
			}},
			{Name: "remove_label", Description: "Remove a label from a message", ReadOnly: false, Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Required: true},
				"label_id":   {Type: "string", Required: true},
			}},
			{Name: "archive", Description: "Archive a message", ReadOnly: false, Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Required: true},
			}},
			{Name: "list_labels", Description: "List labels", ReadOnly: true},
			{Name: "get_attachment", Description: "Download an email attachment", ReadOnly: true, Params: map[string]connector.ParamDef{
				"message_id":    {Type: "string", Required: true},
				"attachment_id": {Type: "string", Required: true},
			}},

			// --- Google Drive (5 operations) ---
			{Name: "drive.list_files", Description: "List files in Google Drive", ReadOnly: true, Params: map[string]connector.ParamDef{
				"query":      {Type: "string", Required: false},
				"page_size":  {Type: "int", Required: false},
				"page_token": {Type: "string", Required: false},
			}},
			{Name: "drive.get_file", Description: "Get metadata for a single file", ReadOnly: true, Params: map[string]connector.ParamDef{
				"file_id": {Type: "string", Required: true},
			}},
			{Name: "drive.download_file", Description: "Download a file from Drive", ReadOnly: true, Params: map[string]connector.ParamDef{
				"file_id": {Type: "string", Required: true},
			}},
			{Name: "drive.upload_file", Description: "Upload a file to Drive", ReadOnly: false, Params: map[string]connector.ParamDef{
				"name":             {Type: "string", Required: true},
				"content":          {Type: "string", Required: true},
				"mime_type":        {Type: "string", Required: true},
				"parent_folder_id": {Type: "string", Required: false},
			}},
			{Name: "drive.share_file", Description: "Share a file with a user", ReadOnly: false, Params: map[string]connector.ParamDef{
				"file_id": {Type: "string", Required: true},
				"email":   {Type: "string", Required: true},
				"role":    {Type: "string", Required: false},
			}},

			// --- Google Calendar (5 operations) ---
			{Name: "calendar.list_events", Description: "List calendar events", ReadOnly: true, Params: map[string]connector.ParamDef{
				"calendar_id": {Type: "string", Required: false},
				"time_min":    {Type: "string", Required: false},
				"time_max":    {Type: "string", Required: false},
				"max_results": {Type: "int", Required: false},
				"page_token":  {Type: "string", Required: false},
			}},
			{Name: "calendar.get_event", Description: "Get a single calendar event", ReadOnly: true, Params: map[string]connector.ParamDef{
				"calendar_id": {Type: "string", Required: false},
				"event_id":    {Type: "string", Required: true},
			}},
			{Name: "calendar.create_event", Description: "Create a new calendar event", ReadOnly: false, Params: map[string]connector.ParamDef{
				"calendar_id": {Type: "string", Required: false},
				"summary":     {Type: "string", Required: true},
				"start":       {Type: "string", Required: true},
				"end":         {Type: "string", Required: true},
				"location":    {Type: "string", Required: false},
				"description": {Type: "string", Required: false},
				"attendees":   {Type: "[]string", Required: false},
			}},
			{Name: "calendar.update_event", Description: "Update a calendar event", ReadOnly: false, Params: map[string]connector.ParamDef{
				"calendar_id": {Type: "string", Required: false},
				"event_id":    {Type: "string", Required: true},
				"summary":     {Type: "string", Required: false},
				"start":       {Type: "string", Required: false},
				"end":         {Type: "string", Required: false},
				"location":    {Type: "string", Required: false},
				"description": {Type: "string", Required: false},
				"attendees":   {Type: "[]string", Required: false},
			}},
			{Name: "calendar.delete_event", Description: "Delete a calendar event", ReadOnly: false, Params: map[string]connector.ParamDef{
				"calendar_id": {Type: "string", Required: false},
				"event_id":    {Type: "string", Required: true},
			}},

			// --- Google People/Contacts (5 operations) ---
			{Name: "people.list_contacts", Description: "List contacts", ReadOnly: true, Params: map[string]connector.ParamDef{
				"page_size":  {Type: "int", Required: false},
				"page_token": {Type: "string", Required: false},
			}},
			{Name: "people.get_contact", Description: "Get a single contact", ReadOnly: true, Params: map[string]connector.ParamDef{
				"resource_name": {Type: "string", Required: true},
			}},
			{Name: "people.create_contact", Description: "Create a new contact", ReadOnly: false, Params: map[string]connector.ParamDef{
				"name":  {Type: "string", Required: false},
				"email": {Type: "string", Required: false},
				"phone": {Type: "string", Required: false},
			}},
			{Name: "people.update_contact", Description: "Update an existing contact", ReadOnly: false, Params: map[string]connector.ParamDef{
				"resource_name": {Type: "string", Required: true},
				"name":          {Type: "string", Required: false},
				"email":         {Type: "string", Required: false},
				"phone":         {Type: "string", Required: false},
			}},
			{Name: "people.delete_contact", Description: "Delete a contact", ReadOnly: false, Params: map[string]connector.ParamDef{
				"resource_name": {Type: "string", Required: true},
			}},

			// --- Google Sheets (4 operations) ---
			{Name: "sheets.get_spreadsheet", Description: "Get spreadsheet metadata", ReadOnly: true, Params: map[string]connector.ParamDef{
				"spreadsheet_id": {Type: "string", Required: true},
			}},
			{Name: "sheets.read_range", Description: "Read values from a range", ReadOnly: true, Params: map[string]connector.ParamDef{
				"spreadsheet_id": {Type: "string", Required: true},
				"range":          {Type: "string", Required: true},
			}},
			{Name: "sheets.write_range", Description: "Write values to a range", ReadOnly: false, Params: map[string]connector.ParamDef{
				"spreadsheet_id": {Type: "string", Required: true},
				"range":          {Type: "string", Required: true},
				"values":         {Type: "string", Required: true},
			}},
			{Name: "sheets.create_spreadsheet", Description: "Create a new spreadsheet", ReadOnly: false, Params: map[string]connector.ParamDef{
				"title": {Type: "string", Required: true},
			}},

			// --- Google Docs (4 operations) ---
			{Name: "docs.get_document", Description: "Get a Google Doc with content", ReadOnly: true, Params: map[string]connector.ParamDef{
				"document_id": {Type: "string", Required: true},
			}},
			{Name: "docs.list_documents", Description: "List Google Docs", ReadOnly: true, Params: map[string]connector.ParamDef{
				"page_size":  {Type: "int", Required: false},
				"page_token": {Type: "string", Required: false},
			}},
			{Name: "docs.create_document", Description: "Create a new Google Doc", ReadOnly: false, Params: map[string]connector.ParamDef{
				"title": {Type: "string", Required: true},
			}},
			{Name: "docs.update_document", Description: "Update a Google Doc", ReadOnly: false, Params: map[string]connector.ParamDef{
				"document_id": {Type: "string", Required: true},
				"requests":    {Type: "string", Required: true},
			}},
		},
	}
}

// NewMinimal creates a Mock with no operations.
func NewMinimal(connType string) *Mock {
	return &Mock{
		ConnType:  connType,
		Responses: make(map[string]any),
		Errors:    make(map[string]error),
	}
}

// SetResponse configures the response for an operation.
func (m *Mock) SetResponse(op string, resp any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Responses[op] = resp
}

// SetError configures an error for an operation.
func (m *Mock) SetError(op string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Errors[op] = err
}

// GetCalls returns all recorded calls.
func (m *Mock) GetCalls() []Call {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Call{}, m.Calls...)
}

// Reset clears recorded calls.
func (m *Mock) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = nil
}

// --- connector.Connector interface ---

func (m *Mock) Type() string { return m.ConnType }

func (m *Mock) Operations() []connector.OperationDef { return m.Ops }

func (m *Mock) Execute(_ context.Context, op string, params map[string]any) (any, error) {
	m.mu.Lock()
	m.Calls = append(m.Calls, Call{Operation: op, Params: params})
	resp := m.Responses[op]
	err := m.Errors[op]
	m.mu.Unlock()

	if err != nil {
		return nil, err
	}
	if resp != nil {
		return resp, nil
	}

	// Default responses for common operations.
	switch op {

	// --- Gmail defaults ---
	case "list_emails":
		return map[string]any{
			"emails": []any{
				map[string]any{
					"id": "msg1", "thread_id": "t1", "from": "sender@test.com",
					"to": []string{"me@test.com"}, "subject": "Test Email",
					"body": "Hello world", "labels": []string{"INBOX"},
					"snippet": "Hello world", "has_attachment": false,
				},
			},
			"total":           1,
			"next_page_token": "",
		}, nil
	case "read_email":
		return map[string]any{
			"id": params["message_id"], "thread_id": "t1", "from": "sender@test.com",
			"to": []string{"me@test.com"}, "subject": "Test Email",
			"body": "Hello world", "labels": []string{"INBOX"},
		}, nil
	case "read_thread":
		return map[string]any{
			"thread_id": params["thread_id"],
			"messages": []any{
				map[string]any{"id": "msg1", "from": "sender@test.com", "body": "Hello"},
			},
		}, nil
	case "create_draft", "update_draft":
		return map[string]any{"id": "draft-001", "message": map[string]any{"id": "msg-draft-001"}}, nil
	case "send_email":
		return map[string]any{"id": "sent1", "thread_id": "t2"}, nil
	case "send_draft":
		return map[string]any{"id": "sent-draft-001", "thread_id": "t3"}, nil
	case "reply":
		return map[string]any{"id": "reply-001", "thread_id": "t1"}, nil
	case "add_label", "remove_label", "archive":
		return map[string]any{"status": "ok"}, nil
	case "list_labels":
		return []any{
			map[string]any{"id": "INBOX", "name": "INBOX"},
			map[string]any{"id": "SENT", "name": "SENT"},
		}, nil
	case "get_attachment":
		return map[string]any{
			"id":        params["attachment_id"],
			"filename":  "report.pdf",
			"mime_type": "application/pdf",
			"size":      int64(1024),
		}, nil

	// --- Google Drive defaults ---
	case "drive.list_files":
		return map[string]any{
			"files": []any{
				map[string]any{
					"id": "file-001", "name": "Q3 Report.pdf",
					"mime_type": "application/pdf", "size": float64(204800),
					"created_time": "2026-03-01T10:00:00Z", "modified_time": "2026-03-15T14:30:00Z",
					"owners": []string{"alice@company.com"},
				},
				map[string]any{
					"id": "file-002", "name": "Budget 2026.xlsx",
					"mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
					"size": float64(51200),
					"created_time": "2026-02-20T08:00:00Z", "modified_time": "2026-03-10T11:00:00Z",
					"owners": []string{"bob@company.com"},
				},
			},
			"next_page_token": "",
		}, nil
	case "drive.get_file":
		return map[string]any{
			"id": params["file_id"], "name": "Q3 Report.pdf",
			"mime_type": "application/pdf", "size": float64(204800),
			"created_time": "2026-03-01T10:00:00Z", "modified_time": "2026-03-15T14:30:00Z",
			"owners": []string{"alice@company.com"},
		}, nil
	case "drive.download_file":
		return map[string]any{
			"content": "SGVsbG8gV29ybGQ=", "filename": "hello.txt",
			"mime_type": "text/plain", "size": int64(11),
		}, nil
	case "drive.upload_file":
		return map[string]any{
			"id": "file-new-001", "name": params["name"],
			"mime_type": params["mime_type"], "size": float64(1024),
			"created_time": "2026-04-13T12:00:00Z", "modified_time": "2026-04-13T12:00:00Z",
		}, nil
	case "drive.share_file":
		return map[string]any{
			"permission_id": "perm-001", "role": "reader",
			"type": "user", "email": params["email"],
		}, nil

	// --- Google Calendar defaults ---
	case "calendar.list_events":
		return map[string]any{
			"events": []any{
				map[string]any{
					"id": "evt-001", "summary": "Team Standup",
					"start": "2026-04-13T09:00:00Z", "end": "2026-04-13T09:30:00Z",
					"location": "Room 42", "status": "confirmed",
					"attendees": []string{"alice@company.com", "bob@company.com"},
				},
				map[string]any{
					"id": "evt-002", "summary": "Sprint Review",
					"start": "2026-04-13T14:00:00Z", "end": "2026-04-13T15:00:00Z",
					"status": "confirmed",
				},
			},
			"next_page_token": "",
		}, nil
	case "calendar.get_event":
		return map[string]any{
			"id": params["event_id"], "summary": "Team Standup",
			"start": "2026-04-13T09:00:00Z", "end": "2026-04-13T09:30:00Z",
			"location": "Room 42", "status": "confirmed",
		}, nil
	case "calendar.create_event":
		return map[string]any{
			"id": "evt-new-001", "summary": params["summary"],
			"start": params["start"], "end": params["end"],
			"status": "confirmed",
		}, nil
	case "calendar.update_event":
		return map[string]any{
			"id": params["event_id"], "summary": "Updated Event",
			"status": "confirmed",
		}, nil
	case "calendar.delete_event":
		return map[string]any{"status": "ok", "deleted_id": params["event_id"]}, nil

	// --- Google People/Contacts defaults ---
	case "people.list_contacts":
		return map[string]any{
			"contacts": []any{
				map[string]any{
					"resource_name":   "people/c1001",
					"names":           []string{"Alice Smith"},
					"email_addresses": []string{"alice@company.com"},
					"phone_numbers":   []string{"+1-555-0101"},
				},
				map[string]any{
					"resource_name":   "people/c1002",
					"names":           []string{"Bob Jones"},
					"email_addresses": []string{"bob@company.com"},
					"phone_numbers":   []string{"+1-555-0102"},
				},
			},
			"total_people":    float64(2),
			"next_page_token": "",
		}, nil
	case "people.get_contact":
		return map[string]any{
			"resource_name":   params["resource_name"],
			"names":           []string{"Alice Smith"},
			"email_addresses": []string{"alice@company.com"},
			"phone_numbers":   []string{"+1-555-0101"},
		}, nil
	case "people.create_contact":
		return map[string]any{
			"resource_name":   "people/c2001",
			"names":           []string{fmt.Sprintf("%v", params["name"])},
			"email_addresses": []string{fmt.Sprintf("%v", params["email"])},
		}, nil
	case "people.update_contact":
		return map[string]any{
			"resource_name": params["resource_name"],
			"names":         []string{"Updated Name"},
		}, nil
	case "people.delete_contact":
		return map[string]any{"status": "ok", "deleted": params["resource_name"]}, nil

	// --- Google Sheets defaults ---
	case "sheets.get_spreadsheet":
		return map[string]any{
			"id": params["spreadsheet_id"], "title": "Budget 2026",
			"sheets": []any{
				map[string]any{"title": "Sheet1", "index": float64(0)},
				map[string]any{"title": "Summary", "index": float64(1)},
			},
		}, nil
	case "sheets.read_range":
		return map[string]any{
			"range": params["range"],
			"values": []any{
				[]any{"Name", "Amount", "Date"},
				[]any{"Alice", "$1000", "2026-01-15"},
				[]any{"Bob", "$2000", "2026-02-20"},
			},
		}, nil
	case "sheets.write_range":
		return map[string]any{
			"spreadsheet_id":  params["spreadsheet_id"],
			"updated_range":   params["range"],
			"updated_rows":    float64(2),
			"updated_columns": float64(3),
			"updated_cells":   float64(6),
		}, nil
	case "sheets.create_spreadsheet":
		return map[string]any{
			"id": "ss-new-001", "title": params["title"],
			"sheets": []any{
				map[string]any{"title": "Sheet1", "index": float64(0)},
			},
		}, nil

	// --- Google Docs defaults ---
	case "docs.get_document":
		return map[string]any{
			"document_id": params["document_id"],
			"title":       "Project Proposal",
			"body":        "This is the project proposal document.\n\nIt contains multiple paragraphs of text.",
		}, nil
	case "docs.list_documents":
		return map[string]any{
			"documents": []any{
				map[string]any{"id": "doc-001", "name": "Project Proposal", "created_time": "2026-03-01T10:00:00Z"},
				map[string]any{"id": "doc-002", "name": "Meeting Notes", "created_time": "2026-03-10T14:00:00Z"},
			},
			"next_page_token": "",
		}, nil
	case "docs.create_document":
		return map[string]any{
			"document_id": "doc-new-001",
			"title":       params["title"],
		}, nil
	case "docs.update_document":
		return map[string]any{
			"document_id": params["document_id"],
			"replies":     float64(1),
		}, nil

	default:
		return nil, fmt.Errorf("mock: operation %q not configured", op)
	}
}

func (m *Mock) Validate(_ context.Context) error { return nil }

// Factory returns a connector.Factory that always returns this mock.
func (m *Mock) Factory() connector.Factory {
	return func(config map[string]any) (connector.Connector, error) {
		return m, nil
	}
}

// Meta returns connector metadata for registration.
func (m *Mock) Meta() connector.ConnectorMeta {
	return connector.ConnectorMeta{
		Type:        m.ConnType,
		Name:        "Mock " + m.ConnType,
		Description: "Mock connector for testing",
		Category:    "Test",
	}
}
