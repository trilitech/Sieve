package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/murbard/Sieve/internal/api"
	"github.com/murbard/Sieve/internal/roles"
	"github.com/murbard/Sieve/internal/testing/testenv"
	"github.com/murbard/Sieve/internal/tokens"
)

// setupGoogleOps creates a test environment with an allow-all policy for
// Google operations (Drive, Calendar, People, Sheets, Docs). Returns the
// server URL, bearer token, and the test environment.
func setupGoogleOps(t *testing.T, policyConfig map[string]any) (string, string, *testenv.Env) {
	t.Helper()
	env := testenv.New(t)

	pol, err := env.Policies.Create("google-ops-policy", "rules", policyConfig)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	err = env.Connections.Add("google-conn", "mock", "Google Account", map[string]any{})
	if err != nil {
		t.Fatalf("add connection: %v", err)
	}

	role, err := env.Roles.Create("google-role", []roles.Binding{
		{ConnectionID: "google-conn", PolicyIDs: []string{pol.ID}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	tokResult, err := env.Tokens.Create(&tokens.CreateRequest{Name: "google-tok", RoleID: role.ID})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	router := api.NewRouter(env.Tokens, env.Connections, env.Policies, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	return srv.URL, tokResult.PlaintextToken, env
}

// allowAllPolicy returns a policy config that allows all operations.
func allowAllPolicy() map[string]any {
	return map[string]any{
		"rules": []any{
			map[string]any{
				"action": "allow",
			},
		},
		"default_action": "allow",
	}
}

// ---------- Drive operations ----------

func TestE2E_DriveListFiles(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/drive.list_files", tok, `{}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	files, ok := body["files"].([]any)
	if !ok {
		t.Fatalf("expected files array in response, got %v", body)
	}
	if len(files) == 0 {
		t.Fatal("expected at least one file in response")
	}

	firstFile, ok := files[0].(map[string]any)
	if !ok {
		t.Fatal("expected file to be a map")
	}
	if _, ok := firstFile["id"]; !ok {
		t.Fatal("expected file to have an 'id' field")
	}
	if _, ok := firstFile["name"]; !ok {
		t.Fatal("expected file to have a 'name' field")
	}
}

func TestE2E_DriveGetFile(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/drive.get_file", tok, `{"file_id":"file-abc-123"}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	fileID, _ := body["id"].(string)
	if fileID != "file-abc-123" {
		t.Fatalf("expected file_id 'file-abc-123' in response, got %q", fileID)
	}
}

func TestE2E_DriveUploadFile_Allowed(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	payload := `{"name":"test.txt","content":"SGVsbG8=","mime_type":"text/plain"}`
	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/drive.upload_file", tok, payload)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	if _, ok := body["id"]; !ok {
		t.Fatal("expected uploaded file to have an 'id'")
	}
}

func TestE2E_DriveUploadFile_Denied(t *testing.T) {
	// Policy that only allows read operations.
	readOnlyPolicy := map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"drive.list_files", "drive.get_file", "drive.download_file"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	}

	url, tok, _ := setupGoogleOps(t, readOnlyPolicy)

	payload := `{"name":"test.txt","content":"SGVsbG8=","mime_type":"text/plain"}`
	status, _ := apiPost(t, url+"/api/v1/connections/google-conn/ops/drive.upload_file", tok, payload)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for denied upload, got %d", status)
	}
}

func TestE2E_DriveDownloadFile(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/drive.download_file", tok, `{"file_id":"file-abc-123"}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	if _, ok := body["content"]; !ok {
		t.Fatal("expected downloaded file to have 'content'")
	}
}

func TestE2E_DriveShareFile(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	payload := `{"file_id":"file-abc-123","email":"bob@company.com","role":"reader"}`
	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/drive.share_file", tok, payload)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	email, _ := body["email"].(string)
	if email != "bob@company.com" {
		t.Fatalf("expected email 'bob@company.com' in share response, got %q", email)
	}
}

// ---------- Calendar operations ----------

func TestE2E_CalendarListEvents(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/calendar.list_events", tok, `{}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	events, ok := body["events"].([]any)
	if !ok {
		t.Fatalf("expected events array in response, got %v", body)
	}
	if len(events) == 0 {
		t.Fatal("expected at least one event")
	}

	firstEvent, ok := events[0].(map[string]any)
	if !ok {
		t.Fatal("expected event to be a map")
	}
	if _, ok := firstEvent["summary"]; !ok {
		t.Fatal("expected event to have a 'summary' field")
	}
}

func TestE2E_CalendarGetEvent(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/calendar.get_event", tok, `{"event_id":"evt-abc"}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	eventID, _ := body["id"].(string)
	if eventID != "evt-abc" {
		t.Fatalf("expected event_id 'evt-abc', got %q", eventID)
	}
}

func TestE2E_CalendarCreateEvent_Allowed(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	payload := `{"summary":"Lunch","start":"2026-04-13T12:00:00Z","end":"2026-04-13T13:00:00Z"}`
	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/calendar.create_event", tok, payload)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	if _, ok := body["id"]; !ok {
		t.Fatal("expected created event to have an 'id'")
	}
}

func TestE2E_CalendarCreateEvent_Denied(t *testing.T) {
	calReadOnlyPolicy := map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"calendar.list_events", "calendar.get_event"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	}

	url, tok, _ := setupGoogleOps(t, calReadOnlyPolicy)

	payload := `{"summary":"Lunch","start":"2026-04-13T12:00:00Z","end":"2026-04-13T13:00:00Z"}`
	status, _ := apiPost(t, url+"/api/v1/connections/google-conn/ops/calendar.create_event", tok, payload)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for denied calendar create, got %d", status)
	}
}

func TestE2E_CalendarDeleteEvent(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/calendar.delete_event", tok, `{"event_id":"evt-del-001"}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	_ = body // delete returns confirmation
}

// ---------- People/Contacts operations ----------

func TestE2E_PeopleListContacts(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/people.list_contacts", tok, `{}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	contacts, ok := body["contacts"].([]any)
	if !ok {
		t.Fatalf("expected contacts array, got %v", body)
	}
	if len(contacts) == 0 {
		t.Fatal("expected at least one contact")
	}
}

func TestE2E_PeopleGetContact(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/people.get_contact", tok, `{"resource_name":"people/c1001"}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	rn, _ := body["resource_name"].(string)
	if rn != "people/c1001" {
		t.Fatalf("expected resource_name 'people/c1001', got %q", rn)
	}
}

func TestE2E_PeopleCreateContact(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	payload := `{"name":"Charlie Brown","email":"charlie@example.com","phone":"+1-555-0199"}`
	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/people.create_contact", tok, payload)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	if _, ok := body["resource_name"]; !ok {
		t.Fatal("expected created contact to have 'resource_name'")
	}
}

func TestE2E_PeopleDeleteContact(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/people.delete_contact", tok, `{"resource_name":"people/c1001"}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	_ = body
}

// ---------- Sheets operations ----------

func TestE2E_SheetsReadRange(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	payload := `{"spreadsheet_id":"ss-001","range":"Sheet1!A1:C3"}`
	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/sheets.read_range", tok, payload)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	values, ok := body["values"].([]any)
	if !ok {
		t.Fatalf("expected values array, got %v", body)
	}
	if len(values) == 0 {
		t.Fatal("expected at least one row of values")
	}
}

func TestE2E_SheetsGetSpreadsheet(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	payload := `{"spreadsheet_id":"ss-001"}`
	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/sheets.get_spreadsheet", tok, payload)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	if _, ok := body["title"]; !ok {
		t.Fatal("expected spreadsheet to have 'title'")
	}
	if _, ok := body["sheets"]; !ok {
		t.Fatal("expected spreadsheet to have 'sheets'")
	}
}

func TestE2E_SheetsWriteRange(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	payload := `{"spreadsheet_id":"ss-001","range":"Sheet1!A1:B2","values":"[[\"x\",\"y\"],[\"1\",\"2\"]]"}`
	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/sheets.write_range", tok, payload)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	updatedCells, ok := body["updated_cells"].(float64)
	if !ok || updatedCells == 0 {
		t.Fatalf("expected non-zero updated_cells, got %v", body["updated_cells"])
	}
}

func TestE2E_SheetsCreateSpreadsheet(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	payload := `{"title":"New Budget"}`
	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/sheets.create_spreadsheet", tok, payload)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	if _, ok := body["id"]; !ok {
		t.Fatal("expected created spreadsheet to have 'id'")
	}
}

// ---------- Docs operations ----------

func TestE2E_DocsGetDocument(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	payload := `{"document_id":"doc-abc-123"}`
	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/docs.get_document", tok, payload)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	docID, _ := body["document_id"].(string)
	if docID != "doc-abc-123" {
		t.Fatalf("expected document_id 'doc-abc-123', got %q", docID)
	}
	if _, ok := body["title"]; !ok {
		t.Fatal("expected document to have 'title'")
	}
	if _, ok := body["body"]; !ok {
		t.Fatal("expected document to have 'body'")
	}
}

func TestE2E_DocsListDocuments(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/docs.list_documents", tok, `{}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	docs, ok := body["documents"].([]any)
	if !ok {
		t.Fatalf("expected documents array, got %v", body)
	}
	if len(docs) == 0 {
		t.Fatal("expected at least one document")
	}
}

func TestE2E_DocsCreateDocument(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	payload := `{"title":"New Document"}`
	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/docs.create_document", tok, payload)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	if _, ok := body["document_id"]; !ok {
		t.Fatal("expected created document to have 'document_id'")
	}
}

func TestE2E_DocsUpdateDocument(t *testing.T) {
	url, tok, _ := setupGoogleOps(t, allowAllPolicy())

	payload := `{"document_id":"doc-abc-123","requests":"[{\"insertText\":{\"text\":\"Hello\",\"location\":{\"index\":1}}}]"}`
	status, body := apiPost(t, url+"/api/v1/connections/google-conn/ops/docs.update_document", tok, payload)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}

	docID, _ := body["document_id"].(string)
	if docID != "doc-abc-123" {
		t.Fatalf("expected document_id 'doc-abc-123', got %q", docID)
	}
}

// ---------- Policy enforcement for new operations ----------

func TestE2E_DriveReadOnlyPolicy(t *testing.T) {
	// Policy allows only drive.list_files and drive.get_file.
	driveReadOnly := map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"drive.list_files", "drive.get_file"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	}

	url, tok, _ := setupGoogleOps(t, driveReadOnly)

	// Allowed: drive.list_files
	status, _ := apiPost(t, url+"/api/v1/connections/google-conn/ops/drive.list_files", tok, `{}`)
	if status != http.StatusOK {
		t.Fatalf("drive.list_files should be allowed, got %d", status)
	}

	// Allowed: drive.get_file
	status, _ = apiPost(t, url+"/api/v1/connections/google-conn/ops/drive.get_file", tok, `{"file_id":"f1"}`)
	if status != http.StatusOK {
		t.Fatalf("drive.get_file should be allowed, got %d", status)
	}

	// Denied: drive.upload_file
	status, _ = apiPost(t, url+"/api/v1/connections/google-conn/ops/drive.upload_file", tok,
		`{"name":"x.txt","content":"AA==","mime_type":"text/plain"}`)
	if status != http.StatusForbidden {
		t.Fatalf("drive.upload_file should be denied, got %d", status)
	}

	// Denied: drive.share_file
	status, _ = apiPost(t, url+"/api/v1/connections/google-conn/ops/drive.share_file", tok,
		`{"file_id":"f1","email":"x@y.com"}`)
	if status != http.StatusForbidden {
		t.Fatalf("drive.share_file should be denied, got %d", status)
	}

	// Denied: drive.download_file
	status, _ = apiPost(t, url+"/api/v1/connections/google-conn/ops/drive.download_file", tok,
		`{"file_id":"f1"}`)
	if status != http.StatusForbidden {
		t.Fatalf("drive.download_file should be denied, got %d", status)
	}

	// Denied: calendar operations
	status, _ = apiPost(t, url+"/api/v1/connections/google-conn/ops/calendar.list_events", tok, `{}`)
	if status != http.StatusForbidden {
		t.Fatalf("calendar.list_events should be denied under drive-only policy, got %d", status)
	}
}

func TestE2E_MixedGooglePolicy(t *testing.T) {
	// Allow Drive reads + Calendar reads, deny everything else.
	mixedPolicy := map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"drive.list_files", "drive.get_file", "calendar.list_events", "calendar.get_event"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
	}

	url, tok, _ := setupGoogleOps(t, mixedPolicy)

	// Allowed
	status, _ := apiPost(t, url+"/api/v1/connections/google-conn/ops/drive.list_files", tok, `{}`)
	if status != http.StatusOK {
		t.Fatalf("drive.list_files should be allowed, got %d", status)
	}
	status, _ = apiPost(t, url+"/api/v1/connections/google-conn/ops/calendar.list_events", tok, `{}`)
	if status != http.StatusOK {
		t.Fatalf("calendar.list_events should be allowed, got %d", status)
	}

	// Denied
	status, _ = apiPost(t, url+"/api/v1/connections/google-conn/ops/people.list_contacts", tok, `{}`)
	if status != http.StatusForbidden {
		t.Fatalf("people.list_contacts should be denied, got %d", status)
	}
	status, _ = apiPost(t, url+"/api/v1/connections/google-conn/ops/sheets.read_range", tok,
		`{"spreadsheet_id":"ss1","range":"A1:B2"}`)
	if status != http.StatusForbidden {
		t.Fatalf("sheets.read_range should be denied, got %d", status)
	}
}

// ---------- Mock connector records calls correctly ----------

func TestE2E_MockRecordsDriveCallParams(t *testing.T) {
	url, tok, env := setupGoogleOps(t, allowAllPolicy())

	payload := `{"file_id":"file-xyz-789"}`
	status, _ := apiPost(t, url+"/api/v1/connections/google-conn/ops/drive.get_file", tok, payload)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}

	calls := env.Mock.GetCalls()
	found := false
	for _, c := range calls {
		if c.Operation == "drive.get_file" {
			found = true
			if c.Params["file_id"] != "file-xyz-789" {
				t.Fatalf("expected file_id 'file-xyz-789' in params, got %v", c.Params["file_id"])
			}
		}
	}
	if !found {
		t.Fatal("mock did not record a drive.get_file call")
	}
}

func TestE2E_MockRecordsCalendarCallParams(t *testing.T) {
	url, tok, env := setupGoogleOps(t, allowAllPolicy())

	payload := `{"summary":"Test Meeting","start":"2026-04-13T10:00:00Z","end":"2026-04-13T11:00:00Z","location":"Room A"}`
	status, _ := apiPost(t, url+"/api/v1/connections/google-conn/ops/calendar.create_event", tok, payload)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}

	calls := env.Mock.GetCalls()
	found := false
	for _, c := range calls {
		if c.Operation == "calendar.create_event" {
			found = true
			if c.Params["summary"] != "Test Meeting" {
				t.Fatalf("expected summary 'Test Meeting', got %v", c.Params["summary"])
			}
			if c.Params["location"] != "Room A" {
				t.Fatalf("expected location 'Room A', got %v", c.Params["location"])
			}
		}
	}
	if !found {
		t.Fatal("mock did not record a calendar.create_event call")
	}
}

// ---------- Verify operations count ----------

func TestE2E_MockOperationsCount(t *testing.T) {
	env := testenv.New(t)
	ops := env.Mock.Operations()

	// Count operations by category.
	gmailCount := 0
	driveCount := 0
	calendarCount := 0
	peopleCount := 0
	sheetsCount := 0
	docsCount := 0

	for _, op := range ops {
		switch {
		case strings.HasPrefix(op.Name, "drive."):
			driveCount++
		case strings.HasPrefix(op.Name, "calendar."):
			calendarCount++
		case strings.HasPrefix(op.Name, "people."):
			peopleCount++
		case strings.HasPrefix(op.Name, "sheets."):
			sheetsCount++
		case strings.HasPrefix(op.Name, "docs."):
			docsCount++
		default:
			gmailCount++
		}
	}

	// Verify: 13 Gmail + 5 Drive + 5 Calendar + 5 People + 4 Sheets + 4 Docs = 36
	if len(ops) != 36 {
		t.Fatalf("expected 36 total operations, got %d", len(ops))
	}
	if gmailCount != 13 {
		t.Fatalf("expected 13 Gmail operations, got %d", gmailCount)
	}
	if driveCount != 5 {
		t.Fatalf("expected 5 Drive operations, got %d", driveCount)
	}
	if calendarCount != 5 {
		t.Fatalf("expected 5 Calendar operations, got %d", calendarCount)
	}
	if peopleCount != 5 {
		t.Fatalf("expected 5 People operations, got %d", peopleCount)
	}
	if sheetsCount != 4 {
		t.Fatalf("expected 4 Sheets operations, got %d", sheetsCount)
	}
	if docsCount != 4 {
		t.Fatalf("expected 4 Docs operations, got %d", docsCount)
	}

	// Verify all expected operation names are present.
	opNames := make(map[string]bool)
	for _, op := range ops {
		opNames[op.Name] = true
	}

	expectedOps := []string{
		// Gmail
		"list_emails", "read_email", "read_thread", "create_draft", "update_draft",
		"send_email", "send_draft", "reply", "add_label", "remove_label",
		"archive", "list_labels", "get_attachment",
		// Drive
		"drive.list_files", "drive.get_file", "drive.download_file",
		"drive.upload_file", "drive.share_file",
		// Calendar
		"calendar.list_events", "calendar.get_event", "calendar.create_event",
		"calendar.update_event", "calendar.delete_event",
		// People
		"people.list_contacts", "people.get_contact", "people.create_contact",
		"people.update_contact", "people.delete_contact",
		// Sheets
		"sheets.get_spreadsheet", "sheets.read_range", "sheets.write_range",
		"sheets.create_spreadsheet",
		// Docs
		"docs.get_document", "docs.list_documents", "docs.create_document",
		"docs.update_document",
	}

	for _, name := range expectedOps {
		if !opNames[name] {
			t.Fatalf("missing expected operation %q", name)
		}
	}
}

// ---------- Verify read-only flags ----------

func TestE2E_MockOperationsReadOnlyFlags(t *testing.T) {
	env := testenv.New(t)
	ops := env.Mock.Operations()

	readOnlyOps := map[string]bool{
		"list_emails": true, "read_email": true, "read_thread": true,
		"list_labels": true, "get_attachment": true,
		"drive.list_files": true, "drive.get_file": true, "drive.download_file": true,
		"calendar.list_events": true, "calendar.get_event": true,
		"people.list_contacts": true, "people.get_contact": true,
		"sheets.get_spreadsheet": true, "sheets.read_range": true,
		"docs.get_document": true, "docs.list_documents": true,
	}

	for _, op := range ops {
		expectReadOnly := readOnlyOps[op.Name]
		if op.ReadOnly != expectReadOnly {
			t.Errorf("operation %q: expected ReadOnly=%v, got %v", op.Name, expectReadOnly, op.ReadOnly)
		}
	}
}

// ---------- Verify default mock responses are well-formed ----------

func TestE2E_DefaultMockResponses(t *testing.T) {
	env := testenv.New(t)
	mock := env.Mock

	tests := []struct {
		op     string
		params map[string]any
		check  func(t *testing.T, resp any)
	}{
		{
			op: "drive.list_files", params: map[string]any{},
			check: func(t *testing.T, resp any) {
				m := resp.(map[string]any)
				files := m["files"].([]any)
				if len(files) != 2 {
					t.Fatalf("expected 2 files, got %d", len(files))
				}
			},
		},
		{
			op: "calendar.list_events", params: map[string]any{},
			check: func(t *testing.T, resp any) {
				m := resp.(map[string]any)
				events := m["events"].([]any)
				if len(events) != 2 {
					t.Fatalf("expected 2 events, got %d", len(events))
				}
			},
		},
		{
			op: "people.list_contacts", params: map[string]any{},
			check: func(t *testing.T, resp any) {
				m := resp.(map[string]any)
				contacts := m["contacts"].([]any)
				if len(contacts) != 2 {
					t.Fatalf("expected 2 contacts, got %d", len(contacts))
				}
			},
		},
		{
			op: "sheets.read_range", params: map[string]any{"spreadsheet_id": "ss1", "range": "A1:C3"},
			check: func(t *testing.T, resp any) {
				m := resp.(map[string]any)
				values := m["values"].([]any)
				if len(values) != 3 {
					t.Fatalf("expected 3 rows, got %d", len(values))
				}
			},
		},
		{
			op: "docs.get_document", params: map[string]any{"document_id": "doc-123"},
			check: func(t *testing.T, resp any) {
				m := resp.(map[string]any)
				if m["document_id"] != "doc-123" {
					t.Fatalf("expected document_id 'doc-123', got %v", m["document_id"])
				}
				if m["title"] == nil || m["title"] == "" {
					t.Fatal("expected non-empty title")
				}
				if m["body"] == nil || m["body"] == "" {
					t.Fatal("expected non-empty body")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.op, func(t *testing.T) {
			resp, err := mock.Execute(nil, tc.op, tc.params)
			if err != nil {
				t.Fatalf("Execute(%q) error: %v", tc.op, err)
			}
			tc.check(t, resp)
		})
	}
}

// ---------- All default operations return without error ----------

func TestE2E_AllDefaultOperationsExecute(t *testing.T) {
	env := testenv.New(t)
	mock := env.Mock

	// Provide required params for each operation.
	opParams := map[string]map[string]any{
		"list_emails":            {},
		"read_email":             {"message_id": "msg-001"},
		"read_thread":            {"thread_id": "t-001"},
		"create_draft":           {"subject": "test"},
		"update_draft":           {"draft_id": "d-001"},
		"send_email":             {"to": []string{"a@b.com"}, "subject": "hi", "body": "hello"},
		"send_draft":             {"draft_id": "d-001"},
		"reply":                  {"message_id": "msg-001", "body": "reply text"},
		"add_label":              {"message_id": "msg-001", "label_id": "INBOX"},
		"remove_label":           {"message_id": "msg-001", "label_id": "INBOX"},
		"archive":                {"message_id": "msg-001"},
		"list_labels":            {},
		"get_attachment":         {"message_id": "msg-001", "attachment_id": "att-001"},
		"drive.list_files":       {},
		"drive.get_file":         {"file_id": "f-001"},
		"drive.download_file":    {"file_id": "f-001"},
		"drive.upload_file":      {"name": "x.txt", "content": "AA==", "mime_type": "text/plain"},
		"drive.share_file":       {"file_id": "f-001", "email": "a@b.com"},
		"calendar.list_events":   {},
		"calendar.get_event":     {"event_id": "e-001"},
		"calendar.create_event":  {"summary": "Test", "start": "2026-04-13T10:00:00Z", "end": "2026-04-13T11:00:00Z"},
		"calendar.update_event":  {"event_id": "e-001", "summary": "Updated"},
		"calendar.delete_event":  {"event_id": "e-001"},
		"people.list_contacts":   {},
		"people.get_contact":     {"resource_name": "people/c1001"},
		"people.create_contact":  {"name": "Test", "email": "test@example.com"},
		"people.update_contact":  {"resource_name": "people/c1001", "name": "Updated"},
		"people.delete_contact":  {"resource_name": "people/c1001"},
		"sheets.get_spreadsheet": {"spreadsheet_id": "ss-001"},
		"sheets.read_range":      {"spreadsheet_id": "ss-001", "range": "A1:B2"},
		"sheets.write_range":     {"spreadsheet_id": "ss-001", "range": "A1:B2", "values": "[[\"a\"]]"},
		"sheets.create_spreadsheet": {"title": "Test Sheet"},
		"docs.get_document":      {"document_id": "doc-001"},
		"docs.list_documents":    {},
		"docs.create_document":   {"title": "Test Doc"},
		"docs.update_document":   {"document_id": "doc-001", "requests": "[]"},
	}

	for op, params := range opParams {
		t.Run(op, func(t *testing.T) {
			resp, err := mock.Execute(nil, op, params)
			if err != nil {
				t.Fatalf("Execute(%q) returned error: %v", op, err)
			}
			if resp == nil {
				t.Fatalf("Execute(%q) returned nil response", op)
			}

			// Verify response is JSON-serializable.
			_, err = json.Marshal(resp)
			if err != nil {
				t.Fatalf("Execute(%q) response not JSON-serializable: %v", op, err)
			}
		})
	}
}
