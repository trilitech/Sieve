package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
)

// applyConnectorFormFields is the single bridge between form values and
// connection config. These tests pin the contract so that adding a new
// field type or editability flag doesn't accidentally regress the
// behavior the rest of the system depends on.

func formReq(t *testing.T, values url.Values) *http.Request {
	t.Helper()
	req, _ := http.NewRequest("POST", "/x", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	return req
}

// TestApply_CreateMissingRequiredFieldFailsLoud guards the explicit
// "required field missing" branch — silently saving an empty target_url
// would yield a broken connector that fails at first agent call.
func TestApply_CreateMissingRequiredFieldFailsLoud(t *testing.T) {
	meta := connector.ConnectorMeta{
		SetupFields: []connector.Field{
			{Name: "target_url", Type: "text", Required: true, Label: "Target URL"},
		},
	}
	cfg := map[string]any{}
	msg := applyConnectorFormFields(meta, formModeCreate, formReq(t, url.Values{}), cfg)
	if msg == "" {
		t.Fatal("expected error for missing required field")
	}
	if !strings.Contains(msg, "Target URL") {
		t.Errorf("error should name the field's Label; got %q", msg)
	}
}

// TestApply_EditEmptySecretKeepsStored pins the "leave password blank
// on edit = keep stored" semantic. Without this, an operator who edits
// any other field would zero out their API key.
func TestApply_EditEmptySecretKeepsStored(t *testing.T) {
	meta := connector.ConnectorMeta{
		SetupFields: []connector.Field{
			{Name: "auth_value", Type: "password", Required: true, Editable: true, Secret: true},
		},
	}
	cfg := map[string]any{"auth_value": "sk-ant-stored"}
	values := url.Values{}
	values.Set("auth_value", "") // present + empty
	msg := applyConnectorFormFields(meta, formModeEdit, formReq(t, values), cfg)
	if msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}
	if cfg["auth_value"] != "sk-ant-stored" {
		t.Errorf("secret was clobbered; got %q", cfg["auth_value"])
	}
}

// TestApply_EditNewSecretReplacesStored is the rotation path — when the
// operator types a new secret, it must overwrite cleanly.
func TestApply_EditNewSecretReplacesStored(t *testing.T) {
	meta := connector.ConnectorMeta{
		SetupFields: []connector.Field{
			{Name: "auth_value", Type: "password", Editable: true, Secret: true},
		},
	}
	cfg := map[string]any{"auth_value": "old"}
	values := url.Values{"auth_value": {"new-secret"}}
	if msg := applyConnectorFormFields(meta, formModeEdit, formReq(t, values), cfg); msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}
	if cfg["auth_value"] != "new-secret" {
		t.Errorf("secret didn't update; got %q", cfg["auth_value"])
	}
}

// TestApply_EditAbsentTextKeepsStored confirms the "key not in form ->
// keep stored" rule. This is the regression for the bug that prompted
// the refactor: posting a partial form (e.g., to flip a checkbox)
// previously clobbered every other field.
func TestApply_EditAbsentTextKeepsStored(t *testing.T) {
	meta := connector.ConnectorMeta{
		SetupFields: []connector.Field{
			{Name: "target_url", Type: "text", Editable: true},
			{Name: "auth_value_scrub", Type: "checkbox", EditOnly: true, Editable: true},
		},
	}
	cfg := map[string]any{"target_url": "https://stored.example", "auth_value_scrub": true}
	values := url.Values{} // posting only "uncheck auth_value_scrub"
	if msg := applyConnectorFormFields(meta, formModeEdit, formReq(t, values), cfg); msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}
	if cfg["target_url"] != "https://stored.example" {
		t.Errorf("target_url was clobbered to %q", cfg["target_url"])
	}
	if v, _ := cfg["auth_value_scrub"].(bool); v {
		t.Errorf("auth_value_scrub should be false (checkbox absent); got %v", cfg["auth_value_scrub"])
	}
}

// TestApply_EditEmptyNonSecretTextIsClear pins the contrast with the
// secret behavior — an explicit empty post on a non-secret text field
// IS a deliberate clear, not a "keep stored". Operators must be able to
// remove a value.
func TestApply_EditEmptyNonSecretTextIsClear(t *testing.T) {
	meta := connector.ConnectorMeta{
		SetupFields: []connector.Field{
			{Name: "category", Type: "text", Editable: true},
		},
	}
	cfg := map[string]any{"category": "llm"}
	values := url.Values{}
	values.Set("category", "")
	if msg := applyConnectorFormFields(meta, formModeEdit, formReq(t, values), cfg); msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}
	if cfg["category"] != "" {
		t.Errorf("category should be cleared; got %q", cfg["category"])
	}
}

// TestApply_TextFieldsTrimWhitespace confirms the trim normalization
// applied to non-secret text. Stops operators from breaking themselves
// with copy-paste whitespace.
func TestApply_TextFieldsTrimWhitespace(t *testing.T) {
	meta := connector.ConnectorMeta{
		SetupFields: []connector.Field{
			{Name: "auth_header", Type: "text", Required: true},
		},
	}
	cfg := map[string]any{}
	values := url.Values{"auth_header": {"  x-api-key  "}}
	if msg := applyConnectorFormFields(meta, formModeCreate, formReq(t, values), cfg); msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}
	if cfg["auth_header"] != "x-api-key" {
		t.Errorf("text should be trimmed; got %q", cfg["auth_header"])
	}
}

// TestApply_SecretFieldsNotTrimmed pins the inverse — secrets MAY have
// significant leading/trailing whitespace (rare but legal); we don't
// quietly mangle them.
func TestApply_SecretFieldsNotTrimmed(t *testing.T) {
	meta := connector.ConnectorMeta{
		SetupFields: []connector.Field{
			{Name: "auth_value", Type: "password", Required: true, Secret: true},
		},
	}
	cfg := map[string]any{}
	values := url.Values{"auth_value": {" sk-spaces "}}
	if msg := applyConnectorFormFields(meta, formModeCreate, formReq(t, values), cfg); msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}
	if cfg["auth_value"] != " sk-spaces " {
		t.Errorf("secret should not be trimmed; got %q", cfg["auth_value"])
	}
}

// TestApply_TextareaSplitsAndTrims pins the textarea contract: each
// non-empty line becomes one entry; whitespace is trimmed; ordering
// preserved.
func TestApply_TextareaSplitsAndTrims(t *testing.T) {
	meta := connector.ConnectorMeta{
		SetupFields: []connector.Field{
			{Name: "headers", Type: "textarea", Editable: true},
		},
	}
	cfg := map[string]any{}
	values := url.Values{"headers": {"X-One\n\n  X-Two  \nX-Three\n"}}
	if msg := applyConnectorFormFields(meta, formModeEdit, formReq(t, values), cfg); msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}
	got, _ := cfg["headers"].([]any)
	want := []any{"X-One", "X-Two", "X-Three"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestApply_JSONFieldRejectsMalformed verifies the JSON parser refuses
// invalid input with a useful message rather than persisting garbage.
func TestApply_JSONFieldRejectsMalformed(t *testing.T) {
	meta := connector.ConnectorMeta{
		SetupFields: []connector.Field{
			{Name: "extra_headers", Type: "json", Editable: true, Label: "Extra Headers"},
		},
	}
	cfg := map[string]any{}
	values := url.Values{"extra_headers": {"not json"}}
	msg := applyConnectorFormFields(meta, formModeEdit, formReq(t, values), cfg)
	if msg == "" {
		t.Fatal("expected error for malformed JSON")
	}
	if !strings.Contains(msg, "Extra Headers") {
		t.Errorf("error should name the field; got %q", msg)
	}
}

// TestApply_NumberRejectsNegative guards against operators trying to
// disable a cap by entering -1.
func TestApply_NumberRejectsNegative(t *testing.T) {
	meta := connector.ConnectorMeta{
		SetupFields: []connector.Field{
			{Name: "cap", Type: "number", EditOnly: true, Editable: true, Label: "Cap"},
		},
	}
	cfg := map[string]any{}
	values := url.Values{"cap": {"-1"}}
	msg := applyConnectorFormFields(meta, formModeEdit, formReq(t, values), cfg)
	if msg == "" {
		t.Fatal("expected error for negative number")
	}
}

// TestApply_EditOnlyFieldsSkippedOnCreate confirms the mode filter:
// operational settings (auth_value_scrub, response_body_cap_bytes) must
// not appear on the create form's parsing path, since they have no
// creation-time concept.
func TestApply_EditOnlyFieldsSkippedOnCreate(t *testing.T) {
	meta := connector.ConnectorMeta{
		SetupFields: []connector.Field{
			{Name: "scrub", Type: "checkbox", EditOnly: true, Editable: true},
		},
	}
	cfg := map[string]any{}
	values := url.Values{"scrub": {"1"}}
	if msg := applyConnectorFormFields(meta, formModeCreate, formReq(t, values), cfg); msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}
	if _, ok := cfg["scrub"]; ok {
		t.Errorf("EditOnly field should not be parsed on create; got %v", cfg)
	}
}

// TestApply_NonEditableFieldsSkippedOnEdit confirms the inverse: a
// field declared without Editable can't be changed via the edit form
// even if the operator hand-crafts a POST with the field name.
func TestApply_NonEditableFieldsSkippedOnEdit(t *testing.T) {
	meta := connector.ConnectorMeta{
		SetupFields: []connector.Field{
			{Name: "frozen", Type: "text"}, // not Editable
		},
	}
	cfg := map[string]any{"frozen": "stored"}
	values := url.Values{"frozen": {"hacker-attempt"}}
	if msg := applyConnectorFormFields(meta, formModeEdit, formReq(t, values), cfg); msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}
	if cfg["frozen"] != "stored" {
		t.Errorf("non-Editable field was changed; got %q", cfg["frozen"])
	}
}

// TestConnectorRequiresBespokeAdd documents which connector types are
// intentionally excluded from the generic data-driven create path —
// changes to this list are an architectural decision (the bespoke flow
// is necessary to validate against the upstream or run OAuth).
func TestConnectorRequiresBespokeAdd(t *testing.T) {
	cases := map[string]bool{
		"slack":      true,
		"google":     true,
		"github":     true,
		"http_proxy": false,
		"mcp_proxy":  false,
		"anthropic":  false,
		"":           false,
		"unknown":    false,
	}
	for name, want := range cases {
		if got := connectorRequiresBespokeAdd(name); got != want {
			t.Errorf("connectorRequiresBespokeAdd(%q) = %v, want %v", name, got, want)
		}
	}
}
