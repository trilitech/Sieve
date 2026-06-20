package linear

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
)

// newTestConnector spins up an httptest.Server with the given handler
// and returns a Connector wired to it via the base_url override.
//
// httpguard.Client default-denies loopback dials, so the test fixture
// always supplies 127.0.0.0/8 in outbound_allowlist — without that,
// every test fails with "destination in default-deny range" before
// reaching the test server. Production connections leave this blank.
func newTestConnector(t *testing.T, handler http.HandlerFunc) *Connector {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	c, err := Factory()(map[string]any{
		"api_key":            "lin_api_test-not-real",
		"base_url":           srv.URL,
		"outbound_allowlist": []string{"127.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	return c.(*Connector)
}

// --- parseConfig ---

func TestParseConfig_RequiresAPIKey(t *testing.T) {
	_, err := parseConfig(map[string]any{"base_url": "https://api.linear.app"})
	if err == nil {
		t.Fatal("expected error for missing api_key")
	}
	if !strings.Contains(err.Error(), "api_key") {
		t.Errorf("error should mention api_key; got %v", err)
	}
}

func TestParseConfig_TrimsAPIKeyWhitespace(t *testing.T) {
	for _, sample := range []string{
		"  lin_api_abc  ",
		"lin_api_abc\n",
		"\tlin_api_abc",
	} {
		t.Run(sample, func(t *testing.T) {
			cfg, err := parseConfig(map[string]any{"api_key": sample})
			if err != nil {
				t.Fatalf("parseConfig: %v", err)
			}
			if cfg.APIKey != "lin_api_abc" {
				t.Errorf("api_key should be trimmed; got %q", cfg.APIKey)
			}
		})
	}
}

func TestParseConfig_DefaultsBaseURL(t *testing.T) {
	cfg, err := parseConfig(map[string]any{"api_key": "lin_api_abc"})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.BaseURL != defaultBaseURL {
		t.Errorf("base_url should default; got %q want %q", cfg.BaseURL, defaultBaseURL)
	}
}

func TestParseConfig_RejectsBaseURLWithoutScheme(t *testing.T) {
	_, err := parseConfig(map[string]any{
		"api_key":  "lin_api_abc",
		"base_url": "api.linear.app",
	})
	if err == nil {
		t.Fatal("expected error for schemeless base_url")
	}
}

func TestParseConfig_StripsTrailingSlash(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"api_key":  "lin_api_abc",
		"base_url": "https://api.linear.app/",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.BaseURL != "https://api.linear.app" {
		t.Errorf("trailing slash should be stripped; got %q", cfg.BaseURL)
	}
}

// --- auth header ---

// TestDoGraphQL_AuthHeaderNoBearerPrefix pins Linear's auth convention:
// Personal API Keys go in `Authorization: <key>` WITHOUT the Bearer
// prefix. OAuth tokens (v2) would use Bearer; sending Bearer with a
// Personal API Key produces a 400. If a future contributor "normalises"
// the header to add Bearer this test fires.
func TestDoGraphQL_AuthHeaderNoBearerPrefix(t *testing.T) {
	var seenAuth string
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"viewer":{"id":"u1"}}}`))
	})
	if err := conn.Validate(context.Background()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if seenAuth != "lin_api_test-not-real" {
		t.Errorf("Authorization header = %q, want bare api_key (no Bearer)", seenAuth)
	}
}

// --- response size cap ---

func TestDoGraphQL_OversizedResponseRejected(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		chunk := make([]byte, 64*1024)
		for i := 0; i < 96; i++ { // 6 MiB > 5 MiB cap
			_, _ = w.Write(chunk)
		}
	})
	_, err := conn.doGraphQL(context.Background(), `query { viewer { id } }`, nil)
	if err == nil {
		t.Fatal("expected error on oversized response")
	}
	if !strings.Contains(err.Error(), "byte cap") {
		t.Errorf("error should mention cap; got %v", err)
	}
}

// --- Validate ---

func TestValidate_401MapsToReauth(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"message":"Unauthorized"}]}`))
	})
	err := conn.Validate(context.Background())
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf("401 should wrap ErrNeedsReauth; got %v", err)
	}
}

func TestValidate_403MapsToReauth(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"message":"Forbidden"}]}`))
	})
	err := conn.Validate(context.Background())
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf("403 should wrap ErrNeedsReauth; got %v", err)
	}
}

// TestValidate_GraphQLAuthErrorMapsToReauth pins the Linear-specific
// 200-OK-with-graphql-error shape. Linear returns HTTP 200 even when
// the key is invalid; the auth signal lives in the GraphQL errors
// array under extensions.type. Confirmed against linear/linear's own
// SDK (packages/sdk/src/error.ts): the extension key is `type` (NOT
// `code`) and the value is the lowercase string "authentication error"
// (with a space). Without this branch, an invalid key would silently
// succeed validation and then fail on every agent call.
func TestValidate_GraphQLAuthErrorMapsToReauth(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"Authentication failed - You need to authenticate with a valid API key","extensions":{"type":"authentication error"}}]}`))
	})
	err := conn.Validate(context.Background())
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf(`extensions.type "authentication error" should wrap ErrNeedsReauth; got %v`, err)
	}
}

// TestValidate_GraphQLForbiddenMapsToReauth covers the sibling case:
// Linear emits extensions.type = "forbidden" when the API key is valid
// but lacks scope for the requested operation. The viewer query needs
// no special scope, so this is rarer at validation time than for agent
// calls, but it's the same operator-action-required signal as
// authentication error and must map to ErrNeedsReauth too.
func TestValidate_GraphQLForbiddenMapsToReauth(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"Forbidden","extensions":{"type":"forbidden"}}]}`))
	})
	err := conn.Validate(context.Background())
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf(`extensions.type "forbidden" should wrap ErrNeedsReauth; got %v`, err)
	}
}

// TestValidate_GraphQLOtherErrorDoesNotBlockSave pins that a non-auth
// graphql error (validation, rate limit, etc.) on the viewer query
// does NOT block save. Same rationale as 5xx: transient or
// not-actually-auth issues shouldn't prevent the operator from
// persisting their key.
func TestValidate_GraphQLOtherErrorDoesNotBlockSave(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"Ratelimited","extensions":{"type":"ratelimited"}}]}`))
	})
	if err := conn.Validate(context.Background()); err != nil {
		t.Errorf("non-auth graphql error must not block save; got %v", err)
	}
}

func TestValidate_5xxDoesNotBlockSave(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	if err := conn.Validate(context.Background()); err != nil {
		t.Errorf("transient 5xx must not block save; got %v", err)
	}
}

func TestValidate_TransportErrorDoesNotBlockSave(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	c, err := Factory()(map[string]any{
		"api_key":            "lin_api_x",
		"base_url":           srv.URL,
		"outbound_allowlist": []string{"127.0.0.0/8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()
	if err := c.Validate(context.Background()); err != nil {
		t.Errorf("transport failure must not block save; got %v", err)
	}
}

func TestValidate_OkResponseSucceeds(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"viewer":{"id":"u1"}}}`))
	})
	if err := conn.Validate(context.Background()); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// --- ops: shape ---

// TestOpListIssues_AppliesFilters confirms the GraphQL variables shape.
// The Linear API has very strict input typing; sending an empty filter
// (instead of omitting it) was rejected with cryptic errors in early
// development. The test pins that omitted params → no filter key in
// variables, and present params → the documented nested-eq shape.
func TestOpListIssues_AppliesFilters(t *testing.T) {
	var receivedBody graphqlRequest
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"issues":{"nodes":[]}}}`))
	})
	_, err := conn.Execute(context.Background(), "linear_list_issues", map[string]any{
		"team_id":  "team-uuid",
		"state_id": "state-uuid",
		"first":    10,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got, _ := receivedBody.Variables["first"].(float64); int(got) != 10 {
		t.Errorf("first variable should be 10; got %v", receivedBody.Variables["first"])
	}
	filter, ok := receivedBody.Variables["filter"].(map[string]any)
	if !ok {
		t.Fatalf("filter should be a map; got %v", receivedBody.Variables["filter"])
	}
	team, _ := filter["team"].(map[string]any)
	teamID, _ := team["id"].(map[string]any)
	if teamID["eq"] != "team-uuid" {
		t.Errorf("filter.team.id.eq = %v, want team-uuid", teamID["eq"])
	}
	if _, present := filter["assignee"]; present {
		t.Errorf("filter should not include assignee when omitted; got %v", filter)
	}
}

// TestOpListIssues_NoFiltersOmitsFilterKey pins that absent params
// result in NO `filter` key in variables (rather than an empty map).
// Linear's IssueFilter input rejects null fields with a confusing
// "Variable $filter of required type IssueFilter! ..." style error if
// we send a typed empty object.
func TestOpListIssues_NoFiltersOmitsFilterKey(t *testing.T) {
	var receivedBody graphqlRequest
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"issues":{"nodes":[]}}}`))
	})
	_, err := conn.Execute(context.Background(), "linear_list_issues", map[string]any{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, present := receivedBody.Variables["filter"]; present {
		t.Errorf("filter key should be omitted when no filters supplied; got %v", receivedBody.Variables)
	}
}

// TestOpListIssues_ClampsFirstAtCeiling pins the page-size cap. An
// agent that passes first=10000 must not result in an unbounded
// request (Linear would 400, but the wider concern is a runaway agent).
func TestOpListIssues_ClampsFirstAtCeiling(t *testing.T) {
	var receivedBody graphqlRequest
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"issues":{"nodes":[]}}}`))
	})
	_, err := conn.Execute(context.Background(), "linear_list_issues", map[string]any{
		"first": 10000,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got, _ := receivedBody.Variables["first"].(float64)
	if int(got) != 250 {
		t.Errorf("first should clamp to 250; got %v", got)
	}
}

func TestOpCreateIssue_BuildsInput(t *testing.T) {
	var receivedBody graphqlRequest
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"issueCreate":{"success":true,"issue":{"id":"x"}}}}`))
	})
	_, err := conn.Execute(context.Background(), "linear_create_issue", map[string]any{
		"team_id":     "team-uuid",
		"title":       "Bug",
		"description": "It broke.",
		"priority":    2,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	input, ok := receivedBody.Variables["input"].(map[string]any)
	if !ok {
		t.Fatalf("input should be a map; got %v", receivedBody.Variables["input"])
	}
	if input["teamId"] != "team-uuid" {
		t.Errorf("teamId = %v, want team-uuid", input["teamId"])
	}
	if input["title"] != "Bug" {
		t.Errorf("title = %v", input["title"])
	}
	if input["description"] != "It broke." {
		t.Errorf("description = %v", input["description"])
	}
	if got, _ := input["priority"].(float64); int(got) != 2 {
		t.Errorf("priority = %v, want 2", input["priority"])
	}
	// Optional fields omitted should not appear in the input.
	if _, present := input["assigneeId"]; present {
		t.Errorf("assigneeId should be omitted; got %v", input)
	}
}

// TestOpCreateIssue_PreservesPriorityZero pins that priority=0
// ("no priority" in Linear's scale) is forwarded rather than silently
// dropped. The early implementation used `if v > 0` and lost this
// case — an agent that wanted to explicitly mark an issue as no-priority
// would see Linear inherit the team default instead.
func TestOpCreateIssue_PreservesPriorityZero(t *testing.T) {
	var receivedBody graphqlRequest
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"issueCreate":{"success":true}}}`))
	})
	_, err := conn.Execute(context.Background(), "linear_create_issue", map[string]any{
		"team_id":  "team-uuid",
		"title":    "Bug",
		"priority": 0,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	input, _ := receivedBody.Variables["input"].(map[string]any)
	got, present := input["priority"]
	if !present {
		t.Fatalf("priority=0 was dropped from input; input=%v", input)
	}
	if g, _ := got.(float64); int(g) != 0 {
		t.Errorf("priority value = %v, want 0", got)
	}
}

// TestOpCreateIssue_OmitsPriorityWhenAbsent pins the inverse: if the
// agent doesn't supply priority, we don't materialise the key.
// Without this, the create mutation would always send priority=0,
// silently overriding the team default.
func TestOpCreateIssue_OmitsPriorityWhenAbsent(t *testing.T) {
	var receivedBody graphqlRequest
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"issueCreate":{"success":true}}}`))
	})
	_, err := conn.Execute(context.Background(), "linear_create_issue", map[string]any{
		"team_id": "team-uuid",
		"title":   "Bug",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	input, _ := receivedBody.Variables["input"].(map[string]any)
	if _, present := input["priority"]; present {
		t.Errorf("priority should be omitted when not supplied; input=%v", input)
	}
}

// TestOpUpdateIssue_RequiresAtLeastOneField pins the guard against a
// no-op mutation. Without it, an agent that forgets the field args
// would send `issueUpdate(id: "x", input: {})` which Linear rejects
// with a less-helpful error.
func TestOpUpdateIssue_RequiresAtLeastOneField(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for empty update")
	})
	_, err := conn.Execute(context.Background(), "linear_update_issue", map[string]any{
		"id": "issue-uuid",
	})
	if err == nil {
		t.Fatal("expected error for empty update input")
	}
}

// TestOpRequest_PassesThroughQueryAndVariables pins the escape hatch:
// agents send a literal GraphQL document and a JSON variables string,
// and we forward verbatim.
func TestOpRequest_PassesThroughQueryAndVariables(t *testing.T) {
	var receivedBody graphqlRequest
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	})
	_, err := conn.Execute(context.Background(), "linear_request", map[string]any{
		"query":     `query Q($id: String!) { issue(id: $id) { id } }`,
		"variables": `{"id":"ENG-42"}`,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(receivedBody.Query, "issue(id: $id)") {
		t.Errorf("query not forwarded; got %q", receivedBody.Query)
	}
	if receivedBody.Variables["id"] != "ENG-42" {
		t.Errorf("variables not forwarded; got %v", receivedBody.Variables)
	}
}

// TestOpRequest_RejectsMalformedVariables pins the friendly-error path
// for a common operator mistake: pasting a Python-style dict instead
// of JSON. Without this, the GraphQL request would be made with empty
// variables and Linear would return an opaque "Variable $id of
// required type String! was not provided" error.
func TestOpRequest_RejectsMalformedVariables(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for malformed variables")
	})
	_, err := conn.Execute(context.Background(), "linear_request", map[string]any{
		"query":     `query { viewer { id } }`,
		"variables": `{id: "ENG-42"}`, // not valid JSON
	})
	if err == nil {
		t.Fatal("expected error for malformed variables")
	}
}

func TestOpRequest_AcceptsTypedVariablesMap(t *testing.T) {
	var receivedBody graphqlRequest
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	})
	_, err := conn.Execute(context.Background(), "linear_request", map[string]any{
		"query":     `query Q($id: String!) { issue(id: $id) { id } }`,
		"variables": map[string]any{"id": "ENG-42"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if receivedBody.Variables["id"] != "ENG-42" {
		t.Errorf("typed variables map should be forwarded; got %v", receivedBody.Variables)
	}
}

// TestOpListWorkflowStates_RequiresTeam pins the required-param guard.
func TestOpListWorkflowStates_RequiresTeam(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called without team_id")
	})
	_, err := conn.Execute(context.Background(), "linear_list_workflow_states", map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing team_id")
	}
}

// TestOperations_CatalogShape pins the v1 operation surface against
// silent rename / removal.
func TestOperations_CatalogShape(t *testing.T) {
	c, err := Factory()(map[string]any{"api_key": "lin_api_test"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"linear_request":              false,
		"linear_list_issues":          true,
		"linear_get_issue":            true,
		"linear_create_issue":         false,
		"linear_update_issue":         false,
		"linear_list_teams":           true,
		"linear_list_users":           true,
		"linear_list_workflow_states": true,
		"linear_list_comments":        true,
		"linear_create_comment":       false,
	}
	got := make(map[string]bool)
	for _, op := range c.Operations() {
		got[op.Name] = op.ReadOnly
	}
	for name, ro := range want {
		actual, present := got[name]
		if !present {
			t.Errorf("operation %q missing from catalog", name)
			continue
		}
		if actual != ro {
			t.Errorf("operation %q: ReadOnly = %v, want %v", name, actual, ro)
		}
	}
	for name := range got {
		if _, expected := want[name]; !expected {
			t.Errorf("unexpected operation %q in catalog", name)
		}
	}
}

func TestExecute_UnknownOperationFailsCleanly(t *testing.T) {
	conn := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for unknown op")
	})
	_, err := conn.Execute(context.Background(), "linear_delete_workspace", nil)
	if err == nil {
		t.Fatal("expected error for unknown op")
	}
	if !strings.Contains(err.Error(), "unknown operation") {
		t.Errorf("expected 'unknown operation' in error; got %v", err)
	}
}

// TestMeta_SetupFieldsCoverPersistedKeys pins the architectural
// invariant from PR #31 locally: every key the Factory consumes from
// the persisted config must appear in Meta().SetupFields, so the edit
// form covers it. This includes both typed-struct keys (api_key,
// base_url) and out-of-struct keys read directly from the map
// (outbound_allowlist).
//
// When PR #31 lands and the global architecture test fires, this
// connector passes; until then, this local test catches the same
// drift class for Linear specifically.
func TestMeta_SetupFieldsCoverPersistedKeys(t *testing.T) {
	persisted := map[string]bool{
		"api_key":            false,
		"base_url":           false,
		"outbound_allowlist": false,
	}
	for _, f := range Meta().SetupFields {
		if _, ok := persisted[f.Name]; ok {
			persisted[f.Name] = true
		}
	}
	for k, present := range persisted {
		if !present {
			t.Errorf("persisted key %q has no matching SetupField — edit form will silently lose this key", k)
		}
	}
}

// TestFactory_RejectsInvalidAllowlistCIDR pins the parse-time
// validation: a typo'd CIDR must fail at Factory time rather than
// silently degrading to "no allowlist entries" at runtime (which
// would then default-deny every dial including api.linear.app's
// public IPs — confusing failure mode at save-time but baffling at
// first agent call).
func TestFactory_RejectsInvalidAllowlistCIDR(t *testing.T) {
	_, err := Factory()(map[string]any{
		"api_key":            "lin_api_x",
		"outbound_allowlist": []string{"not-a-cidr"},
	})
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if !strings.Contains(err.Error(), "outbound_allowlist") {
		t.Errorf("error should mention outbound_allowlist; got %v", err)
	}
}
