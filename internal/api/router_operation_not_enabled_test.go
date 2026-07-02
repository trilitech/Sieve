package api_test

// When a connector returns connector.ErrOperationNotEnabled from Execute,
// the API layer MUST emit HTTP 501 with the canonical
// operation_not_enabled envelope. Distinct from the re-auth 403 and from
// the keyring-locked 503.

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// TestRouter_OperationNotEnabled_Returns501 wires the in-tree mock
// connector to return ErrOperationNotEnabled for the `list_emails`
// op (the policy "read-only" allows it through), then asserts the API
// maps the sentinel to HTTP 501 with the documented envelope.
func TestRouter_OperationNotEnabled_Returns501(t *testing.T) {
	env := testenv.New(t)
	role := env.SetupConnectionAndRole(t, "test-conn", "read-only")
	tok := env.CreateToken(t, role.ID)

	// Inject the sentinel as the per-op error on the mock connector.
	env.Mock.Errors["list_emails"] = fmt.Errorf("%w: pretend this op is gated until vNext", connector.ErrOperationNotEnabled)

	router := api.NewRouter(
		env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit,
	)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	resp := doRequest(t, "POST", srv.URL+"/api/v1/connections/test-conn/ops/list_emails", tok, "{}")
	body := readBody(t, resp)

	if resp.StatusCode != 501 {
		t.Fatalf("expected 501 Not Implemented, got %d (body: %s)", resp.StatusCode, body)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("body is not JSON: %v (body: %s)", err, body)
	}
	if got["error"] != "operation_not_enabled" {
		t.Fatalf("error: got %v, want operation_not_enabled (body: %s)", got["error"], body)
	}
	if got["connection_id"] != "test-conn" {
		t.Fatalf("connection_id: got %v, want test-conn", got["connection_id"])
	}
	if got["operation"] != "list_emails" {
		t.Fatalf("operation: got %v, want list_emails", got["operation"])
	}
	if got["message"] != "pretend this op is gated until vNext" {
		t.Fatalf("message: got %v, want stripped reason (sentinel prefix removed)", got["message"])
	}
}
