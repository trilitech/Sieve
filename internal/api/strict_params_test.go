package api_test

import (
	"strings"
	"testing"
)

// TestStrictParams_RejectsUndeclaredParam is the systemic half of the
// body_html report: the generic ops route handed every key in the JSON body
// straight to Execute, so a parameter the operation knew nothing about was
// accepted and silently discarded — returning 200 for a message that never
// carried the field. Unknown parameters must now fail loudly.
func TestStrictParams_RejectsUndeclaredParam(t *testing.T) {
	env := setupIAMRouter(t)
	status, body := apiPost(t, env.url+"/api/v1/connections/mock-conn/ops/list_emails",
		env.tok, `{"query":"x","totally_made_up":"v"}`)
	if status != 400 {
		t.Fatalf("status = %d, want 400 for an undeclared parameter (body: %s)", status, body)
	}
	if !strings.Contains(body, "totally_made_up") {
		t.Errorf("error should name the offending parameter; got %s", body)
	}
	// And it should tell the caller what IS accepted.
	if !strings.Contains(body, "query") {
		t.Errorf("error should list the accepted parameters; got %s", body)
	}
}

// TestStrictParams_AcceptsDeclaredParams guards against over-rejection: every
// declared parameter must still pass.
func TestStrictParams_AcceptsDeclaredParams(t *testing.T) {
	env := setupIAMRouter(t)
	status, body := apiPost(t, env.url+"/api/v1/connections/mock-conn/ops/list_emails",
		env.tok, `{"query":"x","max_results":5,"page_token":"p"}`)
	if status != 200 {
		t.Fatalf("declared params should pass, got %d (%s)", status, body)
	}
}

// TestStrictParams_EmptyBodyAllowed: a request with no params is fine even for
// ops that declare some.
func TestStrictParams_EmptyBodyAllowed(t *testing.T) {
	env := setupIAMRouter(t)
	if status, body := apiPost(t, env.url+"/api/v1/connections/mock-conn/ops/list_emails", env.tok, `{}`); status != 200 {
		t.Fatalf("empty body should pass, got %d (%s)", status, body)
	}
}

// TestStrictParams_UnknownOperationStillReachesConnector: validation must not
// swallow an unknown operation — the connector's own error is what should
// surface, not a parameter complaint.
func TestStrictParams_UnknownOperationStillReachesConnector(t *testing.T) {
	env := setupIAMRouter(t)
	status, body := apiPost(t, env.url+"/api/v1/connections/mock-conn/ops/no_such_op",
		env.tok, `{"anything":"goes"}`)
	if status == 400 && strings.Contains(body, "unknown parameter") {
		t.Errorf("an unknown operation must not be reported as a parameter error; got %s", body)
	}
}
