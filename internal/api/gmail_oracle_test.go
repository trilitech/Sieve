package api_test

// Regression tests for the connection-existence/status oracle on the
// Gmail-compatible path (gmailExecute). Mirrors oracle_visibility_test.go for
// executeOperation: an unauthorized token must not be able to distinguish a
// missing gmail alias from an existing-but-ungranted one, nor observe its
// status (needs_reauth). The IAM Decide is the sole gate and runs on connection
// metadata before anything connection-specific (the reauth pre-flight, the
// connector build) is revealed.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/roles"
	mockconn "github.com/trilitech/Sieve/internal/testing/mockconnector"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// gmailOracleEnv registers a google-typed mock, adds a granted account g1 and an
// ungranted account g2, and returns a running server + the token (granted read
// on g1 only).
func gmailOracleEnv(t *testing.T) (*testenv.Env, *httptest.Server, string) {
	t.Helper()
	env := testenv.New(t)

	gmock := mockconn.New("google")
	gmock.SetResponse("list_emails", map[string]any{"messages": []any{}})
	env.Registry.Register(gmock.Meta(), gmock.Factory())

	if err := env.Connections.Add("g1", "google", "First", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if err := env.Connections.Add("g2", "google", "Second", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	role, err := env.Roles.Create("g1reader", []roles.Binding{{ConnectionID: "g1"}})
	if err != nil {
		t.Fatal(err)
	}
	tok := env.CreateToken(t, role.ID)
	grant, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: role.ID, Effect: "allow", ConnectorType: "google", OpScope: "read",
		ConnectionIDs: []string{"g1"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.IAM.CreatePolicy("g1-read", "", grant, true); err != nil {
		t.Fatal(err)
	}
	if err := env.Settings.Set("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(api.NewRouter(
		env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit,
	).Handler())
	t.Cleanup(srv.Close)
	return env, srv, tok
}

// TestGmailExecute_NoExistenceOracle: for a token granted only on g1, a missing
// alias, an ungranted g2 in needs_reauth, and an ungranted g2 active all return
// the IDENTICAL uniform not-authorized response — no existence/status oracle.
func TestGmailExecute_NoExistenceOracle(t *testing.T) {
	env, srv, tok := gmailOracleEnv(t)

	get := func(alias string) (int, string) {
		resp := doRequest(t, http.MethodGet, srv.URL+"/gmail/v1/users/"+alias+"/messages", tok, "")
		return resp.StatusCode, readBody(t, resp)
	}

	// (i) missing/guessed alias.
	missStatus, missBody := get("ghost-alias")
	// (ii) existing, ungranted, in needs_reauth.
	if err := env.Connections.SetStatus("g2", connections.StatusReauthRequired); err != nil {
		t.Fatalf("set reauth: %v", err)
	}
	reauthStatus, reauthBody := get("g2")
	// (iii) existing, ungranted, active.
	if err := env.Connections.SetStatus("g2", connections.StatusActive); err != nil {
		t.Fatalf("set active: %v", err)
	}
	activeStatus, activeBody := get("g2")

	if missStatus != reauthStatus || missStatus != activeStatus {
		t.Fatalf("status is an oracle: missing=%d reauth-ungranted=%d active-ungranted=%d",
			missStatus, reauthStatus, activeStatus)
	}
	if missBody != reauthBody || missBody != activeBody {
		t.Fatalf("body is an oracle:\n missing=%q\n reauth-ungranted=%q\n active-ungranted=%q",
			missBody, reauthBody, activeBody)
	}
	if missStatus != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (body %s)", missStatus, missBody)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(missBody), &got); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, missBody)
	}
	if got["error"] != "policy denied" {
		t.Fatalf("expected uniform error=\"policy denied\", got %q", got["error"])
	}
}

// TestGmailExecute_AuthorizedStillSeesReauth: the fix preserves the reauth
// fast-path for an AUTHORIZED caller — the token granted on g1 gets the
// structured reauth_required envelope when g1 is in needs_reauth (status is
// revealed only after an authorizing decision), not the uniform deny.
func TestGmailExecute_AuthorizedStillSeesReauth(t *testing.T) {
	env, srv, tok := gmailOracleEnv(t)

	if err := env.Connections.SetStatus("g1", connections.StatusReauthRequired); err != nil {
		t.Fatalf("set reauth: %v", err)
	}
	resp := doRequest(t, http.MethodGet, srv.URL+"/gmail/v1/users/g1/messages", tok, "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", resp.StatusCode, body)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, body)
	}
	if got["error"] != "reauth_required" {
		t.Fatalf("authorized caller should see reauth_required, got %q (%s)", got["error"], body)
	}
}
