package web

// Web-layer contract for token name collisions: a live clash must render as a
// 409 with a readable banner on the tokens page, never as the HTTP 500 carrying
// a raw `UNIQUE constraint failed: tokens.name` that operators used to see.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/tokens"
)

func tokenPageServer(t *testing.T) (http.Handler, *testenv.Env) {
	t.Helper()
	env := testenv.New(t).WithOperator("test-pass", "test-op")
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := NewServer(
		env.Tokens, env.Connections, env.Roles,
		env.Registry, env.Approval, env.Audit,
		"", env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "127.0.0.1:0",
	)
	srv.SetAuth(env.Operator, env.Session)
	t.Cleanup(srv.Close)
	return srv.Handler(), env
}

func TestTokenCreate_LiveNameCollisionIs409WithBanner(t *testing.T) {
	handler, env := tokenPageServer(t)
	role, err := env.Roles.Create("r", nil)
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	form := url.Values{"name": {"taxes-agent"}, "role_id": {role.ID}}
	if rec := formPost(handler, env, "/tokens/create", form); rec.Code != http.StatusOK {
		t.Fatalf("first create: code = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec := formPost(handler, env, "/tokens/create", form)
	if rec.Code != http.StatusConflict {
		t.Errorf("code = %d, want 409", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "UNIQUE constraint") {
		t.Errorf("response leaks the SQL constraint error:\n%s", body)
	}
	if !strings.Contains(body, "already active") {
		t.Errorf("missing the explanatory banner:\n%s", body)
	}
	// The banner must come back as the tokens page, not a bare error page, so
	// the operator can see the clashing token and act on it.
	if !strings.Contains(body, "Create Token") {
		t.Error("409 did not re-render the tokens page")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html (it must be set before WriteHeader)", ct)
	}
}

func TestTokenCreate_NameReusedAfterRevokeOverHTTP(t *testing.T) {
	handler, env := tokenPageServer(t)
	role, err := env.Roles.Create("r", nil)
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	form := url.Values{"name": {"taxes-agent"}, "role_id": {role.ID}}
	if rec := formPost(handler, env, "/tokens/create", form); rec.Code != http.StatusOK {
		t.Fatalf("first create: %d", rec.Code)
	}

	all, err := env.Tokens.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("list: %v (%d tokens)", err, len(all))
	}
	if rec := formPost(handler, env, "/tokens/"+all[0].ID+"/revoke", url.Values{}); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: code = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec := formPost(handler, env, "/tokens/create", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("recreate after revoke: code = %d, body = %s", rec.Code, rec.Body.String())
	}
	// The whole point: the operator gets a usable token back, not an error.
	if !strings.Contains(rec.Body.String(), "sieve_tok_") {
		t.Error("recreate did not show a new plaintext token")
	}
}

func TestTokenCreate_EmptyNameIs400(t *testing.T) {
	handler, env := tokenPageServer(t)
	role, err := env.Roles.Create("r", nil)
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	rec := formPost(handler, env, "/tokens/create", url.Values{
		"name": {"  "}, "role_id": {role.ID},
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", rec.Code)
	}
	if _, err := env.Tokens.Create(&tokens.CreateRequest{Name: "", RoleID: role.ID}); err == nil {
		t.Error("service still accepts an empty name")
	}
}

// TestAuditPage_ShowsTokenID: with names reusable, the name alone no longer
// identifies which token acted, so the audit view must also show the token id.
// "operator" and "system" are sentinel actors, not ids, and must stay hidden.
func TestAuditPage_ShowsTokenID(t *testing.T) {
	handler, env := tokenPageServer(t)

	if err := env.Audit.Log(&audit.LogRequest{
		TokenID:      "abc123def456",
		TokenName:    "taxes-agent",
		ConnectionID: "c1",
		Operation:    "list_emails",
		PolicyResult: "allow",
	}); err != nil {
		t.Fatalf("log agent entry: %v", err)
	}
	if err := env.Audit.LogOperator("test-op", "token.create", "t1", nil, "success"); err != nil {
		t.Fatalf("log operator entry: %v", err)
	}

	rec := getRequest(handler, env, "/audit")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /audit: %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "abc123def456") {
		t.Error("audit page does not show the token id; the name alone is now ambiguous")
	}
	if !strings.Contains(body, "taxes-agent") {
		t.Error("audit page lost the token name")
	}
	if strings.Contains(body, ">operator<") {
		t.Error("the 'operator' sentinel is rendered as if it were a token id")
	}
}
