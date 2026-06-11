package audit_test

import (
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// ): admin mutations
// must produce audit rows that identify the operator, never include
// plaintext bearer tokens or other one-time secrets.

func TestRedactSensitive_StripsKnownSecrets(t *testing.T) {
	in := map[string]any{
		"name":              "alice-token",
		"role_id":           "role-123",
		"plaintext_token":   "sieve_tok_REAL_SECRET_64HEX",
		"bot_token":         "xoxb-real-secret",
		"client_secret":     "shhh",
		"oauth_secret":      "abcdef",
		"private_key_pem":   "-----BEGIN PRIVATE KEY-----...",
		"current_passphrase": "old-pass",
		"new_passphrase":    "new-pass",
		"password":          "swordfish",
	}
	out := audit.RedactSensitive(in)
	// Non-sensitive keys pass through.
	if out["name"] != "alice-token" {
		t.Errorf("name redacted: %v", out["name"])
	}
	if out["role_id"] != "role-123" {
		t.Errorf("role_id redacted: %v", out["role_id"])
	}
	// Every sensitive key replaced with the sentinel.
	for _, k := range []string{
		"plaintext_token", "bot_token", "client_secret",
		"oauth_secret", "private_key_pem", "current_passphrase",
		"new_passphrase", "password",
	} {
		if got := out[k]; got != "<redacted>" {
			t.Errorf("%s = %v, want <redacted>", k, got)
		}
	}
}

func TestRedactSensitive_NilSafe(t *testing.T) {
	if got := audit.RedactSensitive(nil); got != nil {
		t.Errorf("RedactSensitive(nil) = %v, want nil", got)
	}
}

func TestRedactSensitive_DoesNotMutateInput(t *testing.T) {
	in := map[string]any{"plaintext_token": "secret"}
	_ = audit.RedactSensitive(in)
	if in["plaintext_token"] != "secret" {
		t.Error("input map was mutated")
	}
}

func TestLogOperator_WritesAdminRow(t *testing.T) {
	env := testenv.New(t)
	logger := audit.NewLogger(env.DB)

	err := logger.LogOperator("alice-laptop", "token.create", "token-abc",
		map[string]any{
			"name":            "my-token",
			"role_id":         "role-1",
			"plaintext_token": "sieve_tok_REAL_SECRET",
		},
		"success",
	)
	if err != nil {
		t.Fatalf("LogOperator: %v", err)
	}
	rows, err := logger.List(&audit.ListFilter{Operation: "token.create"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d, want 1", len(rows))
	}
	r := rows[0]
	if r.ActorKind != "operator" {
		t.Errorf("ActorKind=%q, want operator", r.ActorKind)
	}
	if r.OperatorDisplayName != "alice-laptop" {
		t.Errorf("OperatorDisplayName=%q, want alice-laptop", r.OperatorDisplayName)
	}
	if r.Operation != "token.create" {
		t.Errorf("Operation=%q", r.Operation)
	}
	if r.PolicyResult != "success" {
		t.Errorf("PolicyResult=%q", r.PolicyResult)
	}
	// Plaintext secret must NOT appear in the row's params blob.
	if strings.Contains(r.Params, "sieve_tok_REAL_SECRET") {
		t.Fatalf("audit row leaks plaintext token: %s", r.Params)
	}
	// json.Marshal HTML-escapes "<" as "<" by default; either
	// form is acceptable as long as the sentinel is present.
	if !strings.Contains(r.Params, "redacted") {
		t.Errorf("audit row should contain redacted sentinel: %s", r.Params)
	}
}

func TestLog_AgentDefaultActorKind(t *testing.T) {
	env := testenv.New(t)
	logger := audit.NewLogger(env.DB)
	err := logger.Log(&audit.LogRequest{
		TokenID:      "tok-1",
		TokenName:    "agent-token",
		ConnectionID: "conn-1",
		Operation:    "list_emails",
		PolicyResult: "allow",
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := logger.List(&audit.ListFilter{Operation: "list_emails"})
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	if rows[0].ActorKind != "agent" {
		t.Errorf("ActorKind=%q, want agent (default)", rows[0].ActorKind)
	}
}
