package tokens_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/tokens"
)

func setup(t *testing.T) (*tokens.Service, *roles.Service) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return tokens.NewService(db), roles.NewService(db)
}

func TestCreateAndValidate(t *testing.T) {
	tokenSvc, roleSvc := setup(t)
	role, _ := roleSvc.Create("test-role", nil)

	result, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:   "my-token",
		RoleID: role.ID,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	if !strings.HasPrefix(result.PlaintextToken, "sieve_tok_") {
		t.Fatalf("expected sieve_tok_ prefix, got %q", result.PlaintextToken)
	}
	if result.Token.Name != "my-token" {
		t.Fatalf("expected name 'my-token', got %q", result.Token.Name)
	}
	if result.Token.RoleIDs[0] != role.ID {
		t.Fatalf("expected role ID %q, got %q", role.ID, result.Token.RoleIDs[0])
	}

	validated, err := tokenSvc.Validate(result.PlaintextToken)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if validated.ID != result.Token.ID {
		t.Fatalf("expected token ID %q, got %q", result.Token.ID, validated.ID)
	}
	if validated.RoleIDs[0] != role.ID {
		t.Fatalf("expected role ID %q, got %q", role.ID, validated.RoleIDs[0])
	}
}

func TestValidateInvalid(t *testing.T) {
	tokenSvc, _ := setup(t)

	_, err := tokenSvc.Validate("sieve_tok_totallygarbage1234567890abcdef")
	if err == nil {
		t.Fatal("expected error validating garbage token")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Fatalf("expected 'invalid token' error, got: %v", err)
	}
}

func TestRevoke(t *testing.T) {
	tokenSvc, roleSvc := setup(t)
	role, _ := roleSvc.Create("test-role", nil)

	result, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:   "revoke-me",
		RoleID: role.ID,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	if err := tokenSvc.Revoke(result.Token.ID); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	_, err = tokenSvc.Validate(result.PlaintextToken)
	if err == nil {
		t.Fatal("expected error validating revoked token")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Fatalf("expected 'invalid token' error, got: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	tokenSvc, roleSvc := setup(t)
	role, _ := roleSvc.Create("test-role", nil)

	result, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:      "short-lived",
		RoleID:    role.ID,
		ExpiresIn: 1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	// Wait for expiry.
	time.Sleep(10 * time.Millisecond)

	_, err = tokenSvc.Validate(result.PlaintextToken)
	if err == nil {
		t.Fatal("expected error validating expired token")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Fatalf("expected 'invalid token' error, got: %v", err)
	}
}

func TestList(t *testing.T) {
	tokenSvc, roleSvc := setup(t)
	role, _ := roleSvc.Create("test-role", nil)

	for i := 0; i < 3; i++ {
		_, err := tokenSvc.Create(&tokens.CreateRequest{
			Name:   "token-" + string(rune('a'+i)),
			RoleID: role.ID,
		})
		if err != nil {
			t.Fatalf("create token %d: %v", i, err)
		}
	}

	toks, err := tokenSvc.List()
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(toks) != 3 {
		t.Fatalf("expected 3 tokens, got %d", len(toks))
	}
}

func TestDelete(t *testing.T) {
	tokenSvc, roleSvc := setup(t)
	role, _ := roleSvc.Create("test-role", nil)

	result, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:   "delete-me",
		RoleID: role.ID,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	if err := tokenSvc.Delete(result.Token.ID); err != nil {
		t.Fatalf("delete token: %v", err)
	}

	_, err = tokenSvc.Get(result.Token.ID)
	if err == nil {
		t.Fatal("expected error getting deleted token")
	}
}

func TestDuplicateName(t *testing.T) {
	tokenSvc, roleSvc := setup(t)
	role, _ := roleSvc.Create("test-role", nil)

	_, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:   "same-name",
		RoleID: role.ID,
	})
	if err != nil {
		t.Fatalf("create first token: %v", err)
	}

	_, err = tokenSvc.Create(&tokens.CreateRequest{
		Name:   "same-name",
		RoleID: role.ID,
	})
	if err == nil {
		t.Fatal("expected error creating token with duplicate name")
	}
}

func TestValidateWrongPrefix(t *testing.T) {
	tokenSvc, _ := setup(t)

	// Token without the "sieve_tok_" prefix should fail validation.
	_, err := tokenSvc.Validate("wrong_prefix_1234567890abcdef0123456789abcdef")
	if err == nil {
		t.Fatal("expected error validating token without sieve_tok_ prefix")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Fatalf("expected 'invalid token' error, got: %v", err)
	}
}

func TestValidateEmptyString(t *testing.T) {
	tokenSvc, _ := setup(t)

	_, err := tokenSvc.Validate("")
	if err == nil {
		t.Fatal("expected error validating empty string")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Fatalf("expected 'invalid token' error, got: %v", err)
	}
}

func TestValidateFlippedByte(t *testing.T) {
	tokenSvc, roleSvc := setup(t)
	role, _ := roleSvc.Create("test-role", nil)

	result, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:   "flip-test",
		RoleID: role.ID,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	// Verify the original token validates.
	_, err = tokenSvc.Validate(result.PlaintextToken)
	if err != nil {
		t.Fatalf("expected valid token to validate, got: %v", err)
	}

	// Flip one byte in the token (after the prefix).
	tokenBytes := []byte(result.PlaintextToken)
	flipIdx := len("sieve_tok_") + 5 // flip a byte in the hex-encoded random part
	if tokenBytes[flipIdx] == 'a' {
		tokenBytes[flipIdx] = 'b'
	} else {
		tokenBytes[flipIdx] = 'a'
	}
	flipped := string(tokenBytes)

	if flipped == result.PlaintextToken {
		t.Fatal("flipped token should differ from original")
	}

	_, err = tokenSvc.Validate(flipped)
	if err == nil {
		t.Fatal("expected error validating token with flipped byte")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Fatalf("expected 'invalid token' error, got: %v", err)
	}
}

func TestCreateTokenEmptyName(t *testing.T) {
	tokenSvc, roleSvc := setup(t)
	role, _ := roleSvc.Create("test-role", nil)

	// Creating a token with an empty name should still work (no name validation).
	result, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:   "",
		RoleID: role.ID,
	})
	if err != nil {
		t.Fatalf("create token with empty name: %v", err)
	}
	if result.Token.Name != "" {
		t.Fatalf("expected empty name, got %q", result.Token.Name)
	}
	if !strings.HasPrefix(result.PlaintextToken, "sieve_tok_") {
		t.Fatalf("expected sieve_tok_ prefix, got %q", result.PlaintextToken)
	}

	// Validate it works.
	validated, err := tokenSvc.Validate(result.PlaintextToken)
	if err != nil {
		t.Fatalf("validate token with empty name: %v", err)
	}
	if validated.ID != result.Token.ID {
		t.Fatalf("expected token ID %q, got %q", result.Token.ID, validated.ID)
	}
}

// --- User story tests ---

// Story 134: Expired token returns error.
func TestStory134_ExpiredTokenReturnsError(t *testing.T) {
	tokenSvc, roleSvc := setup(t)
	role, _ := roleSvc.Create("test-role", nil)

	result, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:      "expired-token",
		RoleID:    role.ID,
		ExpiresIn: 1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	_, err = tokenSvc.Validate(result.PlaintextToken)
	if err == nil {
		t.Fatal("story 134: expected error validating expired token")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Fatalf("story 134: expected 'invalid token' error, got: %v", err)
	}
}

// Story 135: Revoked token returns same generic "invalid token" error.
func TestStory135_RevokedTokenReturnsSameError(t *testing.T) {
	tokenSvc, roleSvc := setup(t)
	role, _ := roleSvc.Create("test-role", nil)

	result, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:   "revoke-me",
		RoleID: role.ID,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	if err := tokenSvc.Revoke(result.Token.ID); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	_, err = tokenSvc.Validate(result.PlaintextToken)
	if err == nil {
		t.Fatal("story 135: expected error validating revoked token")
	}
	// Revoked tokens must return the same generic error as expired/invalid tokens
	// to prevent enumeration attacks.
	if err.Error() != "invalid token" {
		t.Fatalf("story 135: revoked token must return exactly 'invalid token', got %q", err.Error())
	}
}

// Story 142: Token without sieve_tok_ prefix is hash-looked-up and returns invalid.
func TestStory142_TokenWithoutPrefixReturnsInvalid(t *testing.T) {
	tokenSvc, _ := setup(t)

	_, err := tokenSvc.Validate("no_prefix_here_1234567890abcdef1234567890abcdef")
	if err == nil {
		t.Fatal("story 142: expected error validating token without sieve_tok_ prefix")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Fatalf("story 142: expected 'invalid token' error, got: %v", err)
	}
}

// Story 18: Duplicate token name fails with error.
func TestStory18_DuplicateTokenNameFails(t *testing.T) {
	tokenSvc, roleSvc := setup(t)
	role, _ := roleSvc.Create("test-role", nil)

	_, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:   "unique-name",
		RoleID: role.ID,
	})
	if err != nil {
		t.Fatalf("create first token: %v", err)
	}

	_, err = tokenSvc.Create(&tokens.CreateRequest{
		Name:   "unique-name",
		RoleID: role.ID,
	})
	if err == nil {
		t.Fatal("story 18: expected error creating token with duplicate name")
	}
}

// Story 16: Create token with no expiry, verify ExpiresAt is nil.
func TestStory16_NoExpiryTokenHasNilExpiresAt(t *testing.T) {
	tokenSvc, roleSvc := setup(t)
	role, _ := roleSvc.Create("test-role", nil)

	result, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:   "no-expiry",
		RoleID: role.ID,
		// ExpiresIn is zero (default) — no expiry
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	if result.Token.ExpiresAt != nil {
		t.Fatalf("story 16: expected nil ExpiresAt for no-expiry token, got %v", *result.Token.ExpiresAt)
	}

	// Also verify via Get.
	got, err := tokenSvc.Get(result.Token.ID)
	if err != nil {
		t.Fatalf("get token: %v", err)
	}
	if got.ExpiresAt != nil {
		t.Fatalf("story 16: expected nil ExpiresAt after Get, got %v", *got.ExpiresAt)
	}

	// Validate should succeed (no expiry = never expires).
	_, err = tokenSvc.Validate(result.PlaintextToken)
	if err != nil {
		t.Fatalf("story 16: validate no-expiry token should succeed: %v", err)
	}
}

// Story 15: Create token with 24h expiry, verify ExpiresAt is ~24h from now.
func TestStory15_24hExpiryToken(t *testing.T) {
	tokenSvc, roleSvc := setup(t)
	role, _ := roleSvc.Create("test-role", nil)

	before := time.Now().UTC()
	result, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:      "24h-token",
		RoleID:    role.ID,
		ExpiresIn: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	after := time.Now().UTC()

	if result.Token.ExpiresAt == nil {
		t.Fatal("story 15: expected non-nil ExpiresAt for 24h expiry token")
	}

	expected := before.Add(24 * time.Hour)
	upperBound := after.Add(24 * time.Hour)

	if result.Token.ExpiresAt.Before(expected) {
		t.Fatalf("story 15: ExpiresAt %v is before expected lower bound %v", *result.Token.ExpiresAt, expected)
	}
	if result.Token.ExpiresAt.After(upperBound) {
		t.Fatalf("story 15: ExpiresAt %v is after expected upper bound %v", *result.Token.ExpiresAt, upperBound)
	}

	// The token should still be valid now (24h hasn't passed).
	_, err = tokenSvc.Validate(result.PlaintextToken)
	if err != nil {
		t.Fatalf("story 15: token with 24h expiry should be valid now: %v", err)
	}
}

// Story 19: Revoke token, verify subsequent Validate returns error.
func TestStory19_RevokeTokenValidateFails(t *testing.T) {
	tokenSvc, roleSvc := setup(t)
	role, _ := roleSvc.Create("test-role", nil)

	result, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:   "revoke-test-19",
		RoleID: role.ID,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	// Validate should work before revocation.
	_, err = tokenSvc.Validate(result.PlaintextToken)
	if err != nil {
		t.Fatalf("story 19: validate before revoke should succeed: %v", err)
	}

	// Revoke the token.
	if err := tokenSvc.Revoke(result.Token.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Validate should now fail.
	_, err = tokenSvc.Validate(result.PlaintextToken)
	if err == nil {
		t.Fatal("story 19: validate should fail after revoke")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Fatalf("story 19: expected 'invalid token' error, got: %v", err)
	}

	// Token should still exist via Get (not deleted, just revoked).
	got, err := tokenSvc.Get(result.Token.ID)
	if err != nil {
		t.Fatalf("story 19: Get should still return revoked token: %v", err)
	}
	if !got.Revoked {
		t.Fatal("story 19: expected Revoked=true")
	}
}

func TestCreateTokenNonexistentRole(t *testing.T) {
	tokenSvc, _ := setup(t)

	// Tokens don't validate role existence at creation time.
	result, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:   "orphan-token",
		RoleID: "nonexistent-role-id",
	})
	if err != nil {
		t.Fatalf("create token with nonexistent role: %v", err)
	}
	if result.Token.RoleIDs[0] != "nonexistent-role-id" {
		t.Fatalf("expected role ID 'nonexistent-role-id', got %q", result.Token.RoleIDs[0])
	}

	// The token should still validate (token validation doesn't check role).
	validated, err := tokenSvc.Validate(result.PlaintextToken)
	if err != nil {
		t.Fatalf("validate token with nonexistent role: %v", err)
	}
	if validated.RoleIDs[0] != "nonexistent-role-id" {
		t.Fatalf("expected role ID 'nonexistent-role-id', got %q", validated.RoleIDs[0])
	}
}
