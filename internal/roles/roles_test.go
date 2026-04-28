package roles_test

import (
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/tokens"
)

func setup(t *testing.T) *roles.Service {
	t.Helper()
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return roles.NewService(db)
}

func TestCreateAndGet(t *testing.T) {
	svc := setup(t)

	bindings := []roles.Binding{
		{ConnectionID: "conn-1", PolicyIDs: []string{"pol-a", "pol-b"}},
		{ConnectionID: "conn-2", PolicyIDs: []string{"pol-c"}},
	}

	role, err := svc.Create("my-role", bindings)
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if role.Name != "my-role" {
		t.Fatalf("expected name 'my-role', got %q", role.Name)
	}
	if len(role.Bindings) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(role.Bindings))
	}

	got, err := svc.Get(role.ID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if got.Name != "my-role" {
		t.Fatalf("expected name 'my-role', got %q", got.Name)
	}
	if len(got.Bindings) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(got.Bindings))
	}
	if got.Bindings[0].ConnectionID != "conn-1" {
		t.Fatalf("expected first binding conn-1, got %q", got.Bindings[0].ConnectionID)
	}
	if len(got.Bindings[0].PolicyIDs) != 2 {
		t.Fatalf("expected 2 policy IDs in first binding, got %d", len(got.Bindings[0].PolicyIDs))
	}
}

func TestGetByName(t *testing.T) {
	svc := setup(t)

	_, err := svc.Create("find-me", []roles.Binding{
		{ConnectionID: "conn-1", PolicyIDs: []string{"pol-a"}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	got, err := svc.GetByName("find-me")
	if err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if got.Name != "find-me" {
		t.Fatalf("expected name 'find-me', got %q", got.Name)
	}
}

func TestPoliciesForConnection(t *testing.T) {
	svc := setup(t)

	role, err := svc.Create("policies-test", []roles.Binding{
		{ConnectionID: "conn-1", PolicyIDs: []string{"pol-a", "pol-b"}},
		{ConnectionID: "conn-2", PolicyIDs: []string{"pol-c"}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	pols := role.PoliciesForConnection("conn-1")
	if len(pols) != 2 {
		t.Fatalf("expected 2 policies for conn-1, got %d", len(pols))
	}
	if pols[0] != "pol-a" || pols[1] != "pol-b" {
		t.Fatalf("unexpected policy IDs: %v", pols)
	}

	pols2 := role.PoliciesForConnection("conn-2")
	if len(pols2) != 1 || pols2[0] != "pol-c" {
		t.Fatalf("unexpected policies for conn-2: %v", pols2)
	}
}

func TestPoliciesForUnknownConnection(t *testing.T) {
	svc := setup(t)

	role, err := svc.Create("unknown-conn", []roles.Binding{
		{ConnectionID: "conn-1", PolicyIDs: []string{"pol-a"}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	pols := role.PoliciesForConnection("nonexistent")
	if pols != nil {
		t.Fatalf("expected nil for unknown connection, got %v", pols)
	}
}

func TestConnectionIDs(t *testing.T) {
	svc := setup(t)

	role, err := svc.Create("conn-ids", []roles.Binding{
		{ConnectionID: "conn-1", PolicyIDs: []string{"pol-a"}},
		{ConnectionID: "conn-2", PolicyIDs: []string{"pol-b"}},
		{ConnectionID: "conn-3", PolicyIDs: []string{"pol-c"}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	ids := role.ConnectionIDs()
	if len(ids) != 3 {
		t.Fatalf("expected 3 connection IDs, got %d", len(ids))
	}

	expected := map[string]bool{"conn-1": true, "conn-2": true, "conn-3": true}
	for _, id := range ids {
		if !expected[id] {
			t.Fatalf("unexpected connection ID: %q", id)
		}
	}
}

func TestUpdate(t *testing.T) {
	svc := setup(t)

	role, err := svc.Create("update-me", []roles.Binding{
		{ConnectionID: "conn-1", PolicyIDs: []string{"pol-a"}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	newBindings := []roles.Binding{
		{ConnectionID: "conn-1", PolicyIDs: []string{"pol-a", "pol-b"}},
		{ConnectionID: "conn-2", PolicyIDs: []string{"pol-c"}},
	}

	if err := svc.Update(role.ID, "updated-role", newBindings); err != nil {
		t.Fatalf("update role: %v", err)
	}

	got, err := svc.Get(role.ID)
	if err != nil {
		t.Fatalf("get updated role: %v", err)
	}
	if got.Name != "updated-role" {
		t.Fatalf("expected name 'updated-role', got %q", got.Name)
	}
	if len(got.Bindings) != 2 {
		t.Fatalf("expected 2 bindings after update, got %d", len(got.Bindings))
	}
	if len(got.Bindings[0].PolicyIDs) != 2 {
		t.Fatalf("expected 2 policy IDs in first binding, got %d", len(got.Bindings[0].PolicyIDs))
	}
}

func TestDelete(t *testing.T) {
	svc := setup(t)

	role, err := svc.Create("delete-me", []roles.Binding{
		{ConnectionID: "conn-1", PolicyIDs: []string{"pol-a"}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	if err := svc.Delete(role.ID); err != nil {
		t.Fatalf("delete role: %v", err)
	}

	_, err = svc.Get(role.ID)
	if err == nil {
		t.Fatal("expected error getting deleted role")
	}
}

func TestList(t *testing.T) {
	svc := setup(t)

	for i := 0; i < 3; i++ {
		name := "role-" + string(rune('a'+i))
		_, err := svc.Create(name, []roles.Binding{
			{ConnectionID: "conn-1", PolicyIDs: []string{"pol-a"}},
		})
		if err != nil {
			t.Fatalf("create role %d: %v", i, err)
		}
	}

	list, err := svc.List()
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 roles, got %d", len(list))
	}
}

// Story 29: Role with empty policy_ids means deny all — PoliciesForConnection returns empty slice.
func TestStory29_EmptyPolicyIDsMeansDenyAll(t *testing.T) {
	svc := setup(t)

	// Create a role with a binding that has empty policy_ids.
	role, err := svc.Create("empty-policies-role", []roles.Binding{
		{ConnectionID: "conn-1", PolicyIDs: []string{}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	// PoliciesForConnection should return an empty (non-nil) slice.
	pols := role.PoliciesForConnection("conn-1")
	if pols == nil {
		t.Fatal("story 29: expected non-nil empty slice for bound connection with no policies")
	}
	if len(pols) != 0 {
		t.Fatalf("story 29: expected 0 policies, got %d", len(pols))
	}

	// Verify the role persists correctly.
	got, err := svc.Get(role.ID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	gotPols := got.PoliciesForConnection("conn-1")
	if len(gotPols) != 0 {
		t.Fatalf("story 29: after reload, expected 0 policies, got %d", len(gotPols))
	}
}

// Story 35: Delete role, verify token still exists but role Get fails.
func TestStory35_DeleteRoleTokenSurvives(t *testing.T) {
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	roleSvc := roles.NewService(db)
	tokenSvc := tokens.NewService(db)

	// Create a role and a token referencing it.
	role, err := roleSvc.Create("delete-role-35", []roles.Binding{
		{ConnectionID: "conn-1", PolicyIDs: []string{"pol-a"}},
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	result, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:   "orphan-tok",
		RoleID: role.ID,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	// Delete the role.
	if err := roleSvc.Delete(role.ID); err != nil {
		t.Fatalf("delete role: %v", err)
	}

	// Role Get should fail.
	_, err = roleSvc.Get(role.ID)
	if err == nil {
		t.Fatal("story 35: expected error getting deleted role")
	}

	// Token should still exist in the tokens table.
	tok, err := tokenSvc.Get(result.Token.ID)
	if err != nil {
		t.Fatalf("story 35: token should still exist after role deletion: %v", err)
	}
	if tok.ID != result.Token.ID {
		t.Fatalf("story 35: token ID mismatch: expected %q, got %q", result.Token.ID, tok.ID)
	}
	if tok.RoleID != role.ID {
		t.Fatalf("story 35: token still references deleted role ID %q, got %q", role.ID, tok.RoleID)
	}

	// Token Validate should also still work (it doesn't check role existence).
	validated, err := tokenSvc.Validate(result.PlaintextToken)
	if err != nil {
		t.Fatalf("story 35: validate should succeed for token with deleted role: %v", err)
	}
	if validated.RoleID != role.ID {
		t.Fatalf("story 35: validated token role ID mismatch")
	}
}
