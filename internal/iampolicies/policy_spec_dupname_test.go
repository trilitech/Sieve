package iampolicies

import (
	"errors"
	"testing"
)

const specCedar = `permit(principal in Sieve::Role::"r1", action in Sieve::Action::"read", resource in Sieve::Connection::"c1");`

// TestCreatePolicyWithSpec_Atomic proves the enforced Cedar and the reloadable
// form-state are stored together (review (f): no create+SetPolicySpec desync).
func TestCreatePolicyWithSpec_Atomic(t *testing.T) {
	svc := NewService(testDB(t))
	pol, err := svc.CreatePolicyWithSpec("r", "d", specCedar, `{"form":"state"}`, true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetPolicy(pol.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cedar != specCedar {
		t.Errorf("cedar not stored: %q", got.Cedar)
	}
	if got.SpecJSON != `{"form":"state"}` {
		t.Errorf("spec not stored atomically: %q", got.SpecJSON)
	}
}

// TestUpdatePolicyWithSpec_Atomic proves an edit updates Cedar + form-state in
// one write, so the enforced rule and its reloadable form can't desync.
func TestUpdatePolicyWithSpec_Atomic(t *testing.T) {
	svc := NewService(testDB(t))
	pol, err := svc.CreatePolicyWithSpec("r", "d", specCedar, `{"v":1}`, true)
	if err != nil {
		t.Fatal(err)
	}
	newCedar := `permit(principal in Sieve::Role::"r1", action in Sieve::Action::"write", resource in Sieve::Connection::"c1");`
	if err := svc.UpdatePolicyWithSpec(pol.ID, "r2", "d2", newCedar, `{"v":2}`, true); err != nil {
		t.Fatal(err)
	}
	got, _ := svc.GetPolicy(pol.ID)
	if got.Cedar != newCedar || got.SpecJSON != `{"v":2}` || got.Name != "r2" {
		t.Errorf("update-with-spec desync: cedar=%q spec=%q name=%q", got.Cedar, got.SpecJSON, got.Name)
	}
}

// TestDuplicateName_Sentinel proves a colliding name surfaces ErrDuplicateName
// (review (g): handlers map it to a friendly banner/409 instead of a raw 500).
func TestDuplicateName_Sentinel(t *testing.T) {
	svc := NewService(testDB(t))
	if _, err := svc.CreatePolicy("dup", "d", specCedar, true); err != nil {
		t.Fatal(err)
	}
	// Same name via the plain create path (the raw-Cedar/advanced surface).
	_, err := svc.CreatePolicy("dup", "d", specCedar, true)
	if !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("want ErrDuplicateName, got %v", err)
	}
	// Same name via the atomic create path (the builder surface).
	_, err = svc.CreatePolicyWithSpec("dup", "d", specCedar, "{}", true)
	if !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("want ErrDuplicateName from WithSpec, got %v", err)
	}
	// And on update to a taken name.
	other, _ := svc.CreatePolicy("other", "d", specCedar, true)
	err = svc.UpdatePolicyWithSpec(other.ID, "dup", "d", specCedar, "{}", true)
	if !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("want ErrDuplicateName on update, got %v", err)
	}
}
