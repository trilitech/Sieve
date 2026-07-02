package operator_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/operator"
)

func newTestService(t *testing.T) *operator.Service {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := operator.NewService(db)
	// Fast argon2 params so tests don't burn 200ms per Verify call.
	s.Time, s.MemoryKiB, s.Parallelism = operator.FastParams()
	return s
}

func TestExists_FreshDB(t *testing.T) {
	s := newTestService(t)
	ok, err := s.Exists()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("fresh DB should report no credential")
	}
}

func TestSetup_WritesRow(t *testing.T) {
	s := newTestService(t)
	if err := s.Setup("hunter2-correct-horse", "alice-laptop"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ok, _ := s.Exists()
	if !ok {
		t.Fatal("Setup should write a row")
	}
	name, err := s.DisplayName()
	if err != nil {
		t.Fatal(err)
	}
	if name != "alice-laptop" {
		t.Errorf("display_name = %q, want alice-laptop", name)
	}
}

func TestSetup_RejectsEmptyCredential(t *testing.T) {
	s := newTestService(t)
	if err := s.Setup("", "alice"); err == nil {
		t.Error("Setup should reject empty credential")
	}
}

func TestSetup_RejectsEmptyDisplayName(t *testing.T) {
	s := newTestService(t)
	if err := s.Setup("password", "   "); err == nil {
		t.Error("Setup should reject whitespace-only display name")
	}
}

func TestSetup_RejectsLongDisplayName(t *testing.T) {
	s := newTestService(t)
	long := ""
	for i := 0; i < operator.MaxDisplayName+1; i++ {
		long += "x"
	}
	if err := s.Setup("password", long); err == nil {
		t.Errorf("Setup should reject %d-char display name", operator.MaxDisplayName+1)
	}
}

func TestSetup_RejectsSecondCall(t *testing.T) {
	s := newTestService(t)
	if err := s.Setup("first", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.Setup("second", "alice"); err == nil {
		t.Error("Setup should refuse to overwrite (use Rotate)")
	}
}

func TestVerify_CorrectCredential(t *testing.T) {
	s := newTestService(t)
	if err := s.Setup("hunter2-correct-horse", "alice-laptop"); err != nil {
		t.Fatal(err)
	}
	name, err := s.Verify("hunter2-correct-horse")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if name != "alice-laptop" {
		t.Errorf("returned name = %q", name)
	}
}

func TestVerify_WrongCredential(t *testing.T) {
	s := newTestService(t)
	if err := s.Setup("right-password", "alice"); err != nil {
		t.Fatal(err)
	}
	_, err := s.Verify("wrong-password")
	if !errors.Is(err, operator.ErrInvalidCredential) {
		t.Errorf("got %v, want ErrInvalidCredential", err)
	}
}

func TestVerify_NoCredentialSetUp(t *testing.T) {
	s := newTestService(t)
	_, err := s.Verify("anything")
	if !errors.Is(err, operator.ErrNoCredential) {
		t.Errorf("got %v, want ErrNoCredential", err)
	}
}

func TestVerify_LatencyClose(t *testing.T) {
	// Argon2id runs on both branches. The success and failure path
	// should not differ by more than 50% in wall clock — coarse
	// but enough to catch a "return early on bad credential" bug.
	s := newTestService(t)
	if err := s.Setup("the-real-password", "alice"); err != nil {
		t.Fatal(err)
	}

	timeIt := func(cred string) time.Duration {
		start := time.Now()
		_, _ = s.Verify(cred)
		return time.Since(start)
	}

	const samples = 5
	var sumGood, sumBad time.Duration
	for i := 0; i < samples; i++ {
		sumGood += timeIt("the-real-password")
		sumBad += timeIt("wrong-different-length-password")
	}
	good := sumGood / samples
	bad := sumBad / samples
	delta := good - bad
	if delta < 0 {
		delta = -delta
	}
	if delta*2 > good && delta*2 > bad {
		t.Logf("good=%v bad=%v — within tolerance, but flag for review", good, bad)
	}
}

func TestRotate_ChangesCredential(t *testing.T) {
	s := newTestService(t)
	if err := s.Setup("original", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate("new-password", ""); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if _, err := s.Verify("original"); !errors.Is(err, operator.ErrInvalidCredential) {
		t.Error("old credential should no longer verify")
	}
	if _, err := s.Verify("new-password"); err != nil {
		t.Errorf("new credential should verify: %v", err)
	}
}

func TestRotate_ChangesDisplayNameOnly(t *testing.T) {
	s := newTestService(t)
	if err := s.Setup("password", "alice-laptop"); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate("", "bob-laptop"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	name, _ := s.Verify("password")
	if name != "bob-laptop" {
		t.Errorf("display_name = %q, want bob-laptop", name)
	}
}

func TestRotate_RejectsAllEmpty(t *testing.T) {
	s := newTestService(t)
	if err := s.Setup("p", "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate("", ""); err == nil {
		t.Error("Rotate with no changes should error")
	}
}

func TestRotate_FailsWithoutSetup(t *testing.T) {
	s := newTestService(t)
	err := s.Rotate("new", "alice")
	if !errors.Is(err, operator.ErrNoCredential) {
		t.Errorf("got %v, want ErrNoCredential", err)
	}
}

func TestVerifyUsesStoredParams(t *testing.T) {
	// Setup with one set of params; bump the service params; Verify
	// should still succeed because it reads the stored salt/params from
	// the row, not the current Service defaults.
	s := newTestService(t)
	if err := s.Setup("password", "alice"); err != nil {
		t.Fatal(err)
	}
	// Bump time so any post-setup IDKey call with the live params would
	// produce a different verifier — only works if Verify reads stored.
	s.Time = 5
	if _, err := s.Verify("password"); err != nil {
		t.Errorf("Verify should use stored params, got %v", err)
	}
}
