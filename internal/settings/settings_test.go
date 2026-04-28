package settings_test

import (
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/settings"
)

func setup(t *testing.T) *settings.Service {
	t.Helper()
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return settings.NewService(db)
}

func TestGetMissing(t *testing.T) {
	svc := setup(t)

	val, err := svc.Get("nonexistent")
	if err != nil {
		t.Fatalf("get missing: %v", err)
	}
	if val != "" {
		t.Fatalf("expected empty string, got %q", val)
	}
}

func TestSetAndGet(t *testing.T) {
	svc := setup(t)

	if err := svc.Set("llm_model", "claude-sonnet"); err != nil {
		t.Fatalf("set: %v", err)
	}

	val, err := svc.Get("llm_model")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if val != "claude-sonnet" {
		t.Fatalf("expected 'claude-sonnet', got %q", val)
	}
}

func TestSetOverwrite(t *testing.T) {
	svc := setup(t)

	if err := svc.Set("llm_model", "old-model"); err != nil {
		t.Fatalf("set first: %v", err)
	}
	if err := svc.Set("llm_model", "new-model"); err != nil {
		t.Fatalf("set second: %v", err)
	}

	val, err := svc.Get("llm_model")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if val != "new-model" {
		t.Fatalf("expected 'new-model', got %q", val)
	}
}

func TestGetAll(t *testing.T) {
	svc := setup(t)

	if err := svc.Set("key1", "val1"); err != nil {
		t.Fatalf("set key1: %v", err)
	}
	if err := svc.Set("key2", "val2"); err != nil {
		t.Fatalf("set key2: %v", err)
	}

	all, err := svc.GetAll()
	if err != nil {
		t.Fatalf("get all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 settings, got %d", len(all))
	}
	if all["key1"] != "val1" {
		t.Fatalf("expected key1=val1, got %q", all["key1"])
	}
	if all["key2"] != "val2" {
		t.Fatalf("expected key2=val2, got %q", all["key2"])
	}
}

func TestGetAllEmpty(t *testing.T) {
	svc := setup(t)

	all, err := svc.GetAll()
	if err != nil {
		t.Fatalf("get all: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected 0 settings, got %d", len(all))
	}
}
