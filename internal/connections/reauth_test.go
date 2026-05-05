package connections_test

import (
	"testing"
)

// TestNeedsReauth_DefaultFalse: a freshly-added connection should not be
// flagged. Cheap regression guard for the migration default.
func TestNeedsReauth_DefaultFalse(t *testing.T) {
	svc, _ := setup(t)

	if err := svc.Add("conn", "mock", "Mock", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}
	c, err := svc.Get("conn")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if c.NeedsReauth {
		t.Errorf("freshly-added connection should not be flagged needs_reauth")
	}
	if c.ReauthReason != "" {
		t.Errorf("ReauthReason should be empty, got %q", c.ReauthReason)
	}
}

func TestMarkAndClearNeedsReauth(t *testing.T) {
	svc, _ := setup(t)

	if err := svc.Add("conn", "mock", "Mock", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}

	if err := svc.MarkNeedsReauth("conn", "invalid_grant: refresh token revoked"); err != nil {
		t.Fatalf("mark: %v", err)
	}

	c, err := svc.Get("conn")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !c.NeedsReauth {
		t.Error("expected NeedsReauth=true after Mark")
	}
	if c.ReauthReason != "invalid_grant: refresh token revoked" {
		t.Errorf("ReauthReason = %q, want %q", c.ReauthReason, "invalid_grant: refresh token revoked")
	}

	// List must also surface the flag — the web UI relies on it.
	all, err := svc.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found bool
	for _, lc := range all {
		if lc.ID == "conn" {
			found = true
			if !lc.NeedsReauth {
				t.Error("List(): expected NeedsReauth=true")
			}
			if lc.ReauthReason == "" {
				t.Error("List(): expected non-empty ReauthReason")
			}
		}
	}
	if !found {
		t.Error("List() did not return our connection")
	}

	if err := svc.ClearNeedsReauth("conn"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	c, _ = svc.Get("conn")
	if c.NeedsReauth {
		t.Error("expected NeedsReauth=false after Clear")
	}
	if c.ReauthReason != "" {
		t.Errorf("ReauthReason = %q after Clear, want empty", c.ReauthReason)
	}
}

// TestUpdateConfig_ClearsNeedsReauth: a successful re-auth flow updates the
// config (with fresh OAuth tokens). UpdateConfig must clear the flag in the
// same statement so the UI doesn't keep showing the banner after the user
// completed the OAuth round-trip.
func TestUpdateConfig_ClearsNeedsReauth(t *testing.T) {
	svc, _ := setup(t)

	if err := svc.Add("conn", "mock", "Mock", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := svc.MarkNeedsReauth("conn", "invalid_grant"); err != nil {
		t.Fatalf("mark: %v", err)
	}

	if err := svc.UpdateConfig("conn", map[string]any{"updated": true}); err != nil {
		t.Fatalf("update: %v", err)
	}

	c, err := svc.Get("conn")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if c.NeedsReauth {
		t.Error("UpdateConfig should have cleared NeedsReauth")
	}
	if c.ReauthReason != "" {
		t.Errorf("UpdateConfig should have cleared ReauthReason, got %q", c.ReauthReason)
	}
}

// TestMarkNeedsReauth_GoneConnection: marking a deleted connection is a
// silent no-op. The refresh-failure callback can fire after the operator
// clicked Delete; we don't want a benign race to surface as an error log.
func TestMarkNeedsReauth_GoneConnection(t *testing.T) {
	svc, _ := setup(t)
	if err := svc.MarkNeedsReauth("never-existed", "whatever"); err != nil {
		t.Errorf("MarkNeedsReauth on missing connection should not error, got: %v", err)
	}
}
