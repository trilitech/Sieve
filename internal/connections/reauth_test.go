package connections_test

// Tests for the lifecycle signal (status=reauth_required + reauth_reason).
// The status enum subsumed what was previously a separate `needs_reauth`
// boolean; this file exercises the canonical writer (SetStatusWithReason)
// end-to-end via the same scenarios.

import (
	"testing"

	"github.com/trilitech/Sieve/internal/connections"
)

// TestReauthSignal_DefaultActive: a freshly-added connection is active
// with no reauth reason.
func TestReauthSignal_DefaultActive(t *testing.T) {
	svc, _ := setup(t)

	if err := svc.Add("conn", "mock", "Mock", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}
	c, err := svc.Get("conn")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if c.Status != connections.StatusActive {
		t.Errorf("freshly-added connection should be status=active, got %q", c.Status)
	}
	if c.ReauthReason != "" {
		t.Errorf("ReauthReason should be empty, got %q", c.ReauthReason)
	}
}

// TestSetReauthAndRecover exercises the full lifecycle:
// active → reauth_required (with reason) → active (reason cleared).
func TestSetReauthAndRecover(t *testing.T) {
	svc, _ := setup(t)

	if err := svc.Add("conn", "mock", "Mock", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}

	if err := svc.SetStatusWithReason("conn", connections.StatusReauthRequired, "invalid_grant: refresh token revoked"); err != nil {
		t.Fatalf("set reauth_required: %v", err)
	}

	c, err := svc.Get("conn")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if c.Status != connections.StatusReauthRequired {
		t.Errorf("expected status=reauth_required, got %q", c.Status)
	}
	if c.ReauthReason != "invalid_grant: refresh token revoked" {
		t.Errorf("ReauthReason = %q, want %q", c.ReauthReason, "invalid_grant: refresh token revoked")
	}

	// List must also surface the state — the web UI relies on it.
	all, err := svc.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found bool
	for _, lc := range all {
		if lc.ID == "conn" {
			found = true
			if lc.Status != connections.StatusReauthRequired {
				t.Errorf("List(): expected status=reauth_required, got %q", lc.Status)
			}
			if lc.ReauthReason == "" {
				t.Error("List(): expected non-empty ReauthReason")
			}
		}
	}
	if !found {
		t.Error("List() did not return our connection")
	}

	if err := svc.SetStatus("conn", connections.StatusActive); err != nil {
		t.Fatalf("set active: %v", err)
	}
	c, _ = svc.Get("conn")
	if c.Status != connections.StatusActive {
		t.Errorf("expected status=active after recovery, got %q", c.Status)
	}
	if c.ReauthReason != "" {
		t.Errorf("ReauthReason = %q after recovery, want empty", c.ReauthReason)
	}
}

// TestUpdateConfig_TransitionsToActive: a successful re-auth flow
// updates the config (with fresh OAuth tokens). UpdateConfig must
// transition status to 'active' and clear reauth_reason in the same
// statement so the UI doesn't keep showing the banner after the user
// completed the OAuth round-trip.
func TestUpdateConfig_TransitionsToActive(t *testing.T) {
	svc, _ := setup(t)

	if err := svc.Add("conn", "mock", "Mock", map[string]any{}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := svc.SetStatusWithReason("conn", connections.StatusReauthRequired, "invalid_grant"); err != nil {
		t.Fatalf("set reauth_required: %v", err)
	}

	if err := svc.UpdateConfig("conn", map[string]any{"updated": true}); err != nil {
		t.Fatalf("update: %v", err)
	}

	c, err := svc.Get("conn")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if c.Status != connections.StatusActive {
		t.Errorf("UpdateConfig should have transitioned status to active, got %q", c.Status)
	}
	if c.ReauthReason != "" {
		t.Errorf("UpdateConfig should have cleared ReauthReason, got %q", c.ReauthReason)
	}
}

// TestSetStatusWithReason_GoneConnection: writing status on a deleted
// connection is a silent no-op. The refresh-failure callback can fire
// after the operator clicked Delete; we don't want a benign race to
// surface as an error log.
func TestSetStatusWithReason_GoneConnection(t *testing.T) {
	svc, _ := setup(t)
	if err := svc.SetStatusWithReason("never-existed", connections.StatusReauthRequired, "whatever"); err != nil {
		t.Errorf("SetStatusWithReason on missing connection should not error, got: %v", err)
	}
}
