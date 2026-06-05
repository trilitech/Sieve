package slack

import (
	"context"
	"testing"

	"github.com/trilitech/Sieve/internal/testing/mockslack"
)

// newConnectorForTest stands up a Slack Connector wired to the mock
// server. The terminalAuth callback flips a local flag tests can
// inspect to confirm the classifier fired.
func newConnectorForTest(t *testing.T, mock *mockslack.Server) (*Connector, *bool) {
	t.Helper()
	cfg := &Config{
		AuthKind: KindToken,
		BotToken: "xoxb-test-token",
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	terminalFired := new(bool)
	cli, err := newClient(cfg, mock.URL, func() { *terminalFired = true })
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return &Connector{cfg: cfg, client: cli}, terminalFired
}

// TestValidate_HappyPath asserts auth.test success populates the
// connector's TeamID/TeamName/BotUserID fields. Connection-creation
// flows depend on this — the admin's pasted token is rejected if
// auth.test doesn't return a team_id.
func TestValidate_HappyPath(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)

	c, terminalFired := newConnectorForTest(t, mock)
	if err := c.Validate(context.Background()); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.cfg.TeamID == "" {
		t.Fatal("expected team_id to be set after validate")
	}
	if c.cfg.BotUserID == "" {
		t.Fatal("expected bot_user_id to be set after validate")
	}
	if *terminalFired {
		t.Fatal("terminalAuth callback fired on success")
	}
}

// TestValidate_TerminalAuth asserts a Slack invalid_auth response
// fires the terminalAuth callback (so the upstream connections.Service
// flips status to reauth_required) and returns an error.
func TestValidate_TerminalAuth(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)
	mock.SetForceError("invalid_auth")

	c, terminalFired := newConnectorForTest(t, mock)
	if err := c.Validate(context.Background()); err == nil {
		t.Fatal("expected error on terminal-auth response")
	}
	if !*terminalFired {
		t.Fatal("expected terminalAuth callback to fire")
	}
}

// TestValidate_TransientError asserts a non-terminal error (rate
// limit etc.) does NOT fire the terminalAuth callback.
func TestValidate_TransientError(t *testing.T) {
	mock := mockslack.New()
	t.Cleanup(mock.Close)
	mock.SetForceError("ratelimited")

	c, terminalFired := newConnectorForTest(t, mock)
	if err := c.Validate(context.Background()); err == nil {
		t.Fatal("expected error on transient response")
	}
	if *terminalFired {
		t.Fatal("transient error must not fire terminalAuth callback")
	}
}
