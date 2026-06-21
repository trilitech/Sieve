// Package testenv provides a complete Sieve test environment with an
// in-memory database, mock connectors, and all services initialized.
package testenv

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/approval"
	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/operator"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/secrets"
	"github.com/trilitech/Sieve/internal/session"
	"github.com/trilitech/Sieve/internal/settings"
	mockconn "github.com/trilitech/Sieve/internal/testing/mockconnector"
	"github.com/trilitech/Sieve/internal/tokens"
)

// Env holds all Sieve services for testing.
type Env struct {
	DB          *database.DB
	Connections *connections.Service
	Tokens      *tokens.Service
	IAM         *iampolicies.Service
	Roles       *roles.Service
	Approval    *approval.Queue
	Audit       *audit.Logger
	Settings    *settings.Service
	Registry    *connector.Registry
	Keyring     *secrets.Keyring
	Mock        *mockconn.Mock
	DBPath      string

	// Operator + session services for tests that need to drive the
	// authenticated admin surface. Populated by New with fast Argon2id
	// params so tests don't burn 200ms per Verify. WithOperator seeds
	// the credential and returns a logged-in session; the per-Env
	// operatorActive field caches it so AdminClient attaches the
	// session cookie + CSRF token automatically.
	Operator       *operator.Service
	Session        *session.Manager
	operatorActive *session.Session // populated by WithOperator
}

// New creates a fresh test environment with a temp database.
func New(t *testing.T) *Env {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("create test db: %v", err)
	}

	registry := connector.NewRegistry()
	mock := mockconn.New("mock")
	registry.Register(mock.Meta(), mock.Factory())

	// Tests must run unattended, so set up an in-memory keyring with a
	// fixed test passphrase. Production paths still require an admin
	// passphrase at startup.
	keyring := &secrets.Keyring{}
	saved := secrets.DefaultArgon2Params
	secrets.DefaultArgon2Params = secrets.Argon2Params{Time: 1, Memory: 8, Threads: 1, KeyLen: 32}
	if err := keyring.Setup(db.DB, []byte("test-passphrase")); err != nil {
		t.Fatalf("keyring setup: %v", err)
	}
	secrets.DefaultArgon2Params = saved

	connSvc := connections.NewService(db, registry, keyring)
	tokenSvc := tokens.NewService(db)
	iamSvc := iampolicies.NewService(db)
	rolesSvc := roles.NewService(db)
	approvalQ := approval.NewQueue(db)
	auditLog := audit.NewLogger(db)
	settingsSvc := settings.NewService(db)
	opSvc := operator.NewService(db)
	// Fast argon2 params so tests don't pay the production 150-300ms
	// Verify cost. The verifier shape is identical; only the latency
	// differs.
	opSvc.Time, opSvc.MemoryKiB, opSvc.Parallelism = operator.FastParams()
	sessionMgr := session.NewManager(db, 0) // default idle timeout (8h)

	t.Cleanup(func() {
		db.Close()
		os.Remove(dbPath)
	})

	return &Env{
		DB:          db,
		Connections: connSvc,
		Tokens:      tokenSvc,
		IAM:         iamSvc,
		Roles:       rolesSvc,
		Approval:    approvalQ,
		Audit:       auditLog,
		Settings:    settingsSvc,
		Registry:    registry,
		Keyring:     keyring,
		Mock:        mock,
		DBPath:      dbPath,
		Operator:    opSvc,
		Session:     sessionMgr,
	}
}

// WithOperator seeds the singleton operator_credential row and issues a
// live session that subsequent admin-authenticated calls can attach to
// via AdminClient. Idempotent across rotations within a single test:
// a second WithOperator call rotates the credential and re-issues the
// session.
// Returns the Env for fluent chaining: env := testenv.New(t).WithOperator("test-pass", "test-operator").
func (e *Env) WithOperator(credential, displayName string) *Env {
	// First call: Setup. Subsequent calls: rotate.
	exists, err := e.Operator.Exists()
	if err != nil {
		panic("testenv: operator.Exists: " + err.Error())
	}
	if !exists {
		if err := e.Operator.Setup(credential, displayName); err != nil {
			panic("testenv: operator.Setup: " + err.Error())
		}
	} else {
		if err := e.Operator.Rotate(credential, displayName); err != nil {
			panic("testenv: operator.Rotate: " + err.Error())
		}
		// Rotation invalidates active sessions.
		_ = e.Session.DeleteAll()
	}
	s, err := e.Session.Issue("127.0.0.1", "testenv")
	if err != nil {
		panic("testenv: session.Issue: " + err.Error())
	}
	e.operatorActive = s
	return e
}

// Login issues a fresh session (without rotating credentials) and
// returns the cookie a test should attach to subsequent admin requests.
// Most tests should prefer WithOperator — Login is for tests that
// explicitly drive multiple concurrent sessions or simulate logout.
func (e *Env) Login() *http.Cookie {
	if e.Session == nil {
		panic("testenv: Session manager nil — call New() first")
	}
	s, err := e.Session.Issue("127.0.0.1", "testenv")
	if err != nil {
		panic("testenv: Login: " + err.Error())
	}
	e.operatorActive = s
	return session.NewCookie(s.Plaintext, false /* not TLS in tests */)
}

// SessionCookie returns the http.Cookie carrying the active operator
// session. Used by tests to attach the cookie to requests. Returns nil
// if no operator session has been established via WithOperator or
// Login.
func (e *Env) SessionCookie() *http.Cookie {
	if e.operatorActive == nil {
		return nil
	}
	return session.NewCookie(e.operatorActive.Plaintext, false)
}

// AdminClient returns an *http.Client that automatically attaches the
// active operator session cookie + CSRF header to every request, and
// surfaces 3xx responses without following them (so tests can inspect
// the Location header on login / redirect outcomes).
// Tests use the pattern:
// env := testenv.New(t).WithOperator("p","a")
// srv.SetAuth(env.Operator, env.Session)
// ts := httptest.NewServer(srv.Handler)
// resp, err := env.AdminClient.Get(ts.URL + "/policies")
func (e *Env) AdminClient() *http.Client {
	cookie := e.SessionCookie()
	csrfToken := e.CSRFToken()
	return &http.Client{
		Transport: &csrfRoundTripper{
			cookie:    cookie,
			csrfToken: csrfToken,
			base:      http.DefaultTransport,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// csrfRoundTripper injects the session cookie + CSRF header into every
// outbound test request. Tests can use this to drive admin endpoints
// as if logged in.
type csrfRoundTripper struct {
	cookie    *http.Cookie
	csrfToken string
	base      http.RoundTripper
}

func (rt *csrfRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.cookie != nil {
		req.AddCookie(rt.cookie)
	}
	if rt.csrfToken != "" {
		// X-CSRF-Token header — accepted in addition to the form field.
		req.Header.Set("X-CSRF-Token", rt.csrfToken)
	}
	return rt.base.RoundTrip(req)
}

// CSRFToken returns the plaintext CSRF token bound to the active
// operator session. Tests attach this to state-changing requests via
// the X-CSRF-Token header (preferred for fetch-style callers) or the
// csrf_token form field.
func (e *Env) CSRFToken() string {
	if e.operatorActive == nil {
		return ""
	}
	return e.operatorActive.CSRFToken
}

// SetupConnectionAndRole creates a mock connection plus an IAM role granting
// access to it, enables IAM, and returns the role — the common setup for tests
// that need a working token. The legacy "read-only" policy name maps to a
// read-scoped IAM grant (writes denied); any other/no name grants all ops on the
// connection. Tests needing specific obligations add guardrails via e.IAM.
func (e *Env) SetupConnectionAndRole(t *testing.T, connID string, policyNames ...string) *roles.Role {
	t.Helper()

	if err := e.Connections.Add(connID, "mock", "Test Connection", map[string]any{}); err != nil {
		t.Fatalf("add connection: %v", err)
	}

	role, err := e.Roles.Create("test-role", nil)
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	// IAM grant: allow ops on this connection for the role. "read-only" → read
	// scope (preserves the legacy read-only intent); else all ops.
	opScope := "all"
	for _, n := range policyNames {
		if n == "read-only" {
			opScope = "read"
		}
	}
	cedar, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: role.ID, Effect: "allow", ConnectorType: "mock",
		OpScope: opScope, ConnectionIDs: []string{connID},
	}, e.Mock.Meta().Operations)
	if err != nil {
		t.Fatalf("build IAM grant: %v", err)
	}
	if _, err := e.IAM.CreatePolicy("test-grant-"+connID, "", cedar, true); err != nil {
		t.Fatalf("create IAM grant: %v", err)
	}
	if err := e.Settings.Set("iam_enabled", "true"); err != nil {
		t.Fatalf("enable iam: %v", err)
	}

	return role
}

// CreateToken creates a token for the given role and returns the plaintext.
func (e *Env) CreateToken(t *testing.T, roleID string) string {
	t.Helper()

	result, err := e.Tokens.Create(&tokens.CreateRequest{
		Name:    "test-token",
		RoleIDs: []string{roleID},
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	return result.PlaintextToken
}
