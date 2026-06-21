// Command testserver starts a Sieve web UI + API server backed by a temporary
// SQLite database and mock connectors, for use by Playwright e2e tests.
// It prints the server URLs to stdout as JSON and blocks until killed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/approval"
	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/connector"
	anthropicconn "github.com/trilitech/Sieve/internal/connectors/anthropic"
	githubconn "github.com/trilitech/Sieve/internal/connectors/github"
	gmailconn "github.com/trilitech/Sieve/internal/connectors/gmail"
	httpproxyconn "github.com/trilitech/Sieve/internal/connectors/httpproxy"
	slackconn "github.com/trilitech/Sieve/internal/connectors/slack"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/operator"
	"github.com/trilitech/Sieve/internal/policy"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/secrets"
	"github.com/trilitech/Sieve/internal/session"
	"github.com/trilitech/Sieve/internal/settings"
	mockconn "github.com/trilitech/Sieve/internal/testing/mockconnector"
	"github.com/trilitech/Sieve/internal/tokens"
	"github.com/trilitech/Sieve/internal/web"

	"github.com/trilitech/Sieve/internal/database"
)

func main() {
	testPassphrase := flag.String("test-passphrase", "e2e-test-passphrase",
		"passphrase for the in-memory keyring; e2e tests run unattended")
	flag.Parse()

	dir, err := os.MkdirTemp("", "sieve-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	dbPath := filepath.Join(dir, "test.db")
	db, err := database.New(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create db: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Set up an in-memory keyring with the test passphrase. Production
	// startup uses interactive prompt or systemd LoadCredential — never an
	// argument flag.
	keyring := &secrets.Keyring{}
	saved := secrets.DefaultArgon2Params
	secrets.DefaultArgon2Params = secrets.Argon2Params{Time: 1, Memory: 8, Threads: 1, KeyLen: 32}
	if err := keyring.Setup(db.DB, []byte(*testPassphrase)); err != nil {
		fmt.Fprintf(os.Stderr, "keyring setup: %v\n", err)
		os.Exit(1)
	}
	secrets.DefaultArgon2Params = saved

	// Allowlist an available Python (and Node, if present) so authored
	// script_guard/script_filter policies actually execute in the demo / e2e
	// (prod ships /opt/sieve-py and uses the bundled default).
	var allowCmds []string
	if py, lerr := exec.LookPath("python3"); lerr == nil {
		allowCmds = append(allowCmds, py)
	}
	if nd, lerr := exec.LookPath("node"); lerr == nil {
		allowCmds = append(allowCmds, nd)
	}
	if len(allowCmds) > 0 {
		policy.SetCommandAllowlist(allowCmds)
	}

	// Provide a writable scripts directory with sample guards so an operator
	// poking the demo can create a script_guard/filter without prod's
	// /opt/sieve-py path allowlist. (Demo only — prod uses the bundled dir.)
	scriptDir := filepath.Join(dir, "scripts")
	must(os.MkdirAll(scriptDir, 0o755))
	const sampleGuardPy = `import sys, json
# Sample script_guard (Python): deny a send whose body contains "secret".
req = json.load(sys.stdin)
body = ((req.get("params") or {}).get("body")) or ""
print(json.dumps({"action": "deny", "reason": "blocked: contains 'secret'"}
                 if "secret" in body.lower() else {"action": "allow"}))
`
	const sampleGuardJS = `// Sample script_guard (JavaScript): deny a send whose body contains "secret".
const req = JSON.parse(require('fs').readFileSync(0, 'utf8') || '{}');
const body = ((req.params || {}).body || '').toLowerCase();
console.log(JSON.stringify(body.includes('secret')
  ? {action: 'deny', reason: "blocked: contains 'secret'"}
  : {action: 'allow'}));
`
	must(os.WriteFile(filepath.Join(scriptDir, "block_secret.py"), []byte(sampleGuardPy), 0o600))
	must(os.WriteFile(filepath.Join(scriptDir, "block_secret.js"), []byte(sampleGuardJS), 0o600))
	policy.SetScriptDirs([]string{scriptDir})

	// Set up mock connector registry.
	registry := connector.NewRegistry()
	mock := mockconn.New("mock")
	registry.Register(mock.Meta(), mock.Factory())
	registry.Register(githubconn.Meta(), githubconn.Factory())
	registry.Register(slackconn.Meta(), slackconn.Factory())
	registry.Register(gmailconn.Meta, gmailconn.Factory)
	registry.Register(httpproxyconn.Meta, httpproxyconn.Factory)
	registry.Register(anthropicconn.Meta(), anthropicconn.Factory())

	// Create all services.
	connSvc := connections.NewService(db, registry, keyring)
	tokenSvc := tokens.NewService(db)
	iamSvc := iampolicies.NewService(db)
	rolesSvc := roles.NewService(db)
	approvalQ := approval.NewQueue(db)
	auditLog := audit.NewLogger(db)
	settingsSvc := settings.NewService(db)
	scriptgenSvc := scriptgen.NewService(connSvc, settingsSvc)

	// --- Seed minimal test data ---

	// One connection so the UI has something to bind to.
	must(connSvc.Add("test-conn", "mock", "Test Connection", map[string]any{}))

	// A second connection for multi-binding tests.
	must(connSvc.Add("second-conn", "mock", "Second Connection", map[string]any{}))

	// A third connection seeded into status='reauth_required' for the
	// Playwright assertions: the UI MUST show exactly one badge — never
	// a contradictory "Active" pill alongside the "Reauth required" one.
	must(connSvc.Add("reauth-conn", "mock", "Needs Re-auth", map[string]any{}))
	must(connSvc.SetStatusWithReason("reauth-conn", connections.StatusReauthRequired, "seeded for e2e reauth_required assertion"))

	// A pre-built IAM role + a read-only grant on test-conn (IAM is the engine).
	role, err := rolesSvc.Create("seed-role", nil)
	mustErr(err, "create role")
	grantCedar, err := iampolicies.BuildRuleCedar(iampolicies.RuleSpec{
		RoleID: role.ID, Effect: "allow", ConnectorType: "mock",
		OpScope: "read", ConnectionIDs: []string{"test-conn"},
	}, nil)
	mustErr(err, "build seed grant")
	_, err = iamSvc.CreatePolicy("seed-read", "", grantCedar, true)
	mustErr(err, "create seed grant")

	tokResult, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:    "seed-token",
		RoleIDs: []string{role.ID},
	})
	mustErr(err, "create token")

	// Two pending approvals.
	_, err = approvalQ.Submit(&approval.SubmitRequest{
		TokenID: tokResult.Token.ID, ConnectionID: "test-conn",
		Operation:   "send_email",
		RequestData: map[string]any{"to": "alice@test.com", "subject": "Approval 1", "body": "body1"},
	})
	mustErr(err, "submit approval 1")
	_, err = approvalQ.Submit(&approval.SubmitRequest{
		TokenID: tokResult.Token.ID, ConnectionID: "test-conn",
		Operation:   "send_email",
		RequestData: map[string]any{"to": "bob@test.com", "subject": "Approval 2", "body": "body2"},
	})
	mustErr(err, "submit approval 2")

	// A few audit entries.
	for _, op := range []string{"list_emails", "read_email", "send_email"} {
		auditLog.Log(&audit.LogRequest{
			TokenID: tokResult.Token.ID, TokenName: "seed-token",
			ConnectionID: "test-conn", Operation: op,
			PolicyResult: "allow", DurationMs: 50,
		})
	}

	// --- Start web UI server ---
	// Bind the listener first so we know the port; the rotation-form
	// Origin allow-list (passed into NewServer) needs the concrete
	// host:port to validate cross-origin POSTs.
	webBind := os.Getenv("SIEVE_WEB_ADDR")
	if webBind == "" {
		webBind = "127.0.0.1:0"
	}
	webListener, err := net.Listen("tcp", webBind)
	mustErr(err, "web listen")
	webPort := webListener.Addr().(*net.TCPAddr).Port
	webAddr := fmt.Sprintf("127.0.0.1:%d", webPort)
	webSrv := web.NewServer(
		tokenSvc, connSvc, rolesSvc, registry,
		approvalQ, auditLog, "", settingsSvc, scriptgenSvc,
		keyring, db, webAddr,
	)
	defer webSrv.Close()

	// IAM is the sole authorization engine.
	must(settingsSvc.Set("iam_enabled", "true"))
	webSrv.SetIAM(iamSvc, registry, settingsSvc)

	// --- Start API server ---
	apiRouter := api.NewRouter(tokenSvc, connSvc, iamSvc, registry, rolesSvc, approvalQ, auditLog)
	apiBind := os.Getenv("SIEVE_API_ADDR")
	if apiBind == "" {
		apiBind = "127.0.0.1:0"
	}
	apiListener, err := net.Listen("tcp", apiBind)
	mustErr(err, "api listen")
	apiPort := apiListener.Addr().(*net.TCPAddr).Port

	go http.Serve(apiListener, apiRouter.Handler())

	// Operator auth so the admin UI is reachable in e2e (mirrors production;
	// requireOperatorSession fails closed without it). Tests log in via
	// helpers.loginOperator with the credential below.
	const operatorCredential = "e2e-operator-pass"
	opSvc := operator.NewService(db)
	opSvc.Time, opSvc.MemoryKiB, opSvc.Parallelism = operator.FastParams()
	mustErr(opSvc.Setup(operatorCredential, "e2e-operator"), "operator setup")
	sessionMgr := session.NewManager(db, 0)
	webSrv.SetAuth(opSvc, sessionMgr)

	// Output server info.
	info := map[string]any{
		"web_url":             fmt.Sprintf("http://127.0.0.1:%d", webPort),
		"api_url":             fmt.Sprintf("http://127.0.0.1:%d", apiPort),
		"seed_token":          tokResult.PlaintextToken,
		"seed_token_id":       tokResult.Token.ID,
		"seed_role_id":        role.ID,
		"operator_credential": operatorCredential,
	}
	infoJSON, _ := json.Marshal(info)
	fmt.Println(string(infoJSON))
	os.Stdout.Sync()

	if err := http.Serve(webListener, webSrv.Handler()); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
	_ = time.Now() // keep import
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func mustErr(err error, context string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", context, err)
		os.Exit(1)
	}
}
