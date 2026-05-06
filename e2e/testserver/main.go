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
	"path/filepath"
	"time"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/approval"
	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/connector"
	githubconn "github.com/trilitech/Sieve/internal/connectors/github"
	"github.com/trilitech/Sieve/internal/policies"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/secrets"
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

	// Set up mock connector registry.
	registry := connector.NewRegistry()
	mock := mockconn.New("mock")
	registry.Register(mock.Meta(), mock.Factory())
	registry.Register(githubconn.Meta(), githubconn.Factory())

	// Create all services.
	connSvc := connections.NewService(db, registry, keyring)
	tokenSvc := tokens.NewService(db)
	policiesSvc := policies.NewService(db)
	rolesSvc := roles.NewService(db)
	approvalQ := approval.NewQueue(db)
	auditLog := audit.NewLogger(db)
	settingsSvc := settings.NewService(db)
	scriptgenSvc := scriptgen.NewService(connSvc, settingsSvc)

	if err := policiesSvc.SeedPresets(); err != nil {
		fmt.Fprintf(os.Stderr, "seed presets: %v\n", err)
		os.Exit(1)
	}

	// --- Seed minimal test data ---

	// One connection so the UI has something to bind to.
	must(connSvc.Add("test-conn", "mock", "Test Connection", map[string]any{}))

	// A second connection for multi-binding tests.
	must(connSvc.Add("second-conn", "mock", "Second Connection", map[string]any{}))

	// Get the read-only preset for a pre-built role+token.
	readOnly, err := policiesSvc.GetByName("read-only")
	mustErr(err, "get read-only")

	role, err := rolesSvc.Create("seed-role", []roles.Binding{
		{ConnectionID: "test-conn", PolicyIDs: []string{readOnly.ID}},
	})
	mustErr(err, "create role")

	tokResult, err := tokenSvc.Create(&tokens.CreateRequest{
		Name:   "seed-token",
		RoleID: role.ID,
	})
	mustErr(err, "create token")

	// Two pending approvals.
	_, err = approvalQ.Submit(&approval.SubmitRequest{
		TokenID: tokResult.Token.ID, ConnectionID: "test-conn",
		Operation: "send_email",
		RequestData: map[string]any{"to": "alice@test.com", "subject": "Approval 1", "body": "body1"},
	})
	mustErr(err, "submit approval 1")
	_, err = approvalQ.Submit(&approval.SubmitRequest{
		TokenID: tokResult.Token.ID, ConnectionID: "test-conn",
		Operation: "send_email",
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
	webListener, err := net.Listen("tcp", "127.0.0.1:0")
	mustErr(err, "web listen")
	webPort := webListener.Addr().(*net.TCPAddr).Port
	webAddr := fmt.Sprintf("127.0.0.1:%d", webPort)
	webSrv := web.NewServer(
		tokenSvc, connSvc, policiesSvc, rolesSvc, registry,
		approvalQ, auditLog, "", settingsSvc, scriptgenSvc,
		keyring, db, webAddr,
	)
	defer webSrv.Close()

	// --- Start API server ---
	apiRouter := api.NewRouter(tokenSvc, connSvc, policiesSvc, rolesSvc, approvalQ, auditLog)
	apiListener, err := net.Listen("tcp", "127.0.0.1:0")
	mustErr(err, "api listen")
	apiPort := apiListener.Addr().(*net.TCPAddr).Port

	go http.Serve(apiListener, apiRouter.Handler())

	// Output server info.
	info := map[string]any{
		"web_url":         fmt.Sprintf("http://127.0.0.1:%d", webPort),
		"api_url":         fmt.Sprintf("http://127.0.0.1:%d", apiPort),
		"seed_token":      tokResult.PlaintextToken,
		"seed_token_id":   tokResult.Token.ID,
		"seed_role_id":    role.ID,
		"read_only_policy_id": readOnly.ID,
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
