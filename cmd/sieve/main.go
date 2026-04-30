// Command sieve is the production Sieve binary.
//
// It serves two HTTP listeners:
//
//   - 19816 (web)  — admin UI for human operators
//   - 19817 (api)  — agent-facing API+MCP, combined behind one listener
//
// Passphrase intake follows the strict priority documented in
// docs/credential-encryption.md: TTY prompt → SIEVE_PASSPHRASE_FILE →
// FD 3 (systemd LoadCredential=). Never an environment variable.
//
// Connection configs are envelope-encrypted at rest. The keyring is set
// up on first run (--setup) and loaded on every start thereafter.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/approval"
	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/connector"
	githubconn "github.com/trilitech/Sieve/internal/connectors/github"
	"github.com/trilitech/Sieve/internal/connectors/gmail"
	"github.com/trilitech/Sieve/internal/connectors/httpproxy"
	"github.com/trilitech/Sieve/internal/connectors/mcpproxy"
	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/mcp"
	"github.com/trilitech/Sieve/internal/policies"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/secrets"
	"github.com/trilitech/Sieve/internal/settings"
	"github.com/trilitech/Sieve/internal/tokens"
	"github.com/trilitech/Sieve/internal/web"
)

const (
	defaultDBPath  = "./data/sieve.db"
	defaultWebAddr = "127.0.0.1:19816"
	defaultAPIAddr = "127.0.0.1:19817"
)

func main() {
	// Subcommand dispatch must run BEFORE flag.Parse and BEFORE keyring
	// intake — `mcp-launch` is a stdio bridge that talks to a separately
	// running Sieve over HTTP, so it has no business prompting for a
	// passphrase or opening the database.
	if len(os.Args) > 1 && os.Args[1] == "mcp-launch" {
		if err := runMCPLaunch(os.Args[2:]); err != nil {
			log.SetFlags(0)
			log.Fatalf("sieve mcp-launch: %v", err)
		}
		return
	}

	var (
		dbPath          = flag.String("db", defaultDBPath, "path to the persistent sieve database file")
		webAddr         = flag.String("web", defaultWebAddr, "host:port for the admin web UI")
		apiAddr         = flag.String("api", defaultAPIAddr, "host:port for the agent API+MCP")
		setup           = flag.Bool("setup", false, "first-run mode: initialize the keyring (prompts for passphrase twice)")
		googleCredsPath = flag.String("google-credentials", "",
			"path to the Google OAuth client_secret*.json (for the Google Account connector). "+
				"Empty = auto-discover *client_secret*.json in cwd. Optional.")
	)
	flag.Parse()

	if err := run(*dbPath, *webAddr, *apiAddr, *setup, *googleCredsPath); err != nil {
		log.SetFlags(0)
		log.Fatalf("sieve: %v", err)
	}
}

func run(dbPath, webAddr, apiAddr string, setup bool, googleCredsPath string) error {
	// --- Database ---
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return fmt.Errorf("create db dir: %w", err)
	}
	db, err := database.New(dbPath)
	if err != nil {
		return fmt.Errorf("open db %q: %w", dbPath, err)
	}
	defer db.Close()

	// --- Keyring ---
	pp, err := secrets.Acquire(secrets.PromptOptions{Confirm: setup})
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}
	defer zero(pp)

	keyring := &secrets.Keyring{}
	if setup {
		if err := keyring.Setup(db.DB, pp); err != nil {
			return fmt.Errorf("keyring setup: %w", err)
		}
		log.Printf("keyring initialized at %s", dbPath)
	} else {
		if err := keyring.Load(db.DB, pp); err != nil {
			return fmt.Errorf("keyring load (wrong passphrase or DB never set up — run with --setup once): %w", err)
		}
	}

	// --- Connector registry ---
	registry := connector.NewRegistry()
	registry.Register(gmail.Meta, gmail.Factory)
	registry.Register(httpproxy.Meta, httpproxy.Factory)
	registry.Register(mcpproxy.Meta, mcpproxy.Factory)
	registry.Register(githubconn.Meta(), githubconn.Factory())

	// --- Services ---
	connSvc := connections.NewService(db, registry, keyring)
	tokenSvc := tokens.NewService(db)
	policiesSvc := policies.NewService(db)
	rolesSvc := roles.NewService(db)
	approvalQ := approval.NewQueue(db)
	auditLog := audit.NewLogger(db)
	settingsSvc := settings.NewService(db)
	scriptgenSvc := scriptgen.NewService(connSvc, settingsSvc)

	if err := policiesSvc.SeedPresets(); err != nil {
		return fmt.Errorf("seed policy presets: %w", err)
	}

	// Resolve Google OAuth credentials path (optional).
	if googleCredsPath == "" {
		matches, _ := filepath.Glob("*client_secret*.json")
		sort.Strings(matches)
		if len(matches) > 0 {
			abs, _ := filepath.Abs(matches[0])
			googleCredsPath = abs
			log.Printf("auto-discovered Google credentials: %s", googleCredsPath)
		}
	}

	// --- Web UI server (port 19816, human admin only) ---
	webSrv := web.NewServer(
		tokenSvc, connSvc, policiesSvc, rolesSvc, registry,
		approvalQ, auditLog, googleCredsPath, settingsSvc, scriptgenSvc,
	)
	defer webSrv.Close()

	// --- API + MCP server (port 19817, agent-facing) ---
	// Both share one listener; we mux /mcp to the MCP server, everything
	// else to the API router. Per CLAUDE.md the two-port split (web vs
	// agent) is structural, not cosmetic — admin endpoints stay on 19816,
	// agent endpoints stay on 19817.
	apiRouter := api.NewRouter(tokenSvc, connSvc, policiesSvc, rolesSvc, approvalQ, auditLog)
	mcpSrv := mcp.NewServer(tokenSvc, connSvc, policiesSvc, rolesSvc, approvalQ, auditLog)

	agentMux := http.NewServeMux()
	agentMux.Handle("/mcp", mcpSrv.Handler())
	agentMux.Handle("/", apiRouter.Handler())

	webHTTP := &http.Server{Addr: webAddr, Handler: webSrv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	apiHTTP := &http.Server{Addr: apiAddr, Handler: agentMux, ReadHeaderTimeout: 10 * time.Second}

	// --- Start ---
	errCh := make(chan error, 2)
	go func() {
		log.Printf("web UI:  http://%s  (admin only — do not expose to agents)", webAddr)
		if err := webHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("web: %w", err)
		}
	}()
	go func() {
		log.Printf("agent:   http://%s  (REST + MCP at /mcp)", apiAddr)
		if err := apiHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("api: %w", err)
		}
	}()

	// --- Wait for signal or fatal listener error ---
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var listenErr error
	select {
	case sig := <-sigCh:
		log.Printf("received %s, shutting down…", sig)
	case listenErr = <-errCh:
		log.Printf("listener error: %v", listenErr)
	}

	// --- Graceful shutdown ---
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := webHTTP.Shutdown(shutdownCtx); err != nil {
		log.Printf("web shutdown: %v", err)
	}
	if err := apiHTTP.Shutdown(shutdownCtx); err != nil {
		log.Printf("api shutdown: %v", err)
	}

	log.Print("shutdown complete")
	return listenErr
}

// zero overwrites the passphrase bytes after we're done with them. Doesn't
// guard against Go's GC having moved a copy elsewhere, but it's the right
// gesture and matches the rest of the codebase's handling of secrets.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
