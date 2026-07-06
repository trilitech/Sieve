// Command sieve is the production Sieve binary.
// It serves two HTTP listeners:
// - 19816 (web) — admin UI for human operators
// - 19817 (api) — agent-facing API+MCP, combined behind one listener
// Passphrase intake follows the strict priority documented in
// docs/credential-encryption.md: SIEVE_PASSPHRASE_FILE → FD 3 (systemd
// LoadCredential=) → TTY prompt. Never an environment variable
// (other than the file pointer). The file/FD3 sources take precedence
// over the TTY prompt so operators with wired-up credential plumbing
// aren't re-prompted on every start.
// Connection configs are envelope-encrypted at rest. The keyring is set
// up on first run (--setup) and loaded on every start thereafter.
// Rotation:
// - --rotate-passphrase enters offline rotation mode: prompts for the
// current passphrase, then twice for the new passphrase, runs an
// atomic re-wrap of every per-record DEK, and exits. The binary
// does NOT bind any network ports in this mode. Sieve must be
// stopped before running rotation against the same DB to avoid a
// SQLite write-lock conflict.
// - --reset-keyring is the recovery path for a forgotten passphrase.
// It deletes every encrypted credential and the keyring metadata,
// preserves everything else (policies, roles, tokens, audit log,
// settings), and exits. Operator must type RESET at the TTY
// confirmation prompt; the flag refuses to run without a TTY. After
// reset, run --setup to choose a new passphrase, then re-add
// connections.
// Exit codes (rotation/reset modes):
// 0 — success
// 1 — generic / unexpected failure
// 2 — wrong current passphrase
// 3 — new-passphrase confirmation mismatch (caught by intake layer)
// 4 — new passphrase identical to current
// 5 — keyring not initialized (run --setup first)
// 6 — DB lock conflict (another Sieve process is holding the DB,
// or another rotation is already in progress)
// 7 — reset aborted (operator did not type RESET, or no TTY)
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/approval"
	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/connections"
	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/iampolicies"
	"github.com/trilitech/Sieve/internal/mcp"
	"github.com/trilitech/Sieve/internal/operator"
	"github.com/trilitech/Sieve/internal/policy"
	"github.com/trilitech/Sieve/internal/ratelimit"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/secrets"
	"github.com/trilitech/Sieve/internal/session"
	"github.com/trilitech/Sieve/internal/settings"
	"github.com/trilitech/Sieve/internal/tokens"
	"github.com/trilitech/Sieve/internal/web"
)

// Exit codes for the offline rotation/reset flows. See package doc.
const (
	rotateExitSuccess         = 0
	rotateExitGeneric         = 1
	rotateExitWrongPassphrase = 2
	rotateExitConfirmMismatch = 3
	rotateExitSameAsCurrent   = 4
	rotateExitKeyringMissing  = 5
	rotateExitLockConflict    = 6
	resetExitAborted          = 7 // operator did not type RESET, or stdin is not a TTY
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
		dbPath           = flag.String("db", defaultDBPath, "path to the persistent sieve database file")
		webAddr          = flag.String("web", defaultWebAddr, "host:port for the admin web UI")
		apiAddr          = flag.String("api", defaultAPIAddr, "host:port for the agent API+MCP")
		setup            = flag.Bool("setup", false, "first-run mode: initialize the keyring (prompts for passphrase twice)")
		rotatePassphrase = flag.Bool("rotate-passphrase", false,
			"offline rotation mode: prompt for current and new passphrases, "+
				"re-wrap every credential record under the new key, and exit. "+
				"Stop the running Sieve process first to avoid a DB lock conflict.")
		resetKeyring = flag.Bool("reset-keyring", false,
			"DESTRUCTIVE recovery for a forgotten passphrase: deletes every "+
				"stored credential and the keyring metadata, then exits. Policies, "+
				"roles, tokens, audit history, and settings are preserved. Run "+
				"--setup afterward to choose a new passphrase. Requires a TTY; "+
				"the operator must type RESET to confirm.")
		googleCredsPath = flag.String("google-credentials", "",
			"path to the Google OAuth client_secret*.json (for the Google Account connector). "+
				"Empty = auto-discover *client_secret*.json in cwd. Optional.")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags]\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "       %s mcp-launch [flags]   stdio→HTTP MCP bridge for Claude Desktop\n\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output(), "Flags:")
		flag.PrintDefaults()
	}
	flag.Parse()

	if exclusiveCount(*setup, *rotatePassphrase, *resetKeyring) > 1 {
		log.SetFlags(0)
		log.Fatalf("sieve: --setup, --rotate-passphrase, and --reset-keyring are mutually exclusive")
	}

	if *rotatePassphrase {
		os.Exit(runRotate(*dbPath))
	}
	if *resetKeyring {
		os.Exit(runResetKeyring(*dbPath))
	}

	if err := run(*dbPath, *webAddr, *apiAddr, *setup, *googleCredsPath); err != nil {
		log.SetFlags(0)
		log.Fatalf("sieve: %v", err)
	}
}

// runRotate is the offline passphrase-rotation entrypoint. It prompts for
// the current passphrase, prompts twice for the new passphrase, runs an
// atomic re-wrap of every per-record DEK, writes one audit row inside the
// rotation transaction, and exits with one of the documented exit codes.
// The function does NOT bind any network ports and does NOT start the
// background goroutines that the normal start path uses — rotation is
// an offline maintenance operation.
func runRotate(dbPath string) int {
	log.SetFlags(0)

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "sieve: create db dir: %v\n", err)
		return rotateExitGeneric
	}
	db, err := database.New(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sieve: open db %q: %v\n", dbPath, err)
		// Most "open db" failures from a busy DB look like SQLITE_BUSY;
		// surface the lock-conflict exit code so scripts can branch.
		if isLockConflict(err) {
			fmt.Fprintln(os.Stderr, "sieve: another Sieve process appears to hold the DB; stop it first.")
			return rotateExitLockConflict
		}
		return rotateExitGeneric
	}
	defer db.Close()

	// Acquire current passphrase. Confirm=false: only one prompt.
	// The current passphrase may come from SIEVE_PASSPHRASE_FILE or
	// FD 3 — operators rotating an unattended deployment shouldn't
	// have to type their existing passphrase by hand. The *new*
	// passphrase below sets Confirm=true, which implies
	// RequireTTY=true inside secrets.Acquire, so this current-reads-
	// from-file branch can't be abused to silently rotate a file
	// source onto itself.
	current, err := secrets.Acquire(secrets.PromptOptions{
		Confirm: false,
		Prompt:  "Current passphrase: ",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "sieve: read current passphrase: %v\n", err)
		return rotateExitGeneric
	}
	defer zero(current)

	// Acquire new passphrase. Confirm=true implies RequireTTY=true:
	// confirming a value against a static file source is meaningless,
	// and silently reading the same file twice ("current" then "new")
	// would make rotation a no-op and trip the
	// "new identical to current" guard. Force the TTY here.
	newPP, err := secrets.Acquire(secrets.PromptOptions{
		Confirm: true,
		Prompt:  "New passphrase: ",
	})
	if err != nil {
		// secrets.Acquire surfaces a literal "passphrases do not match"
		// error on TTY confirm mismatch — map that to its dedicated exit
		// code so scripts can distinguish it from a generic IO error.
		if strings.Contains(err.Error(), "passphrases do not match") {
			fmt.Fprintln(os.Stderr, "sieve: new passphrase confirmation does not match")
			return rotateExitConfirmMismatch
		}
		fmt.Fprintf(os.Stderr, "sieve: read new passphrase: %v\n", err)
		return rotateExitGeneric
	}
	defer zero(newPP)

	if bytes.Equal(current, newPP) {
		fmt.Fprintln(os.Stderr, "sieve: new passphrase identical to current; no rotation performed")
		return rotateExitSameAsCurrent
	}

	// Wire the audit logger so the rotation row commits inside the
	// rotation transaction.
	auditLog := audit.NewLogger(db)
	auditor := auditLog.AsRotationAuditor("cli")

	keyring := &secrets.Keyring{}
	count, err := keyring.Rotate(db.DB, current, newPP, auditor)
	if err != nil {
		switch {
		case errors.Is(err, secrets.ErrWrongPassphrase):
			fmt.Fprintln(os.Stderr, "sieve: current passphrase incorrect")
			return rotateExitWrongPassphrase
		case errors.Is(err, secrets.ErrCryptoMetaMissing):
			fmt.Fprintln(os.Stderr, "sieve: keyring not initialized — run with --setup once before rotating")
			return rotateExitKeyringMissing
		case errors.Is(err, secrets.ErrAlreadyRotating):
			fmt.Fprintln(os.Stderr, "sieve: another rotation is already in progress")
			return rotateExitLockConflict
		case isLockConflict(err):
			fmt.Fprintln(os.Stderr, "sieve: database is busy — another Sieve process must be stopped before rotation")
			return rotateExitLockConflict
		default:
			fmt.Fprintf(os.Stderr, "sieve: rotation failed: %v\n", err)
			return rotateExitGeneric
		}
	}

	fmt.Fprintf(os.Stderr, "sieve: passphrase rotated. %d credential record", count)
	if count != 1 {
		fmt.Fprint(os.Stderr, "s")
	}
	fmt.Fprintln(os.Stderr, " re-wrapped.")
	return rotateExitSuccess
}

// isLockConflict checks whether err looks like a SQLite busy/locked
// error. SQLite's go driver wraps these with the literal "database is
// locked" string; this is the most reliable check across driver versions.
func isLockConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "database table is locked")
}

// exclusiveCount returns the number of true values among bs. main uses
// this to enforce mutual exclusion between --setup, --rotate-passphrase,
// and --reset-keyring (each is a top-level mode the binary enters and
// exits without becoming a network-listening process).
func exclusiveCount(bs ...bool) int {
	n := 0
	for _, b := range bs {
		if b {
			n++
		}
	}
	return n
}

// runResetKeyring is the recovery path for an operator who has forgotten
// their passphrase. By design, Sieve has no way to decrypt credentials
// without the passphrase — this is the same property that protects them
// from any attacker who steals the database file. The trade-off: a
// forgotten passphrase means starting over with credentials.
// What this function deletes:
// - every row in the connections table (the encrypted credentials)
// - the singleton crypto_meta row (the keyring salt + verifier)
// Everything else — policies, roles, tokens, audit history, settings —
// is preserved, so the operator's bindings and tokens keep working as
// soon as they re-add the underlying connections after running --setup.
// One audit row (operation = "keyring.reset", surface = "cli") is
// written inside the same transaction as the deletes so the event is
// visible in the admin UI's audit page after recovery.
// Safeguards (per the threat-model discussion in
// docs/credential-encryption.md):
// - stdin must be a TTY. The reset flag refuses to run under piped
// input so a script cannot accidentally fire it; running it has to
// be a deliberate hands-on operation.
// - the operator must type the literal string "RESET" at the
// confirmation prompt; anything else aborts.
// These are UX safeguards against accidental destruction, not security
// boundaries: anyone with write access to the DB file can already
// destroy the credentials by other means (rm, sqlite3 DELETE, etc.).
// File permissions (chmod 0600 on data/sieve.db, plus running Sieve as
// a dedicated user) are the actual security boundary.
func runResetKeyring(dbPath string) int {
	log.SetFlags(0)

	if !secrets.IsStdinTerminal() {
		fmt.Fprintln(os.Stderr, "sieve: --reset-keyring requires a TTY for confirmation; aborting")
		return resetExitAborted
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "sieve: create db dir: %v\n", err)
		return rotateExitGeneric
	}
	db, err := database.New(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sieve: open db %q: %v\n", dbPath, err)
		if isLockConflict(err) {
			fmt.Fprintln(os.Stderr, "sieve: another Sieve process appears to hold the DB; stop it first.")
			return rotateExitLockConflict
		}
		return rotateExitGeneric
	}
	defer db.Close()

	// Tell the operator exactly what they're about to lose AND what
	// will survive, so the confirmation is informed. Surface a query
	// failure rather than swallowing it: a corrupted or unreadable DB
	// must not present "0 records will be deleted" and let the operator
	// type RESET thinking nothing's at stake. The DELETE below runs
	// regardless of what we display here.
	var connectionCount int
	countKnown := true
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM connections`).Scan(&connectionCount); err != nil {
		fmt.Fprintf(os.Stderr, "sieve: warning: could not count stored credentials: %v\n", err)
		countKnown = false
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "WARNING: --reset-keyring is destructive and irreversible.")
	if countKnown {
		fmt.Fprintf(os.Stderr, "  • %d stored credential record(s) will be deleted.\n", connectionCount)
	} else {
		fmt.Fprintln(os.Stderr, "  • An UNKNOWN number of stored credential record(s) will be deleted")
		fmt.Fprintln(os.Stderr, "    (the count query failed — see warning above).")
	}
	fmt.Fprintln(os.Stderr, "  • You will need to re-add every connection (Gmail, OAuth")
	fmt.Fprintln(os.Stderr, "    accounts, LLM API keys, etc.) after running --setup again.")
	fmt.Fprintln(os.Stderr, "  • Policies, roles, tokens, audit history, and settings are")
	fmt.Fprintln(os.Stderr, "    preserved.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprint(os.Stderr, "Type RESET (in capital letters) to confirm, anything else to abort: ")

	var line string
	if _, err := fmt.Fscanln(os.Stdin, &line); err != nil {
		// Empty line / EOF / read error all map to "abort".
		fmt.Fprintln(os.Stderr, "sieve: reset aborted")
		return resetExitAborted
	}
	if strings.TrimSpace(line) != "RESET" {
		fmt.Fprintln(os.Stderr, "sieve: reset aborted (input did not match)")
		return resetExitAborted
	}

	// Single transaction so the deletes commit atomically with the audit
	// row that records the event.
	tx, err := db.DB.Begin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sieve: begin reset tx: %v\n", err)
		if isLockConflict(err) {
			return rotateExitLockConflict
		}
		return rotateExitGeneric
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM connections`); err != nil {
		fmt.Fprintf(os.Stderr, "sieve: delete connections: %v\n", err)
		return rotateExitGeneric
	}
	if _, err := tx.Exec(`DELETE FROM crypto_meta`); err != nil {
		fmt.Fprintf(os.Stderr, "sieve: delete crypto_meta: %v\n", err)
		return rotateExitGeneric
	}

	auditLog := audit.NewLogger(db)
	if err := auditLog.LogTx(tx, &audit.LogRequest{
		TokenID:      "system",
		TokenName:    "system",
		ConnectionID: "-",
		Operation:    "keyring.reset",
		Params: map[string]any{
			"surface":             "cli",
			"connections_deleted": connectionCount,
		},
		PolicyResult: "success",
	}); err != nil {
		fmt.Fprintf(os.Stderr, "sieve: audit reset: %v\n", err)
		return rotateExitGeneric
	}

	if err := tx.Commit(); err != nil {
		fmt.Fprintf(os.Stderr, "sieve: commit reset: %v\n", err)
		if isLockConflict(err) {
			return rotateExitLockConflict
		}
		return rotateExitGeneric
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "sieve: keyring reset. %d credential record(s) deleted.\n", connectionCount)
	fmt.Fprintln(os.Stderr, "sieve: run with --setup to choose a new passphrase, then re-add your connections.")
	return rotateExitSuccess
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
	registry := buildConnectorRegistry()

	// --- Services ---
	connSvc := connections.NewService(db, registry, keyring)
	tokenSvc := tokens.NewService(db)
	iamSvc := iampolicies.NewService(db)
	rolesSvc := roles.NewService(db)
	approvalQ := approval.NewQueue(db)
	auditLog := audit.NewLogger(db)
	settingsSvc := settings.NewService(db)

	scriptgenSvc := scriptgen.NewService(connSvc, settingsSvc)

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
		tokenSvc, connSvc, rolesSvc, registry,
		approvalQ, auditLog, googleCredsPath, settingsSvc, scriptgenSvc,
		keyring, db, webAddr,
	)
	webSrv.SetIAM(iamSvc, registry, settingsSvc)
	defer webSrv.Close()

	// Operator + session services drive the admin-authentication path.
	// Wiring SetAuth here makes the operator credential MANDATORY on
	// every admin endpoint not in authExemptPaths/Prefixes (login,
	// setup, OAuth callback, docs) — the requireOperatorSession
	// middleware enforces it. See internal/web/auth.go for the gate.
	opSvc := operator.NewService(db)
	sessionMgr := session.NewManager(db, settingsSvc.SessionIdleTimeout())
	// Wire the session-invalidate hook so a credential rotation
	// terminates every active admin session without the rotate endpoint
	// having to remember to call DeleteAll itself.
	opSvc.SetSessionTerminator(sessionMgr)
	webSrv.SetAuth(opSvc, sessionMgr)
	// Per-IP rate limiter on POST /login and POST /setup. Without this
	// the only brake on an online credential guess is argon2's ~150-300 ms
	// cost, which a determined attacker can amortise across machines.
	// Shares the agent listener's "failures per window" tuning so both
	// surfaces respond the same way to abuse.
	loginLimiter := ratelimit.NewLimiter(
		settingsSvc.RateLimitFailures(),
		settingsSvc.RateLimitWindow()/time.Duration(max(settingsSvc.RateLimitFailures(), 1)),
		0,
	)
	webSrv.SetLoginRateLimiter(loginLimiter)

	// Background sweep of expired admin sessions. 5-minute
	// cadence is the documented default; tests can drive SweepExpired
	// directly.
	sessionSweepCtx, sessionSweepCancel := context.WithCancel(context.Background())
	defer sessionSweepCancel()
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-sessionSweepCtx.Done():
				return
			case <-t.C:
				_, _ = sessionMgr.SweepExpired()
			}
		}
	}()

	// --- API + MCP server (port 19817, agent-facing) ---
	// Both share one listener; we mux /mcp to the MCP server, everything
	// else to the API router. Per CLAUDE.md the two-port split (web vs
	// agent) is structural, not cosmetic — admin endpoints stay on 19816,
	// agent endpoints stay on 19817.
	apiRouter := api.NewRouter(tokenSvc, connSvc, iamSvc, registry, rolesSvc, approvalQ, auditLog)
	// Per-IP token-bucket on the bearer-token validation path:
	// failed auth depletes the bucket, success refunds, 429 + Retry-After
	// on refusal. Settings-tuned; defaults: 10 failures per 60s window.
	apiRouter.SetRateLimiter(ratelimit.NewLimiter(
		settingsSvc.RateLimitFailures(),
		settingsSvc.RateLimitWindow()/time.Duration(max(settingsSvc.RateLimitFailures(), 1)),
		0, // documented LRU bound
	))
	mcpSrv := mcp.NewServer(tokenSvc, connSvc, iamSvc, registry, rolesSvc, approvalQ, auditLog)

	// IAM (internal/iam) is the sole authorization engine. The iam_enabled
	// setting is retained only for the admin "engine status" display; default it
	// to "true" so a fresh DB reads consistently.
	if v, _ := settingsSvc.Get("iam_enabled"); v == "" {
		_ = settingsSvc.Set("iam_enabled", "true")
	}

	agentMux := http.NewServeMux()
	agentMux.Handle("/mcp", mcpSrv.Handler())
	agentMux.Handle("/", apiRouter.Handler())

	webHTTP := &http.Server{Addr: webAddr, Handler: webSrv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	apiHTTP := &http.Server{Addr: apiAddr, Handler: agentMux, ReadHeaderTimeout: 10 * time.Second}

	// Wire the command allowlist for script-policy validation. Empty
	// settings value falls back to the bundled-Python default via
	// policy.ValidateCommand semantics — see CurrentCommandAllowlist.
	policy.SetCommandAllowlist(settingsSvc.CommandAllowlist())

	// Per-listener TLS configuration. Both-or-neither per listener;
	// HSTS automatically set on every TLS response by hstsMiddleware
	// (inside serveListener).
	adminTLS := tlsPair{
		CertPath: settingsSvc.AdminTLSCertPath(),
		KeyPath:  settingsSvc.AdminTLSKeyPath(),
	}
	apiTLS := tlsPair{
		CertPath: settingsSvc.APITLSCertPath(),
		KeyPath:  settingsSvc.APITLSKeyPath(),
	}
	if _, err := adminTLS.enabled(); err != nil {
		return fmt.Errorf("admin TLS config: %w", err)
	}
	if _, err := apiTLS.enabled(); err != nil {
		return fmt.Errorf("agent API TLS config: %w", err)
	}
	adminTLSOn, _ := adminTLS.enabled()
	apiTLSOn, _ := apiTLS.enabled()

	// Startup exposure check: the admin UI is documented to bind
	// 127.0.0.1 in production. When the operator overrides that to a
	// non-loopback interface WITHOUT TLS, log a prominent warning
	// naming the exposure. Don't refuse to start — some deployments
	// are intentional (e.g., WireGuard-tunneled).
	if host, _, err := net.SplitHostPort(webAddr); err == nil {
		ip := net.ParseIP(host)
		nonLoopback := host != "" && host != "localhost" && (ip == nil || !ip.IsLoopback())
		if nonLoopback && !adminTLSOn {
			log.Printf("WARNING: admin UI is bound to non-loopback address %q WITHOUT TLS. Anyone who can reach this port can capture admin traffic in cleartext. Configure admin.tls_cert_path / admin.tls_key_path in settings, bind to 127.0.0.1, or restrict reachability at the network layer.", webAddr)
		}
	}

	// --- Start ---
	errCh := make(chan error, 2)
	scheme := func(on bool) string {
		if on {
			return "https"
		}
		return "http"
	}
	go func() {
		log.Printf("web UI:  %s://%s  (admin only — do not expose to agents)", scheme(adminTLSOn), webAddr)
		if err := serveListener(webHTTP, adminTLS); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("web: %w", err)
		}
	}()
	go func() {
		log.Printf("agent:   %s://%s  (REST + MCP at /mcp)", scheme(apiTLSOn), apiAddr)
		if err := serveListener(apiHTTP, apiTLS); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("api: %w", err)
		}
	}()

	// --- Hourly reauth sweeper ---
	// Polls each connection's Validate so the needs_reauth flag stays
	// fresh without waiting for an agent to hit a dead connection. On
	// success, clears any stale flag (auto-recovery from transient blips).
	// The flip-on-failure path is owned by the connector's token source —
	// this loop just lights up the lamp earlier.
	sweepCtx, sweepCancel := context.WithCancel(context.Background())
	defer sweepCancel()
	go reauthSweeper(sweepCtx, connSvc)

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

// reauthSweepInterval is the spacing between Validate rounds. An hour is
// the right magnitude: long enough that we don't pound Google/GitHub for
// idle Sieves, short enough that a revoked token usually trips the flag
// before the next agent call. Made small (and overridable) only as needed.
const reauthSweepInterval = time.Hour

// reauthSweeper runs Validate against every connection on a periodic
// loop. The loop honors ctx so a SIGTERM during shutdown stops it.
// connector returns ErrNeedsReauth → SetStatusWithReason(reauth_required)
// (idempotent if status already reauth_required).
// connector returns nil but status==reauth_required → SetStatus(active)
// (auto-recover from blips).
// connector returns some other error → leave the status alone (could be a
// transient network blip; not our
// place to declare it dead).
// First sweep runs after one interval, not at startup, so the server isn't
// hammering external APIs in its first second of life.
func reauthSweeper(ctx context.Context, connSvc *connections.Service) {
	ticker := time.NewTicker(reauthSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runReauthSweep(ctx, connSvc)
		}
	}
}

func runReauthSweep(ctx context.Context, connSvc *connections.Service) {
	conns, err := connSvc.List()
	if err != nil {
		log.Printf("reauth sweep: list connections: %v", err)
		return
	}
	for _, c := range conns {
		// Disabled connections were turned off on purpose — leave them alone.
		if c.Status == connections.StatusDisabled {
			continue
		}
		// For reauth_required rows the GetConnector status gate would
		// short-circuit before Validate could probe for recovery, so build
		// the connector bypassing the gate. Active rows go through the
		// normal path (the gate is a no-op for them, and GetConnector is
		// what serves agent traffic — exercising the same path here keeps
		// caching/refresh-callback behavior consistent).
		var conn connector.Connector
		if c.Status == connections.StatusReauthRequired {
			conn, err = connSvc.LoadConnectorForRevalidation(c.ID)
		} else {
			conn, err = connSvc.GetConnector(c.ID)
		}
		if err != nil {
			// Stale credentials, missing client_id, keyring locked, etc.
			// Already-flagged connections surface this on every call — the
			// sweeper shouldn't double-mark.
			continue
		}
		// Validate is meant to be a cheap "are we authorized?" check.
		// Time-bound it so a stuck upstream doesn't wedge the sweeper.
		validateCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = conn.Validate(validateCtx)
		cancel()

		switch {
		case errors.Is(err, connector.ErrNeedsReauth):
			// onRefreshFailure inside the connector has already transitioned
			// status in the DB for connectors wired to the callback; this is
			// the safety net for connectors that don't.
			if c.Status != connections.StatusReauthRequired {
				_ = connSvc.SetStatusWithReason(c.ID, connections.StatusReauthRequired, "validate detected refresh failure")
				log.Printf("reauth sweep: connection %q transitioned to reauth_required", c.ID)
			}
		case err == nil && c.Status == connections.StatusReauthRequired:
			_ = connSvc.SetStatus(c.ID, connections.StatusActive)
			log.Printf("reauth sweep: connection %q recovered, transitioning to active", c.ID)
		}
	}
}
