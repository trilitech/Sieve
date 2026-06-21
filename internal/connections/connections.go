// Package connections manages the registry of external service connections
// (e.g., Gmail accounts) and their live connector instances.
// Each connection has two representations:
// - A database row with ID, connector type, display name, and encrypted config.
// This is the durable record.
// - A live connector instance (connector.Connector) held in an in-memory cache.
// This is the active, authenticated client used to execute operations.
// The live cache avoids re-creating OAuth-authenticated clients on every request.
// It uses read-write locking with a double-check pattern in GetConnector to
// safely handle concurrent access without holding a write lock during the
// (potentially slow) connector creation.
// Add intentionally does not fail if the live connector cannot be created. This
// supports the OAuth flow where a connection is saved to the database before
// OAuth completes — the config may lack valid credentials at that point. The
// live connector will be created lazily on first use via GetConnector.
package connections

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/secrets"
	"golang.org/x/oauth2"
)

// Connection status values. A connection can be in exactly one of these states.
const (
	StatusActive         = "active"
	StatusReauthRequired = "reauth_required"
	StatusDisabled       = "disabled"
)

// Sentinel errors returned when GetConnector is called on a non-active
// connection. Both are mapped to HTTP 403 by the API and web routers
// (see internal/api/router.go and internal/mcp/server.go).
var (
	ErrReauthRequired     = errors.New("connection requires reauthentication")
	ErrConnectionDisabled = errors.New("connection is disabled")
)

// validateStatus reports whether s is a recognised connection status.
func validateStatus(s string) error {
	switch s {
	case StatusActive, StatusReauthRequired, StatusDisabled:
		return nil
	default:
		return fmt.Errorf("invalid connection status %q (want active|reauth_required|disabled)", s)
	}
}

// Connection represents a stored connection to an external service.
type Connection struct {
	ID            string         `json:"id"`
	ConnectorType string         `json:"connector"`
	DisplayName   string         `json:"display_name"`
	Status        string         `json:"status"`
	Config        map[string]any `json:"-"` // only populated for internal use; excluded from JSON serialization
	CreatedAt     time.Time      `json:"created_at"`
	ReauthReason  string         `json:"reauth_reason,omitempty"`
}

// Service manages the connection registry.
type Service struct {
	db       *database.DB
	registry *connector.Registry
	keyring  *secrets.Keyring
	// Live connector instances keyed by connection ID
	live map[string]connector.Connector
	mu   sync.RWMutex
}

// NewService creates a new connection service. The keyring must be loaded
// (passphrase supplied at startup) before any credential read or write —
// operations that need decryption return secrets.ErrKeyringNotLoaded
// otherwise, and callers should surface that as a 503.
func NewService(db *database.DB, registry *connector.Registry, keyring *secrets.Keyring) *Service {
	return &Service{
		db:       db,
		registry: registry,
		keyring:  keyring,
		live:     make(map[string]connector.Connector),
	}
}

// Add registers a new connection.
func (s *Service) Add(id, connectorType, displayName string, config map[string]any) error {
	if !s.registry.HasType(connectorType) {
		return &connector.ErrUnknownConnector{Type: connectorType}
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	var blob *secrets.EncryptedBlob
	if err := s.keyring.WithKEK(func(kek []byte) error {
		b, err := secrets.Encrypt(kek, configJSON)
		if err != nil {
			return fmt.Errorf("encrypt config: %w", err)
		}
		blob = b
		return nil
	}); err != nil {
		return err
	}

	if _, err := s.db.DB.Exec(
		`INSERT INTO connections (
			id, connector_type, display_name,
			config_ciphertext, config_nonce,
			dek_wrapped, dek_nonce, enc_version,
			status, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, connectorType, displayName,
		blob.Ciphertext, blob.Nonce,
		blob.WrappedDEK, blob.DEKNonce, blob.Version,
		StatusActive, time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("insert connection: %w", err)
	}

	// Best-effort live connector creation. Failure is expected during the
	// OAuth flow: the connection is persisted first, then the user completes
	// OAuth, and UpdateConfig is called with real credentials. The live
	// connector will be created lazily on first GetConnector call.
	conn, err := s.registry.Create(connectorType, config)
	if err == nil {
		s.mu.Lock()
		s.live[id] = conn
		s.mu.Unlock()
	}

	return nil
}

// Get returns a connection by ID (without sensitive config). Does not
// require the keyring — `status` is non-secret and readable independently.
func (s *Service) Get(id string) (*Connection, error) {
	row := s.db.DB.QueryRow(
		`SELECT id, connector_type, display_name, status, created_at, reauth_reason
		 FROM connections WHERE id = ?`, id,
	)

	var c Connection
	var reauthReason *string
	if err := row.Scan(&c.ID, &c.ConnectorType, &c.DisplayName, &c.Status, &c.CreatedAt, &reauthReason); err != nil {
		return nil, fmt.Errorf("get connection %q: %w", id, err)
	}
	if reauthReason != nil {
		c.ReauthReason = *reauthReason
	}
	return &c, nil
}

// GetWithConfig returns a connection including its config (for internal use).
// Requires the keyring to be loaded; returns secrets.ErrKeyringNotLoaded if
// no passphrase has been supplied, or secrets.ErrKeyringRotating if a
// rotation is in progress (the caller should retry).
func (s *Service) GetWithConfig(id string) (*Connection, error) {
	// Fail-fast keyring precondition check before the DB read so that a
	// caller hitting a locked keyring gets the typed sentinel even when
	// the requested row does not exist. The actual decrypt below holds
	// the keyring mutex via WithKEK.
	if !s.keyring.IsLoaded() {
		return nil, secrets.ErrKeyringNotLoaded
	}

	row := s.db.DB.QueryRow(
		`SELECT id, connector_type, display_name,
			config_ciphertext, config_nonce,
			dek_wrapped, dek_nonce, enc_version,
			status, created_at, reauth_reason
		 FROM connections WHERE id = ?`, id,
	)

	var c Connection
	var blob secrets.EncryptedBlob
	var reauthReason *string
	if err := row.Scan(
		&c.ID, &c.ConnectorType, &c.DisplayName,
		&blob.Ciphertext, &blob.Nonce,
		&blob.WrappedDEK, &blob.DEKNonce, &blob.Version,
		&c.Status, &c.CreatedAt, &reauthReason,
	); err != nil {
		return nil, fmt.Errorf("get connection %q: %w", id, err)
	}
	if reauthReason != nil {
		c.ReauthReason = *reauthReason
	}

	if err := s.keyring.WithKEK(func(kek []byte) error {
		configJSON, err := secrets.Decrypt(kek, &blob)
		if err != nil {
			return fmt.Errorf("decrypt config for %q: %w", id, err)
		}
		if err := json.Unmarshal(configJSON, &c.Config); err != nil {
			return fmt.Errorf("unmarshal config: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &c, nil
}

// List returns all connections (without sensitive config). Reserved-prefix
// rows (connector_type starting with "_") are filtered out — they hold
// system state like OAuth-app credentials and MUST NOT appear in the
// per-tenant connections list. Use ListReserved to surface them in the
// admin "OAuth app credentials" view. Does not require the keyring.
func (s *Service) List() ([]Connection, error) {
	rows, err := s.db.DB.Query(
		`SELECT id, connector_type, display_name, status, created_at, reauth_reason
		 FROM connections WHERE connector_type NOT LIKE '\_%' ESCAPE '\' ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("list connections: %w", err)
	}
	defer rows.Close()

	var connections []Connection
	for rows.Next() {
		var c Connection
		var reauthReason *string
		if err := rows.Scan(&c.ID, &c.ConnectorType, &c.DisplayName, &c.Status, &c.CreatedAt, &reauthReason); err != nil {
			return nil, fmt.Errorf("scan connection: %w", err)
		}
		if reauthReason != nil {
			c.ReauthReason = *reauthReason
		}
		connections = append(connections, c)
	}
	return connections, rows.Err()
}

// IsReservedConnectorType reports whether a connector_type value denotes
// a reserved system row (currently any value starting with "_"). Reserved
// rows hold per-deployment state like OAuth-app credentials and are never
// addressable as per-tenant connection targets.
func IsReservedConnectorType(s string) bool {
	return strings.HasPrefix(s, "_")
}

// IsReservedConnectionID reports whether a connection id refers to a
// reserved system row. The id convention is `oauth_app__<provider>` for
// OAuth-app credential rows; future reserved kinds use other prefixes
// that this helper recognises by inspecting the id string.
func IsReservedConnectionID(id string) bool {
	return strings.HasPrefix(id, "oauth_app__")
}

// SetStatus updates the connection's status. Validates that status is one
// of the allowed values; returns an error for unknown values without
// touching the database. Does not require the keyring — status is non-secret.
// Clears reauth_reason when transitioning to active (the credentials are
// presumed working again); leaves it intact for other transitions because
// callers usually pair SetStatus(reauth_required|disabled) with a reason
// via SetStatusWithReason and we don't want to wipe a reason just set.
func (s *Service) SetStatus(id, status string) error {
	if err := validateStatus(status); err != nil {
		return err
	}
	var (
		res sql.Result
		err error
	)
	if status == StatusActive {
		res, err = s.db.DB.Exec(`UPDATE connections SET status = ?, reauth_reason = NULL WHERE id = ?`, status, id)
	} else {
		res, err = s.db.DB.Exec(`UPDATE connections SET status = ? WHERE id = ?`, status, id)
	}
	if err != nil {
		return fmt.Errorf("update status for %q: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("connection %q not found", id)
	}
	return nil
}

// SetStatusWithReason updates both the status column and reauth_reason in
// one statement. This is the canonical writer for the unified lifecycle:
// every "this connection is broken" signal calls this single method.
// Returns no error if the connection has already been deleted (a refresh
// callback may fire after a Remove).
func (s *Service) SetStatusWithReason(id, status, reason string) error {
	if err := validateStatus(status); err != nil {
		return err
	}
	if status == StatusActive {
		// reauth_reason cleared on transition to active.
		_, err := s.db.DB.Exec(
			`UPDATE connections SET status = ?, reauth_reason = NULL WHERE id = ?`,
			status, id,
		)
		if err != nil {
			return fmt.Errorf("set status for %q: %w", id, err)
		}
		return nil
	}
	_, err := s.db.DB.Exec(
		`UPDATE connections SET status = ?, reauth_reason = ? WHERE id = ?`,
		status, reason, id,
	)
	if err != nil {
		return fmt.Errorf("set status for %q: %w", id, err)
	}
	return nil
}

// UpdateConfig updates a connection's stored config.
// Rotates the per-record DEK on every write — random 32 bytes is cheap and
// avoids carrying state about whether the row's existing DEK is reusable.
func (s *Service) UpdateConfig(id string, config map[string]any) error {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	var blob *secrets.EncryptedBlob
	if err := s.keyring.WithKEK(func(kek []byte) error {
		b, encErr := secrets.Encrypt(kek, configJSON)
		if encErr != nil {
			return fmt.Errorf("encrypt config: %w", encErr)
		}
		blob = b
		return nil
	}); err != nil {
		return err
	}

	// Transitioning status='active' and clearing reauth_reason in the same
	// statement as the config update is deliberate: if the operator just
	// completed a re-auth flow, the new credentials are the cure for
	// whatever flagged the connection in the first place. Doing it
	// atomically avoids a window where the DB still claims the connection
	// is broken even though we just installed a working refresh token.
	res, err := s.db.DB.Exec(
		`UPDATE connections SET
			config_ciphertext = ?, config_nonce = ?,
			dek_wrapped = ?, dek_nonce = ?, enc_version = ?,
			status = 'active', reauth_reason = NULL
		 WHERE id = ?`,
		blob.Ciphertext, blob.Nonce,
		blob.WrappedDEK, blob.DEKNonce, blob.Version,
		id,
	)
	if err != nil {
		return fmt.Errorf("update connection config: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("connection %q not found", id)
	}

	// Recreate live connector with new config
	conn, err := s.GetWithConfig(id)
	if err != nil {
		return err
	}
	liveConn, err := s.registry.Create(conn.ConnectorType, config)
	if err != nil {
		return fmt.Errorf("recreate connector: %w", err)
	}
	s.mu.Lock()
	s.live[id] = liveConn
	s.mu.Unlock()

	return nil
}

// Remove deletes a connection.
func (s *Service) Remove(id string) error {
	res, err := s.db.DB.Exec(`DELETE FROM connections WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete connection: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("connection %q not found", id)
	}

	s.mu.Lock()
	delete(s.live, id)
	s.mu.Unlock()
	return nil
}

// Exists checks if a connection exists.
func (s *Service) Exists(id string) (bool, error) {
	var count int
	err := s.db.DB.QueryRow(`SELECT COUNT(*) FROM connections WHERE id = ?`, id).Scan(&count)
	return count > 0, err
}

// persistRefreshedToken merges the refreshed access/refresh-token pair from
// tok into the connection's stored config and persists it. Returns any
// error from the read or write step.
// Exposed as a method (not just a closure body) so the failure path can be
// exercised in tests — see refresh_test.go.
func (s *Service) persistRefreshedToken(id string, tok *oauth2.Token) error {
	c, err := s.GetWithConfig(id)
	if err != nil {
		return fmt.Errorf("read for refresh: %w", err)
	}
	oauthToken, _ := c.Config["oauth_token"].(map[string]any)
	if oauthToken == nil {
		oauthToken = make(map[string]any)
	}
	oauthToken["access_token"] = tok.AccessToken
	oauthToken["token_type"] = tok.TokenType
	if tok.RefreshToken != "" {
		oauthToken["refresh_token"] = tok.RefreshToken
	}
	if !tok.Expiry.IsZero() {
		oauthToken["expiry"] = tok.Expiry.Format(time.RFC3339)
	}
	c.Config["oauth_token"] = oauthToken
	return s.UpdateConfig(id, c.Config)
}

// injectRefreshCallback adds two token-lifecycle callbacks to the config map.
// The connector hands these to its OAuth token source:
// - _on_token_refresh: a refresh succeeded. Persist the new access (and
// possibly rotated refresh) token to the DB so future server starts
// don't immediately burn another refresh.
// - _on_token_refresh_failure: a refresh failed irrecoverably. Mark the
// connection needs_reauth with the error code as the reason. The web
// UI will surface a banner; the API/MCP layers will return 503
// connection_reauth_required to anyone trying to use it.
// Linear, Jira, and Asana rotate refresh tokens — the upstream invalidates
// the old refresh token the moment the new pair is issued. If the persist
// of the new pair fails (DB error, decrypt error, keyring unloaded mid-
// call), the connection is unrecoverable until an admin re-authenticates.
// Surface that immediately by transitioning the connection's status to
// reauth_required so the next agent call short-circuits with
// ErrReauthRequired (mapped to HTTP 403) instead of burning further
// refresh attempts against a stale refresh token.
// The status transition is best-effort: if SetStatus itself fails (e.g.,
// the same DB error that broke UpdateConfig), the original persist error
// is logged and the next call's auth-error path will transition status
// when the upstream returns 401.
func (s *Service) injectRefreshCallback(id string, config map[string]any) {
	config["_on_token_refresh"] = func(tok *oauth2.Token) {
		if err := s.persistRefreshedToken(id, tok); err != nil {
			// Record the persist failure as the reauth reason so the UI/API
			// surface a meaningful explanation instead of a blank reason
			// (matching the _on_token_refresh_failure branch below).
			reason := fmt.Sprintf("refresh-token persist failed: %v", err)
			if setErr := s.SetStatusWithReason(id, StatusReauthRequired, reason); setErr != nil {
				log.Printf("connections: refresh-token persist failed for %q: %v (SetStatusWithReason also failed: %v)", id, err, setErr)
			} else {
				log.Printf("connections: refresh-token persist failed for %q, transitioned to reauth_required: %v", id, err)
			}
		}
	}
	config["_on_token_refresh_failure"] = func(reason string) {
		// Best-effort: a deleted connection or a closed DB shouldn't block
		// the calling goroutine. The error path is logged elsewhere when
		// the wrapped sentinel surfaces at the API/MCP boundary.
		_ = s.SetStatusWithReason(id, StatusReauthRequired, reason)
	}
}

// GetConnector returns the live connector instance for a connection.
// If not cached, it loads from DB and creates one.
// Connections whose status is not `active` are short-circuited with a
// sentinel error: ErrReauthRequired or ErrConnectionDisabled. The check
// happens before keyring decryption so a non-active connection can be
// rejected even when the keyring is unloaded. Routers map both sentinels
// to HTTP 403.
// Cost note: every call now incurs one keyless `SELECT... WHERE id = ?`
// against the connections table to read the current status. Previously
// the cache-hit path was a single sync.RWMutex.RLock with no DB round
// trip. We accept the cost because:
// - Sieve is positioned for individual-account scale (tens of
// connections, not high request rate).
// - Every operation is already audit-logged + policy-evaluated, so
// one extra SELECT is in the noise.
// - Caching status alongside the live connector instance would force
// us to invalidate on every SetStatus, re-introducing the
// stale-state foot-gun that the gate exists to close.
func (s *Service) GetConnector(id string) (connector.Connector, error) {
	// Reserved-prefix system rows (e.g., _oauth_app:slack) hold per-deployment
	// state and have no registered factory. Refuse them up front so agent
	// traffic can never address them as a connection.
	if IsReservedConnectionID(id) {
		return nil, &connector.ErrUnknownConnector{Type: "reserved system row"}
	}
	// Status gate: refuse non-active connections immediately. Reading
	// status does not require the keyring.
	meta, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	switch meta.Status {
	case StatusReauthRequired:
		return nil, ErrReauthRequired
	case StatusDisabled:
		return nil, ErrConnectionDisabled
	}
	return s.loadConnectorBypassingStatusGate(id)
}

// LoadConnectorForRevalidation builds a connector instance bypassing the
// status gate. It exists for the background reauth sweeper, which needs to
// probe a reauth_required connection to see whether the upstream has
// recovered — GetConnector would short-circuit before Validate could run.
// Reserved system rows are still rejected. Like GetConnector, it caches
// the live instance on success. Callers that intend to serve agent traffic
// must go through GetConnector instead so non-active connections are
// short-circuited at the gate.
func (s *Service) LoadConnectorForRevalidation(id string) (connector.Connector, error) {
	if IsReservedConnectionID(id) {
		return nil, &connector.ErrUnknownConnector{Type: "reserved system row"}
	}
	return s.loadConnectorBypassingStatusGate(id)
}

func (s *Service) loadConnectorBypassingStatusGate(id string) (connector.Connector, error) {
	s.mu.RLock()
	if conn, ok := s.live[id]; ok {
		s.mu.RUnlock()
		return conn, nil
	}
	s.mu.RUnlock()

	// Load from DB and create with refresh callback for token persistence.
	c, err := s.GetWithConfig(id)
	if err != nil {
		return nil, err
	}

	s.injectRefreshCallback(id, c.Config)
	conn, err := s.registry.Create(c.ConnectorType, c.Config)
	if err != nil {
		return nil, fmt.Errorf("create connector for %q: %w", id, err)
	}

	// Double-check locking: between the RUnlock above and this Lock, another
	// goroutine may have loaded the same connection from DB and inserted it.
	// Use the existing instance if so to avoid duplicate connector objects.
	s.mu.Lock()
	if existing, ok := s.live[id]; ok {
		s.mu.Unlock()
		return existing, nil
	}
	s.live[id] = conn
	s.mu.Unlock()
	return conn, nil
}

// InitAll loads all connections from DB and creates live connector instances.
// Requires the keyring to be loaded; returns secrets.ErrKeyringNotLoaded if
// no passphrase has been supplied, or secrets.ErrKeyringRotating if a
// rotation is in progress (the caller should retry).
func (s *Service) InitAll() error {
	if !s.keyring.IsLoaded() {
		return secrets.ErrKeyringNotLoaded
	}

	// Skip non-active rows: GetConnector would refuse them anyway, and
	// creating a live instance for a disabled/reauth_required connection
	// is wasted work. Operators clear status via the admin UI.
	rows, err := s.db.DB.Query(
		`SELECT id, connector_type,
			config_ciphertext, config_nonce,
			dek_wrapped, dek_nonce, enc_version
		 FROM connections WHERE status = 'active'`,
	)
	if err != nil {
		return fmt.Errorf("load connections: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, connType string
		var blob secrets.EncryptedBlob
		if err := rows.Scan(
			&id, &connType,
			&blob.Ciphertext, &blob.Nonce,
			&blob.WrappedDEK, &blob.DEKNonce, &blob.Version,
		); err != nil {
			return fmt.Errorf("scan connection: %w", err)
		}

		var config map[string]any
		if err := s.keyring.WithKEK(func(kek []byte) error {
			configJSON, decErr := secrets.Decrypt(kek, &blob)
			if decErr != nil {
				return fmt.Errorf("decrypt config for %q: %w", id, decErr)
			}
			if jsonErr := json.Unmarshal(configJSON, &config); jsonErr != nil {
				return fmt.Errorf("unmarshal config for %q: %w", id, jsonErr)
			}
			return nil
		}); err != nil {
			return err
		}

		s.injectRefreshCallback(id, config)
		conn, err := s.registry.Create(connType, config)
		if err != nil {
			// Log but don't fail: some connections may have stale or incomplete
			// credentials (e.g., expired OAuth tokens). They'll be retried
			// lazily when GetConnector is called, which may trigger a token refresh.
			fmt.Printf("warning: failed to initialize connection %q: %v\n", id, err)
			continue
		}
		s.mu.Lock()
		s.live[id] = conn
		s.mu.Unlock()
	}

	return rows.Err()
}
