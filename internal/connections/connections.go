// Package connections manages the registry of external service connections
// (e.g., Gmail accounts) and their live connector instances.
//
// Each connection has two representations:
//   - A database row with ID, connector type, display name, and encrypted config.
//     This is the durable record.
//   - A live connector instance (connector.Connector) held in an in-memory cache.
//     This is the active, authenticated client used to execute operations.
//
// The live cache avoids re-creating OAuth-authenticated clients on every request.
// It uses read-write locking with a double-check pattern in GetConnector to
// safely handle concurrent access without holding a write lock during the
// (potentially slow) connector creation.
//
// Add intentionally does not fail if the live connector cannot be created. This
// supports the OAuth flow where a connection is saved to the database before
// OAuth completes — the config may lack valid credentials at that point. The
// live connector will be created lazily on first use via GetConnector.
package connections

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/trilitech/Sieve/internal/connector"
	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/secrets"
	"golang.org/x/oauth2"
)

// Connection represents a stored connection to an external service.
type Connection struct {
	ID            string         `json:"id"`
	ConnectorType string         `json:"connector"`
	DisplayName   string         `json:"display_name"`
	Config        map[string]any `json:"-"` // only populated for internal use; excluded from JSON serialization
	CreatedAt     time.Time      `json:"created_at"`

	// NeedsReauth flips to true when a token refresh fails irrecoverably
	// (e.g., OAuth invalid_grant). The web UI surfaces this as a banner;
	// the API/MCP layers translate it to a structured 503 so agents and
	// their humans know which connection is dead and where to fix it.
	// Cleared on successful re-authentication or on a successful Validate
	// (the hourly sweeper auto-recovers from transient blips).
	NeedsReauth   bool   `json:"needs_reauth,omitempty"`
	ReauthReason  string `json:"reauth_reason,omitempty"`
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
	if !s.keyring.IsLoaded() {
		return secrets.ErrKeyringNotLoaded
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	blob, err := secrets.Encrypt(s.keyring.KEK(), configJSON)
	if err != nil {
		return fmt.Errorf("encrypt config: %w", err)
	}

	_, err = s.db.DB.Exec(
		`INSERT INTO connections (
			id, connector_type, display_name,
			config_ciphertext, config_nonce,
			dek_wrapped, dek_nonce, enc_version,
			created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, connectorType, displayName,
		blob.Ciphertext, blob.Nonce,
		blob.WrappedDEK, blob.DEKNonce, blob.Version,
		time.Now().UTC(),
	)
	if err != nil {
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

// Get returns a connection by ID (without sensitive config).
func (s *Service) Get(id string) (*Connection, error) {
	row := s.db.DB.QueryRow(
		`SELECT id, connector_type, display_name, created_at, needs_reauth, reauth_reason
		 FROM connections WHERE id = ?`, id,
	)

	var c Connection
	var needsReauth int
	var reauthReason *string
	if err := row.Scan(&c.ID, &c.ConnectorType, &c.DisplayName, &c.CreatedAt, &needsReauth, &reauthReason); err != nil {
		return nil, fmt.Errorf("get connection %q: %w", id, err)
	}
	c.NeedsReauth = needsReauth != 0
	if reauthReason != nil {
		c.ReauthReason = *reauthReason
	}
	return &c, nil
}

// GetWithConfig returns a connection including its config (for internal use).
// Requires the keyring to be loaded; returns secrets.ErrKeyringNotLoaded if not.
func (s *Service) GetWithConfig(id string) (*Connection, error) {
	if !s.keyring.IsLoaded() {
		return nil, secrets.ErrKeyringNotLoaded
	}

	row := s.db.DB.QueryRow(
		`SELECT id, connector_type, display_name,
			config_ciphertext, config_nonce,
			dek_wrapped, dek_nonce, enc_version,
			created_at, needs_reauth, reauth_reason
		 FROM connections WHERE id = ?`, id,
	)

	var c Connection
	var blob secrets.EncryptedBlob
	var needsReauth int
	var reauthReason *string
	if err := row.Scan(
		&c.ID, &c.ConnectorType, &c.DisplayName,
		&blob.Ciphertext, &blob.Nonce,
		&blob.WrappedDEK, &blob.DEKNonce, &blob.Version,
		&c.CreatedAt, &needsReauth, &reauthReason,
	); err != nil {
		return nil, fmt.Errorf("get connection %q: %w", id, err)
	}
	c.NeedsReauth = needsReauth != 0
	if reauthReason != nil {
		c.ReauthReason = *reauthReason
	}

	configJSON, err := secrets.Decrypt(s.keyring.KEK(), &blob)
	if err != nil {
		return nil, fmt.Errorf("decrypt config for %q: %w", id, err)
	}
	if err := json.Unmarshal(configJSON, &c.Config); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &c, nil
}

// List returns all connections (without sensitive config).
func (s *Service) List() ([]Connection, error) {
	rows, err := s.db.DB.Query(
		`SELECT id, connector_type, display_name, created_at, needs_reauth, reauth_reason
		 FROM connections ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("list connections: %w", err)
	}
	defer rows.Close()

	var connections []Connection
	for rows.Next() {
		var c Connection
		var needsReauth int
		var reauthReason *string
		if err := rows.Scan(&c.ID, &c.ConnectorType, &c.DisplayName, &c.CreatedAt, &needsReauth, &reauthReason); err != nil {
			return nil, fmt.Errorf("scan connection: %w", err)
		}
		c.NeedsReauth = needsReauth != 0
		if reauthReason != nil {
			c.ReauthReason = *reauthReason
		}
		connections = append(connections, c)
	}
	return connections, rows.Err()
}

// UpdateConfig updates a connection's stored config.
// Rotates the per-record DEK on every write — random 32 bytes is cheap and
// avoids carrying state about whether the row's existing DEK is reusable.
func (s *Service) UpdateConfig(id string, config map[string]any) error {
	if !s.keyring.IsLoaded() {
		return secrets.ErrKeyringNotLoaded
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	blob, err := secrets.Encrypt(s.keyring.KEK(), configJSON)
	if err != nil {
		return fmt.Errorf("encrypt config: %w", err)
	}

	// Clearing needs_reauth in the same statement as the config update is
	// deliberate: if the operator just completed a re-auth flow, the new
	// credentials are the cure for whatever flagged the connection in the
	// first place. Doing it atomically avoids a window where the DB still
	// claims the connection is broken even though we just installed a
	// working refresh token.
	res, err := s.db.DB.Exec(
		`UPDATE connections SET
			config_ciphertext = ?, config_nonce = ?,
			dek_wrapped = ?, dek_nonce = ?, enc_version = ?,
			needs_reauth = 0, reauth_reason = NULL
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

// MarkNeedsReauth flips a connection's needs_reauth flag to 1 and records
// a short human-readable reason. Idempotent — re-marking with a different
// reason just updates the reason. Returns no error if the connection has
// already been deleted (a refresh callback may fire after a Remove).
func (s *Service) MarkNeedsReauth(id, reason string) error {
	_, err := s.db.DB.Exec(
		`UPDATE connections SET needs_reauth = 1, reauth_reason = ? WHERE id = ?`,
		reason, id,
	)
	if err != nil {
		return fmt.Errorf("mark connection %q reauth: %w", id, err)
	}
	return nil
}

// ClearNeedsReauth clears the flag — used by the sweeper when Validate()
// recovers, and as a safety net (UpdateConfig clears it inline).
func (s *Service) ClearNeedsReauth(id string) error {
	_, err := s.db.DB.Exec(
		`UPDATE connections SET needs_reauth = 0, reauth_reason = NULL WHERE id = ?`,
		id,
	)
	if err != nil {
		return fmt.Errorf("clear connection %q reauth: %w", id, err)
	}
	return nil
}

// Exists checks if a connection exists.
func (s *Service) Exists(id string) (bool, error) {
	var count int
	err := s.db.DB.QueryRow(`SELECT COUNT(*) FROM connections WHERE id = ?`, id).Scan(&count)
	return count > 0, err
}

// injectRefreshCallback adds two token-lifecycle callbacks to the config
// map. The connector hands these to its OAuth token source:
//
//   - _on_token_refresh: a refresh succeeded. Persist the new access (and
//     possibly rotated refresh) token to the DB so future server starts
//     don't immediately burn another refresh.
//   - _on_token_refresh_failure: a refresh failed irrecoverably. Mark the
//     connection needs_reauth with the error code as the reason. The web
//     UI will surface a banner; the API/MCP layers will return 503
//     connection_reauth_required to anyone trying to use it.
func (s *Service) injectRefreshCallback(id string, config map[string]any) {
	config["_on_token_refresh"] = func(tok *oauth2.Token) {
		c, err := s.GetWithConfig(id)
		if err != nil {
			return
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
		s.UpdateConfig(id, c.Config)
	}
	config["_on_token_refresh_failure"] = func(reason string) {
		// Best-effort: a deleted connection or a closed DB shouldn't block
		// the calling goroutine. The error path is logged elsewhere when
		// the wrapped sentinel surfaces at the API/MCP boundary.
		_ = s.MarkNeedsReauth(id, reason)
	}
}

// GetConnector returns the live connector instance for a connection.
// If not cached, it loads from DB and creates one.
func (s *Service) GetConnector(id string) (connector.Connector, error) {
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
// Requires the keyring to be loaded; returns secrets.ErrKeyringNotLoaded if not.
func (s *Service) InitAll() error {
	if !s.keyring.IsLoaded() {
		return secrets.ErrKeyringNotLoaded
	}

	rows, err := s.db.DB.Query(
		`SELECT id, connector_type,
			config_ciphertext, config_nonce,
			dek_wrapped, dek_nonce, enc_version
		 FROM connections`,
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

		configJSON, err := secrets.Decrypt(s.keyring.KEK(), &blob)
		if err != nil {
			return fmt.Errorf("decrypt config for %q: %w", id, err)
		}

		var config map[string]any
		if err := json.Unmarshal(configJSON, &config); err != nil {
			return fmt.Errorf("unmarshal config for %q: %w", id, err)
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
