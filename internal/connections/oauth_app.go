package connections

// OAuth application credentials (client_id + client_secret) per provider.
// Stored as a reserved row in the connections table — connector_type
// starts with the `_oauth_app:` prefix so the row is filtered from the
// per-tenant connections list, rejected by GetConnector, and refused
// by role bindings. Reuses the existing envelope encryption (per-record
// DEK + KEK wrap) verbatim so passphrase rotation picks it up for free.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/trilitech/Sieve/internal/secrets"
)

// OAuthAppCredentials is the decrypted shape stored in the encrypted
// config blob of an _oauth_app:<provider> row.
type OAuthAppCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// OAuthAppMeta is the non-secret summary returned by ListOAuthApps for
// the admin "OAuth app credentials" view. Never carries the secret.
type OAuthAppMeta struct {
	Provider  string    `json:"provider"`
	ClientID  string    `json:"client_id"`
	HasSecret bool      `json:"has_secret"`
	UpdatedAt time.Time `json:"updated_at"`
}

var providerNameRE = regexp.MustCompile(`^[a-z][a-z0-9]{1,31}$`)

const (
	oauthAppConnectorPrefix = "_oauth_app:"
	oauthAppIDPrefix        = "oauth_app__"
)

// oauthAppRowKeys returns the (id, connector_type) pair for a provider.
func oauthAppRowKeys(provider string) (string, string) {
	return oauthAppIDPrefix + provider, oauthAppConnectorPrefix + provider
}

// validateOAuthAppInputs checks provider/client_id/client_secret per the
// contract (oauth-app-config.md § Validation rules).
func validateOAuthAppInputs(provider string, creds OAuthAppCredentials) error {
	if !providerNameRE.MatchString(provider) {
		return fmt.Errorf("oauth_app: invalid provider %q (must match %s)", provider, providerNameRE.String())
	}
	if strings.TrimSpace(creds.ClientID) == "" {
		return errors.New("oauth_app: client_id required")
	}
	if len(creds.ClientID) > 256 {
		return errors.New("oauth_app: client_id too long (max 256 chars)")
	}
	if len(strings.TrimSpace(creds.ClientSecret)) < 16 {
		return errors.New("oauth_app: client_secret too short (min 16 chars)")
	}
	return nil
}

// GetOAuthApp returns the decrypted credentials for a provider, or
// (nil, nil) if no row exists. Returns secrets.ErrKeyringNotLoaded when
// the keyring is locked.
func (s *Service) GetOAuthApp(provider string) (*OAuthAppCredentials, error) {
	id, _ := oauthAppRowKeys(provider)
	if !s.keyring.IsLoaded() {
		return nil, secrets.ErrKeyringNotLoaded
	}
	row := s.db.DB.QueryRow(
		`SELECT config_ciphertext, config_nonce, dek_wrapped, dek_nonce, enc_version
		 FROM connections WHERE id = ?`, id,
	)
	var blob secrets.EncryptedBlob
	if err := row.Scan(
		&blob.Ciphertext, &blob.Nonce, &blob.WrappedDEK, &blob.DEKNonce, &blob.Version,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("oauth_app: get %q: %w", provider, err)
	}
	var out OAuthAppCredentials
	if err := s.keyring.WithKEK(func(kek []byte) error {
		plaintext, err := secrets.Decrypt(kek, &blob)
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
		return json.Unmarshal(plaintext, &out)
	}); err != nil {
		return nil, fmt.Errorf("oauth_app: get %q: %w", provider, err)
	}
	return &out, nil
}

// PutOAuthApp upserts the credentials for a provider. Returns
// secrets.ErrKeyringNotLoaded when the keyring is locked.
func (s *Service) PutOAuthApp(provider string, creds OAuthAppCredentials) error {
	if err := validateOAuthAppInputs(provider, creds); err != nil {
		return err
	}
	if !s.keyring.IsLoaded() {
		return secrets.ErrKeyringNotLoaded
	}
	id, ctype := oauthAppRowKeys(provider)
	plaintext, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("oauth_app: marshal: %w", err)
	}
	var blob *secrets.EncryptedBlob
	if err := s.keyring.WithKEK(func(kek []byte) error {
		b, encErr := secrets.Encrypt(kek, plaintext)
		if encErr != nil {
			return encErr
		}
		blob = b
		return nil
	}); err != nil {
		return fmt.Errorf("oauth_app: encrypt: %w", err)
	}

	// Upsert via DELETE+INSERT to avoid SQLite's ON CONFLICT verbosity
	// for the multi-column-update case.
	tx, err := s.db.DB.Begin()
	if err != nil {
		return fmt.Errorf("oauth_app: begin tx: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM connections WHERE id = ?`, id); err != nil {
		return fmt.Errorf("oauth_app: delete existing: %w", err)
	}
	displayName := "OAuth App: " + provider
	if _, err := tx.Exec(
		`INSERT INTO connections (
			id, connector_type, display_name,
			config_ciphertext, config_nonce,
			dek_wrapped, dek_nonce, enc_version,
			status, created_at, reauth_reason
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, NULL)`,
		id, ctype, displayName,
		blob.Ciphertext, blob.Nonce,
		blob.WrappedDEK, blob.DEKNonce, blob.Version,
		time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("oauth_app: insert: %w", err)
	}
	return tx.Commit()
}

// DeleteOAuthApp removes the credentials row for a provider. Idempotent
// (returns nil if absent). Does not require the keyring — plaintext
// row delete only.
func (s *Service) DeleteOAuthApp(provider string) error {
	id, _ := oauthAppRowKeys(provider)
	if _, err := s.db.DB.Exec(`DELETE FROM connections WHERE id = ?`, id); err != nil {
		return fmt.Errorf("oauth_app: delete %q: %w", provider, err)
	}
	return nil
}

// ListOAuthApps returns metadata (no secrets) for every _oauth_app:*
// row, sorted by provider. Does not require the keyring.
func (s *Service) ListOAuthApps() ([]OAuthAppMeta, error) {
	rows, err := s.db.DB.Query(
		`SELECT id, connector_type, created_at FROM connections
		 WHERE connector_type LIKE ? ESCAPE '\'
		 ORDER BY connector_type`,
		`\_oauth_app:%`,
	)
	if err != nil {
		return nil, fmt.Errorf("oauth_app: list: %w", err)
	}
	defer rows.Close()
	var out []OAuthAppMeta
	for rows.Next() {
		var id, ctype string
		var updatedAt time.Time
		if err := rows.Scan(&id, &ctype, &updatedAt); err != nil {
			return nil, fmt.Errorf("oauth_app: scan: %w", err)
		}
		provider := strings.TrimPrefix(ctype, oauthAppConnectorPrefix)
		meta := OAuthAppMeta{Provider: provider, HasSecret: true, UpdatedAt: updatedAt}
		// Decrypt client_id only if the keyring is loaded — the secret
		// stays sealed but client_id is non-secret and useful to the
		// admin UI for diagnostic display.
		if s.keyring.IsLoaded() {
			if creds, err := s.GetOAuthApp(provider); err == nil && creds != nil {
				meta.ClientID = creds.ClientID
			}
		}
		out = append(out, meta)
	}
	return out, rows.Err()
}
