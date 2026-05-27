// Package settings provides a simple key-value settings store backed by SQLite.
// It stores configuration like which LLM connection and model to use for
// AI-assisted features such as script generation.
package settings

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/trilitech/Sieve/internal/database"
)

// Well-known setting keys.
const (
	KeyLLMConnection = "llm_connection" // connection ID to use for LLM calls (e.g., "anthropic")
	KeyLLMModel      = "llm_model"      // model name (e.g., "claude-sonnet-4-20250514")
	KeyLLMMaxTokens  = "llm_max_tokens" // max tokens for generation (e.g., "4096")

	// NOTE: KeySlackClientID / KeySlackClientSecret were removed by
	// spec 002 US3 / FR-009. Slack OAuth credentials now live in the
	// connections table as an envelope-encrypted _oauth_app:slack row.
	// One-time migration of any legacy plaintext settings rows runs
	// from cmd/sieve/main.go after the keyring loads (FR-012).
)

// Delete removes a setting by key. No-op if the key is absent.
func (s *Service) Delete(key string) error {
	_, err := s.db.Exec(`DELETE FROM settings WHERE key = ?`, key)
	if err != nil {
		return fmt.Errorf("delete setting %q: %w", key, err)
	}
	return nil
}

// Service provides access to the settings store.
type Service struct {
	db *database.DB
}

// NewService creates a new settings service and ensures the settings table exists.
func NewService(db *database.DB) *Service {
	s := &Service{db: db}
	s.initTable()
	return s
}

func (s *Service) initTable() {
	const schema = `
	CREATE TABLE IF NOT EXISTS settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`
	// CREATE TABLE IF NOT EXISTS is idempotent — errors here indicate
	// a real DB problem, not a duplicate table.
	s.db.Exec(schema)
}

// Get returns the value for a setting key. Returns "" if not found.
func (s *Service) Get(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("get setting %q: %w", key, err)
	}
	return value, nil
}

// Set upserts a setting.
func (s *Service) Set(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("set setting %q: %w", key, err)
	}
	return nil
}

// GetAll returns all settings as a map.
func (s *Service) GetAll() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, fmt.Errorf("list settings: %w", err)
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("scan setting: %w", err)
		}
		result[k] = v
	}
	return result, rows.Err()
}
