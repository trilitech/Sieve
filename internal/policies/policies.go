package policies

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/trilitech/Sieve/internal/database"
	"github.com/trilitech/Sieve/internal/policy"
)

// Policy is a stored, reusable policy definition.
type Policy struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	PolicyType   string         `json:"policy_type"`
	PolicyConfig map[string]any `json:"policy_config"`
	CreatedAt    time.Time      `json:"created_at"`
	// LintAck stores sticky acknowledgements of lint warnings, keyed by
	// the lint rule name (e.g., "deny_ceiling_v1"). A non-empty value
	// means the operator has accepted the named lint for the current
	// policy shape; subsequent saves that produce the same fingerprint
	// don't re-warn. Persisted in the lint_ack column of the policies
	// table as a JSON object; SetLintAck overwrites the whole column.
	LintAck map[string]any `json:"lint_ack,omitempty"`
}

type Service struct {
	db *database.DB
}

func NewService(db *database.DB) *Service {
	return &Service{db: db}
}

// Create stores a new policy.
func (s *Service) Create(name, policyType string, config map[string]any) (*Policy, error) {
	id := generateID()

	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("marshal policy config: %w", err)
	}

	now := time.Now().UTC()
	_, err = s.db.DB.Exec(
		`INSERT INTO policies (id, name, policy_type, policy_config, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, name, policyType, string(configJSON), now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert policy: %w", err)
	}

	return &Policy{
		ID:           id,
		Name:         name,
		PolicyType:   policyType,
		PolicyConfig: config,
		CreatedAt:    now,
	}, nil
}

// Update modifies an existing policy's name, type, and config.
func (s *Service) Update(id, name, policyType string, config map[string]any) error {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal policy config: %w", err)
	}

	res, err := s.db.DB.Exec(
		`UPDATE policies SET name = ?, policy_type = ?, policy_config = ? WHERE id = ?`,
		name, policyType, string(configJSON), id,
	)
	if err != nil {
		return fmt.Errorf("update policy: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("policy %q not found", id)
	}
	return nil
}

// Get returns a policy by ID.
func (s *Service) Get(id string) (*Policy, error) {
	row := s.db.DB.QueryRow(
		`SELECT id, name, policy_type, policy_config, created_at, lint_ack FROM policies WHERE id = ?`, id,
	)
	return scanPolicy(row)
}

// GetByName returns a policy by name.
func (s *Service) GetByName(name string) (*Policy, error) {
	row := s.db.DB.QueryRow(
		`SELECT id, name, policy_type, policy_config, created_at, lint_ack FROM policies WHERE name = ?`, name,
	)
	return scanPolicy(row)
}

// List returns all policies.
func (s *Service) List() ([]Policy, error) {
	rows, err := s.db.DB.Query(
		`SELECT id, name, policy_type, policy_config, created_at, lint_ack FROM policies ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	var result []Policy
	for rows.Next() {
		var p Policy
		var configJSON, lintAckJSON string
		if err := rows.Scan(&p.ID, &p.Name, &p.PolicyType, &configJSON, &p.CreatedAt, &lintAckJSON); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		if err := json.Unmarshal([]byte(configJSON), &p.PolicyConfig); err != nil {
			return nil, fmt.Errorf("unmarshal policy config: %w", err)
		}
		if lintAckJSON != "" && lintAckJSON != "{}" {
			if err := json.Unmarshal([]byte(lintAckJSON), &p.LintAck); err != nil {
				return nil, fmt.Errorf("unmarshal policy lint_ack (id=%s): %w", p.ID, err)
			}
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

// Delete removes a policy.
func (s *Service) Delete(id string) error {
	res, err := s.db.DB.Exec(`DELETE FROM policies WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete policy: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("policy %q not found", id)
	}
	return nil
}

// CreateEvaluator builds a policy.Evaluator from a stored policy.
func (s *Service) CreateEvaluator(p *Policy) (policy.Evaluator, error) {
	return policy.CreateEvaluator(p.PolicyType, p.PolicyConfig, nil)
}

// SeedPresets creates built-in preset policies if they don't already exist,
// and updates existing ones with the latest config (e.g., adding scope field).
func (s *Service) SeedPresets() error {
	for _, name := range policy.RulesPresetNames() {
		config, _ := policy.GetRulesPreset(name)

		var count int
		if err := s.db.DB.QueryRow(`SELECT COUNT(*) FROM policies WHERE name = ?`, name).Scan(&count); err != nil {
			return fmt.Errorf("check preset %q: %w", name, err)
		}

		if count > 0 {
			// Update existing preset with latest config (picks up new fields like scope).
			configJSON, _ := json.Marshal(config)
			s.db.DB.Exec(`UPDATE policies SET policy_config = ? WHERE name = ?`, string(configJSON), name)
			continue
		}

		if _, err := s.Create(name, "rules", config); err != nil {
			return fmt.Errorf("seed preset %q: %w", name, err)
		}
	}
	return nil
}

func scanPolicy(row interface{ Scan(...any) error }) (*Policy, error) {
	var p Policy
	var configJSON, lintAckJSON string
	if err := row.Scan(&p.ID, &p.Name, &p.PolicyType, &configJSON, &p.CreatedAt, &lintAckJSON); err != nil {
		return nil, fmt.Errorf("scan policy: %w", err)
	}
	if err := json.Unmarshal([]byte(configJSON), &p.PolicyConfig); err != nil {
		return nil, fmt.Errorf("unmarshal policy config: %w", err)
	}
	if lintAckJSON != "" && lintAckJSON != "{}" {
		if err := json.Unmarshal([]byte(lintAckJSON), &p.LintAck); err != nil {
			return nil, fmt.Errorf("unmarshal policy lint_ack (id=%s): %w", p.ID, err)
		}
	}
	return &p, nil
}

// SetLintAck overwrites the lint_ack JSON for the given policy.
// Callers compute the payload (typically a single rule_name → AckPayload
// entry) and pass it in. Pass nil/empty to clear the acks (the
// composition was removed).
func (s *Service) SetLintAck(id string, ack map[string]any) error {
	var payload string
	if len(ack) == 0 {
		payload = "{}"
	} else {
		b, err := json.Marshal(ack)
		if err != nil {
			return fmt.Errorf("marshal lint_ack: %w", err)
		}
		payload = string(b)
	}
	res, err := s.db.DB.Exec(`UPDATE policies SET lint_ack = ? WHERE id = ?`, payload, id)
	if err != nil {
		return fmt.Errorf("update lint_ack: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("policy %q not found", id)
	}
	return nil
}

// BuildEvaluator creates a composite evaluator from a list of policy IDs.
// Single-policy case returns the evaluator directly; multi-policy chains them
// via CompositeEvaluator (first deny wins, redactions merged).
func (s *Service) BuildEvaluator(policyIDs []string) (policy.Evaluator, error) {
	if len(policyIDs) == 0 {
		return nil, fmt.Errorf("no policies provided")
	}
	if len(policyIDs) == 1 {
		p, err := s.Get(policyIDs[0])
		if err != nil {
			return nil, err
		}
		return s.CreateEvaluator(p)
	}
	var evaluators []policy.Evaluator
	for _, pid := range policyIDs {
		p, err := s.Get(pid)
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", pid, err)
		}
		eval, err := s.CreateEvaluator(p)
		if err != nil {
			return nil, fmt.Errorf("policy %q evaluator: %w", pid, err)
		}
		evaluators = append(evaluators, eval)
	}
	return &policy.CompositeEvaluator{Evaluators: evaluators}, nil
}

func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
