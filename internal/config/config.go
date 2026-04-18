package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server     ServerConfig               `yaml:"server"`
	Connectors map[string]ConnectorConfig `yaml:"connectors"`
	Policy     PolicyConfig               `yaml:"policy"`
	Audit      AuditConfig                `yaml:"audit"`
	Database   DatabaseConfig             `yaml:"database"`
}

type ServerConfig struct {
	Host         string `yaml:"host"`
	APIPort      int    `yaml:"api_port"`
	UIPort       int    `yaml:"ui_port"`
	MCPTransport string `yaml:"mcp_transport"`
	// PassphraseFile is the path to a file containing the keyring passphrase.
	// Mirrors the SIEVE_PASSPHRASE_FILE env var so operators can configure
	// non-interactive startup via either YAML or environment.
	PassphraseFile string `yaml:"passphrase_file,omitempty"`
}

type ConnectorConfig struct {
	ClientCredentialsFile string `yaml:"client_credentials_file,omitempty"`
	// Generic key-value for connector-specific config
	Extra map[string]any `yaml:",inline"`
}

type PolicyConfig struct {
	ScriptsDir   string                       `yaml:"scripts_dir"`
	LLMProviders map[string]LLMProviderConfig `yaml:"llm_providers"`
}

type LLMProviderConfig struct {
	Endpoint  string `yaml:"endpoint,omitempty"`
	Region    string `yaml:"region,omitempty"`
	APIKeyEnv string `yaml:"api_key_env,omitempty"`
	Model     string `yaml:"model,omitempty"`
}

type AuditConfig struct {
	RetentionDays int `yaml:"retention_days"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "127.0.0.1",
			APIPort:      19817,
			UIPort:       19816,
			MCPTransport: "sse",
		},
		Connectors: map[string]ConnectorConfig{},
		Policy: PolicyConfig{
			ScriptsDir:   "/policies",
			LLMProviders: map[string]LLMProviderConfig{},
		},
		Audit: AuditConfig{
			RetentionDays: 90,
		},
		Database: DatabaseConfig{
			Path: "/data/sieve.db",
		},
	}
}
