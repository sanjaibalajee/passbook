package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration
type Config struct {
	// User identity config (local)
	Identity IdentityConfig `yaml:"identity"`

	// Store config (from .passbook-config)
	Org   OrgConfig   `yaml:"org"`
	Git   GitConfig   `yaml:"git"`
	Email EmailConfig `yaml:"email"`

	// Preferences
	Preferences PreferencesConfig `yaml:"preferences"`

	// Runtime (not serialized)
	StorePath      string `yaml:"-"`
	ConfigDir      string `yaml:"-"`
	UserConfigPath string `yaml:"-"`
}

// IdentityConfig holds user identity settings
type IdentityConfig struct {
	Email          string `yaml:"email"`
	PrivateKeyPath string `yaml:"private_key_path"`
	PublicKey      string `yaml:"public_key"`
}

// OrgConfig holds organization settings
type OrgConfig struct {
	Name          string `yaml:"name"`
	AllowedDomain string `yaml:"allowed_domain"` // e.g., "mycompany.com"
}

// GitConfig holds git settings
type GitConfig struct {
	Remote   string `yaml:"remote"`
	AutoPush bool   `yaml:"autopush"`
	AutoSync bool   `yaml:"autosync"`
	Branch   string `yaml:"branch"`
}

// EmailConfig holds email settings for magic link auth
type EmailConfig struct {
	Provider string     `yaml:"provider"` // "smtp", "sendgrid", "ses"
	SMTP     SMTPConfig `yaml:"smtp"`
}

// SMTPConfig holds SMTP server settings
type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"` // Or use env var PASSBOOK_SMTP_PASSWORD
}

// PreferencesConfig holds user preferences
type PreferencesConfig struct {
	Editor           string `yaml:"editor"`
	ClipboardTimeout int    `yaml:"clipboard_timeout"` // seconds
	Color            bool   `yaml:"color"`
}

// ServerConfig holds web server settings
type ServerConfig struct {
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	BaseURL       string `yaml:"base_url"`
	SessionSecret string `yaml:"session_secret"`
}

// Load loads configuration from files
func Load() (*Config, error) {
	cfg := &Config{}

	// Set default paths
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	cfg.ConfigDir = filepath.Join(homeDir, ".config", "passbook")
	cfg.UserConfigPath = filepath.Join(cfg.ConfigDir, "config.yaml")
	cfg.StorePath = filepath.Join(homeDir, ".passbook")

	// Override store path from env
	if path := os.Getenv("PASSBOOK_STORE"); path != "" {
		cfg.StorePath = path
	}

	// 1. Load user config (local settings)
	if err := loadYAML(cfg.UserConfigPath, cfg); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	// 2. Load store config (shared settings)
	storeConfigPath := filepath.Join(cfg.StorePath, ".passbook-config")
	if err := loadYAML(storeConfigPath, cfg); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	// 3. Apply defaults
	applyDefaults(cfg)

	// 4. Override from environment
	applyEnvOverrides(cfg)

	return cfg, nil
}

// Save saves the user configuration
func (c *Config) Save() error {
	// Ensure config directory exists
	if err := os.MkdirAll(c.ConfigDir, 0700); err != nil {
		return err
	}

	// Marshal user config
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return os.WriteFile(c.UserConfigPath, data, 0600)
}

// SaveStoreConfig saves the store configuration
func (c *Config) SaveStoreConfig() error {
	storeConfigPath := filepath.Join(c.StorePath, ".passbook-config")

	// Only save store-relevant config
	storeConfig := struct {
		Org   OrgConfig   `yaml:"org"`
		Git   GitConfig   `yaml:"git"`
		Email EmailConfig `yaml:"email"`
	}{
		Org:   c.Org,
		Git:   c.Git,
		Email: c.Email,
	}

	data, err := yaml.Marshal(storeConfig)
	if err != nil {
		return err
	}

	return os.WriteFile(storeConfigPath, data, 0600)
}

// IsAllowedEmail checks if email matches org's allowed domain
func (c *Config) IsAllowedEmail(email string) bool {
	if c.Org.AllowedDomain == "" {
		return true // No restriction
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	return strings.EqualFold(parts[1], c.Org.AllowedDomain)
}

// IdentityPath returns the path to the age identity file
func (c *Config) IdentityPath() string {
	if c.Identity.PrivateKeyPath != "" {
		return expandPath(c.Identity.PrivateKeyPath)
	}
	return filepath.Join(c.ConfigDir, "identity")
}

// IsInitialized checks if passbook is initialized
func (c *Config) IsInitialized() bool {
	// Check if store directory exists
	info, err := os.Stat(c.StorePath)
	if err != nil || !info.IsDir() {
		return false
	}

	// Check if .passbook-config exists
	configPath := filepath.Join(c.StorePath, ".passbook-config")
	_, err = os.Stat(configPath)
	return err == nil
}

// HasIdentity checks if user has an identity configured
func (c *Config) HasIdentity() bool {
	identityPath := c.IdentityPath()
	_, err := os.Stat(identityPath)
	return err == nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.StorePath == "" {
		return errors.New("store path is required")
	}
	return nil
}

// loadYAML loads a YAML file into the config struct
func loadYAML(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, cfg)
}

// expandPath expands ~ to home directory
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(homeDir, path[2:])
	}
	return path
}

// applyEnvOverrides applies environment variable overrides
func applyEnvOverrides(cfg *Config) {
	if password := os.Getenv("PASSBOOK_SMTP_PASSWORD"); password != "" {
		cfg.Email.SMTP.Password = password
	}

	if domain := os.Getenv("PASSBOOK_ALLOWED_DOMAIN"); domain != "" {
		cfg.Org.AllowedDomain = domain
	}
}
