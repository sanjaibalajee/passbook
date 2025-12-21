package config

import "os"

// applyDefaults applies default values to the configuration
func applyDefaults(cfg *Config) {
	// Git defaults
	if cfg.Git.Branch == "" {
		cfg.Git.Branch = "main"
	}

	// Email defaults - use console for dev, smtp requires explicit config
	if cfg.Email.Provider == "" {
		cfg.Email.Provider = "console"
	}
	if cfg.Email.SMTP.Port == 0 {
		cfg.Email.SMTP.Port = 587
	}

	// Preferences defaults
	if cfg.Preferences.Editor == "" {
		cfg.Preferences.Editor = getDefaultEditor()
	}
	if cfg.Preferences.ClipboardTimeout == 0 {
		cfg.Preferences.ClipboardTimeout = 45 // 45 seconds
	}
	// Color defaults to true
	if !cfg.Preferences.Color {
		cfg.Preferences.Color = true
	}
}

// getDefaultEditor returns the default editor from environment
func getDefaultEditor() string {
	// Check environment variables in order of preference
	if editor := os.Getenv("EDITOR"); editor != "" {
		return editor
	}
	if editor := os.Getenv("VISUAL"); editor != "" {
		return editor
	}
	// Default to vim
	return "vim"
}

// DefaultConfig returns a new config with default values
func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()

	cfg := &Config{
		ConfigDir:      homeDir + "/.config/passbook",
		UserConfigPath: homeDir + "/.config/passbook/config.yaml",
		StorePath:      homeDir + "/.passbook",
		Git: GitConfig{
			Branch:   "main",
			AutoPush: true,
			AutoSync: true,
		},
		Email: EmailConfig{
			Provider: "console", // Default to console for dev; set "smtp" with host for production
			SMTP: SMTPConfig{
				Port: 587,
			},
		},
		Preferences: PreferencesConfig{
			Editor:           getDefaultEditor(),
			ClipboardTimeout: 45,
			Color:            true,
		},
	}

	return cfg
}
