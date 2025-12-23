package action

import (
	"passbook/internal/config"
)

// Action provides CLI command handlers
type Action struct {
	cfg   *config.Config
	store Store
}

// Store interface for data operations
type Store interface {
	// Will be implemented by store package
}

// New creates a new Action handler with full initialization
func New(cfg *config.Config) (*Action, error) {
	a := &Action{
		cfg: cfg,
	}

	if !cfg.IsInitialized() {
		return nil, ErrNotInitialized
	}

	return a, nil
}

// NewBasic creates a basic Action handler for setup commands
func NewBasic(cfg *config.Config) *Action {
	return &Action{
		cfg: cfg,
	}
}

// Config returns the current configuration
func (a *Action) Config() *config.Config {
	return a.cfg
}
