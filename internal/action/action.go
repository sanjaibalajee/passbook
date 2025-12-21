package action

import (
	"passbook/internal/auth"
	"passbook/internal/config"
)

// Action provides CLI command handlers
type Action struct {
	cfg   *config.Config
	store Store
	auth  *auth.Auth
	// rbac  *rbac.Engine
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

	// Full initialization requires:
	// - Valid store path
	// - Identity configured
	// - Store initialized

	if !cfg.IsInitialized() {
		return nil, ErrNotInitialized
	}

	// Initialize auth
	authService, err := auth.New(cfg)
	if err != nil {
		return nil, err
	}
	a.auth = authService

	// TODO: Initialize store, rbac when those packages are ready

	return a, nil
}

// NewBasic creates a basic Action handler for setup commands
func NewBasic(cfg *config.Config) *Action {
	a := &Action{
		cfg: cfg,
	}

	// Initialize auth even for basic actions (for login)
	authService, err := auth.New(cfg)
	if err == nil {
		a.auth = authService
	}

	return a
}

// Config returns the current configuration
func (a *Action) Config() *config.Config {
	return a.cfg
}

// Auth returns the auth service
func (a *Action) Auth() *auth.Auth {
	return a.auth
}
