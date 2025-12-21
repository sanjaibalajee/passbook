package auth

import (
	"errors"
	"passbook/internal/config"
)

var (
	ErrInvalidDomain  = errors.New("email domain not allowed")
	ErrTokenExpired   = errors.New("verification code expired")
	ErrTokenInvalid   = errors.New("invalid verification code")
	ErrNotLoggedIn    = errors.New("not logged in")
	ErrSessionExpired = errors.New("session expired")
)

// Auth provides authentication services
type Auth struct {
	cfg       *config.Config
	magicLink *MagicLinkService
	session   *SessionService
	emailer   EmailSender
}

// New creates a new Auth service
func New(cfg *config.Config) (*Auth, error) {
	// Create email sender based on config
	emailer, err := NewEmailSender(cfg)
	if err != nil {
		return nil, err
	}

	return &Auth{
		cfg:       cfg,
		magicLink: NewMagicLinkService(cfg),
		session:   NewSessionService(cfg),
		emailer:   emailer,
	}, nil
}

// RequestLogin initiates the login flow by sending a verification code
func (a *Auth) RequestLogin(email string) error {
	// Validate domain
	if !a.cfg.IsAllowedEmail(email) {
		return ErrInvalidDomain
	}

	// Generate verification code
	code := a.magicLink.GenerateCode(email)

	// Send email with code
	return a.emailer.SendVerificationCode(email, code)
}

// VerifyLogin verifies the code and creates a session
func (a *Auth) VerifyLogin(email, code string) (*Session, error) {
	// Verify the code
	if !a.magicLink.VerifyCode(email, code) {
		return nil, ErrTokenInvalid
	}

	// Create session
	session := &Session{
		Email:     email,
		PublicKey: a.cfg.Identity.PublicKey,
	}

	// Save session
	if err := a.session.Save(session); err != nil {
		return nil, err
	}

	return session, nil
}

// GetCurrentSession returns the current session if valid
func (a *Auth) GetCurrentSession() (*Session, error) {
	return a.session.Load()
}

// Logout clears the current session
func (a *Auth) Logout() error {
	return a.session.Clear()
}

// IsLoggedIn checks if user is logged in
func (a *Auth) IsLoggedIn() bool {
	session, err := a.session.Load()
	return err == nil && session != nil
}
