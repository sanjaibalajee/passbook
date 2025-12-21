package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"passbook/internal/config"
)

const (
	// SessionFileName is the name of the session file
	SessionFileName = "session.json"
	// SessionDuration is how long a session is valid
	SessionDuration = 7 * 24 * time.Hour // 1 week
)

// Session represents an authenticated user session
type Session struct {
	Email     string    `json:"email"`
	PublicKey string    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired checks if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// SessionService manages session persistence
type SessionService struct {
	cfg         *config.Config
	sessionPath string
}

// NewSessionService creates a new session service
func NewSessionService(cfg *config.Config) *SessionService {
	return &SessionService{
		cfg:         cfg,
		sessionPath: filepath.Join(cfg.ConfigDir, SessionFileName),
	}
}

// Save saves a session to disk
func (s *SessionService) Save(session *Session) error {
	// Set timestamps
	session.CreatedAt = time.Now()
	session.ExpiresAt = time.Now().Add(SessionDuration)

	// Ensure directory exists
	if err := os.MkdirAll(s.cfg.ConfigDir, 0700); err != nil {
		return err
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}

	// Write file with restricted permissions
	return os.WriteFile(s.sessionPath, data, 0600)
}

// Load loads the current session from disk
func (s *SessionService) Load() (*Session, error) {
	data, err := os.ReadFile(s.sessionPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotLoggedIn
		}
		return nil, err
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	// Check expiration
	if session.IsExpired() {
		// Clear expired session
		_ = s.Clear()
		return nil, ErrSessionExpired
	}

	return &session, nil
}

// Clear removes the session file
func (s *SessionService) Clear() error {
	err := os.Remove(s.sessionPath)
	if os.IsNotExist(err) {
		return nil // Already cleared
	}
	return err
}

// Exists checks if a session file exists
func (s *SessionService) Exists() bool {
	_, err := os.Stat(s.sessionPath)
	return err == nil
}
