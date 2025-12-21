package auth

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"passbook/internal/config"
)

const (
	// CodeLength is the length of the verification code
	CodeLength = 6
	// CodeTTL is how long a verification code is valid
	CodeTTL = 15 * time.Minute
)

// PendingVerification represents a pending login attempt
type PendingVerification struct {
	Email     string
	Code      string
	ExpiresAt time.Time
}

// MagicLinkService handles verification code generation and validation
type MagicLinkService struct {
	cfg      *config.Config
	pending  map[string]*PendingVerification // email -> verification
	mu       sync.RWMutex
}

// NewMagicLinkService creates a new magic link service
func NewMagicLinkService(cfg *config.Config) *MagicLinkService {
	return &MagicLinkService{
		cfg:     cfg,
		pending: make(map[string]*PendingVerification),
	}
}

// GenerateCode generates a verification code for the given email
func (s *MagicLinkService) GenerateCode(email string) string {
	code := generateSecureCode(CodeLength)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pending[strings.ToLower(email)] = &PendingVerification{
		Email:     email,
		Code:      code,
		ExpiresAt: time.Now().Add(CodeTTL),
	}

	// Cleanup expired codes
	s.cleanupExpired()

	return code
}

// VerifyCode verifies a code for the given email
func (s *MagicLinkService) VerifyCode(email, code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	emailKey := strings.ToLower(email)
	pending, ok := s.pending[emailKey]
	if !ok {
		return false
	}

	// Check expiration
	if time.Now().After(pending.ExpiresAt) {
		delete(s.pending, emailKey)
		return false
	}

	// Check code (case-insensitive)
	if !strings.EqualFold(pending.Code, code) {
		return false
	}

	// Remove used code
	delete(s.pending, emailKey)
	return true
}

// cleanupExpired removes expired pending verifications
func (s *MagicLinkService) cleanupExpired() {
	now := time.Now()
	for email, pending := range s.pending {
		if now.After(pending.ExpiresAt) {
			delete(s.pending, email)
		}
	}
}

// generateSecureCode generates a random alphanumeric code
func generateSecureCode(length int) string {
	// Generate random bytes
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to less secure but working code
		return "123456"
	}

	// Convert to hex and take first 'length' characters
	code := strings.ToUpper(hex.EncodeToString(bytes))[:length]
	return code
}
