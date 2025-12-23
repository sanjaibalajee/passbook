package verification

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"passbook/internal/backend/crypto/age"
)

const (
	// ChallengeLength is the length of the random challenge in bytes
	ChallengeLength = 32
	// ChallengeTTL is how long a challenge is valid
	ChallengeTTL = 24 * time.Hour
	// PendingVerificationsFile is the file storing pending verifications
	PendingVerificationsFile = ".passbook-pending-verifications"
)

var (
	// ErrChallengeExpired is returned when a challenge has expired
	ErrChallengeExpired = errors.New("verification challenge has expired")
	// ErrChallengeNotFound is returned when a challenge is not found
	ErrChallengeNotFound = errors.New("verification challenge not found")
	// ErrChallengeMismatch is returned when the response doesn't match
	ErrChallengeMismatch = errors.New("verification response does not match challenge")
	// ErrAlreadyVerified is returned when key is already verified
	ErrAlreadyVerified = errors.New("public key is already verified")
)

// PendingVerification represents a pending key ownership verification
type PendingVerification struct {
	Email              string    `yaml:"email"`
	PublicKey          string    `yaml:"public_key"`
	Challenge          string    `yaml:"challenge"`           // Base64 encoded random bytes
	EncryptedChallenge string    `yaml:"encrypted_challenge"` // Base64 encoded age-encrypted challenge
	CreatedAt          time.Time `yaml:"created_at"`
	ExpiresAt          time.Time `yaml:"expires_at"`
}

// PendingVerifications holds all pending verifications
type PendingVerifications struct {
	Verifications []PendingVerification `yaml:"verifications"`
}

// Verifier handles key ownership verification
type Verifier struct {
	storePath string
}

// NewVerifier creates a new verifier
func NewVerifier(storePath string) *Verifier {
	return &Verifier{storePath: storePath}
}

// CreateChallenge creates a new verification challenge for a public key
func (v *Verifier) CreateChallenge(email, publicKey string) (*PendingVerification, error) {
	// Validate public key format
	if !age.ValidatePublicKey(publicKey) {
		return nil, fmt.Errorf("invalid public key format")
	}

	// Generate random challenge
	challengeBytes := make([]byte, ChallengeLength)
	if _, err := rand.Read(challengeBytes); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}
	challenge := base64.StdEncoding.EncodeToString(challengeBytes)

	// Encrypt challenge with the claimed public key
	// Only the holder of the private key can decrypt this
	crypto := age.NewWithoutIdentity()
	encrypted, err := crypto.Encrypt(context.Background(), challengeBytes, []string{publicKey})
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt challenge: %w", err)
	}
	encryptedChallenge := base64.StdEncoding.EncodeToString(encrypted)

	// Create pending verification
	pv := &PendingVerification{
		Email:              email,
		PublicKey:          publicKey,
		Challenge:          challenge,
		EncryptedChallenge: encryptedChallenge,
		CreatedAt:          time.Now(),
		ExpiresAt:          time.Now().Add(ChallengeTTL),
	}

	// Save to pending verifications file
	if err := v.savePendingVerification(pv); err != nil {
		return nil, err
	}

	return pv, nil
}

// VerifyResponse verifies that the user can decrypt the challenge
func (v *Verifier) VerifyResponse(email, response string) error {
	// Load pending verifications
	pending, err := v.loadPendingVerifications()
	if err != nil {
		return err
	}

	// Find the verification for this email
	var found *PendingVerification
	var foundIdx int
	for i, pv := range pending.Verifications {
		if pv.Email == email {
			found = &pending.Verifications[i]
			foundIdx = i
			break
		}
	}

	if found == nil {
		return ErrChallengeNotFound
	}

	// Check expiration
	if time.Now().After(found.ExpiresAt) {
		// Remove expired challenge
		v.removePendingVerification(foundIdx)
		return ErrChallengeExpired
	}

	// Compare response with original challenge
	if response != found.Challenge {
		return ErrChallengeMismatch
	}

	// Verification successful - remove the pending verification
	if err := v.removePendingVerification(foundIdx); err != nil {
		return fmt.Errorf("failed to remove pending verification: %w", err)
	}

	return nil
}

// GetPendingVerification returns the pending verification for an email
func (v *Verifier) GetPendingVerification(email string) (*PendingVerification, error) {
	pending, err := v.loadPendingVerifications()
	if err != nil {
		return nil, err
	}

	for _, pv := range pending.Verifications {
		if pv.Email == email {
			if time.Now().After(pv.ExpiresAt) {
				return nil, ErrChallengeExpired
			}
			return &pv, nil
		}
	}

	return nil, ErrChallengeNotFound
}

// GetEncryptedChallenge returns the encrypted challenge for a user to decrypt
func (v *Verifier) GetEncryptedChallenge(email string) (string, error) {
	pv, err := v.GetPendingVerification(email)
	if err != nil {
		return "", err
	}
	return pv.EncryptedChallenge, nil
}

// CleanupExpired removes all expired pending verifications
func (v *Verifier) CleanupExpired() error {
	pending, err := v.loadPendingVerifications()
	if err != nil {
		return err
	}

	var active []PendingVerification
	now := time.Now()
	for _, pv := range pending.Verifications {
		if now.Before(pv.ExpiresAt) {
			active = append(active, pv)
		}
	}

	pending.Verifications = active
	return v.savePendingVerifications(pending)
}

// loadPendingVerifications loads the pending verifications file
func (v *Verifier) loadPendingVerifications() (*PendingVerifications, error) {
	path := filepath.Join(v.storePath, PendingVerificationsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &PendingVerifications{}, nil
		}
		return nil, err
	}

	var pending PendingVerifications
	if err := yaml.Unmarshal(data, &pending); err != nil {
		return nil, err
	}

	return &pending, nil
}

// savePendingVerifications saves all pending verifications
func (v *Verifier) savePendingVerifications(pending *PendingVerifications) error {
	path := filepath.Join(v.storePath, PendingVerificationsFile)
	data, err := yaml.Marshal(pending)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// savePendingVerification adds a new pending verification
func (v *Verifier) savePendingVerification(pv *PendingVerification) error {
	pending, err := v.loadPendingVerifications()
	if err != nil {
		return err
	}

	// Remove any existing verification for this email
	var filtered []PendingVerification
	for _, existing := range pending.Verifications {
		if existing.Email != pv.Email {
			filtered = append(filtered, existing)
		}
	}
	filtered = append(filtered, *pv)
	pending.Verifications = filtered

	return v.savePendingVerifications(pending)
}

// removePendingVerification removes a pending verification by index
func (v *Verifier) removePendingVerification(idx int) error {
	pending, err := v.loadPendingVerifications()
	if err != nil {
		return err
	}

	if idx < 0 || idx >= len(pending.Verifications) {
		return nil
	}

	pending.Verifications = append(pending.Verifications[:idx], pending.Verifications[idx+1:]...)
	return v.savePendingVerifications(pending)
}

// DecryptChallenge is a helper function for the new user to decrypt the challenge
// This would be called by the new user on their machine
func DecryptChallenge(identityPath, encryptedChallengeB64 string) (string, error) {
	// Decode the encrypted challenge
	encrypted, err := base64.StdEncoding.DecodeString(encryptedChallengeB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted challenge: %w", err)
	}

	// Load identity and decrypt
	crypto, err := age.New(identityPath)
	if err != nil {
		return "", fmt.Errorf("failed to load identity: %w", err)
	}

	decrypted, err := crypto.Decrypt(context.Background(), encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt challenge: %w", err)
	}

	// Return the original challenge (base64 encoded)
	return base64.StdEncoding.EncodeToString(decrypted), nil
}

// VerifyKeyOwnership is a helper that combines challenge creation and verification
// Returns the encrypted challenge that needs to be decrypted by the key owner
func VerifyKeyOwnership(storePath, email, publicKey string) (encryptedChallenge string, err error) {
	verifier := NewVerifier(storePath)

	// Create challenge
	pv, err := verifier.CreateChallenge(email, publicKey)
	if err != nil {
		return "", err
	}

	return pv.EncryptedChallenge, nil
}

// CompleteVerification completes the verification process
func CompleteVerification(storePath, email, response string) error {
	verifier := NewVerifier(storePath)
	return verifier.VerifyResponse(email, response)
}

// GenerateVerificationInstructions generates instructions for the new user
func GenerateVerificationInstructions(encryptedChallenge string) string {
	var buf bytes.Buffer
	buf.WriteString("To verify your key ownership, follow these steps:\n\n")
	buf.WriteString("1. Save the following encrypted challenge to a file (e.g., challenge.txt):\n\n")
	buf.WriteString(encryptedChallenge)
	buf.WriteString("\n\n2. Run the following command to decrypt it:\n")
	buf.WriteString("   passbook verify-key --challenge-file challenge.txt\n\n")
	buf.WriteString("3. Send the decrypted response back to the admin.\n")
	return buf.String()
}
