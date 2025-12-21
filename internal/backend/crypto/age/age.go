package age

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

const (
	// Ext is the file extension for encrypted files
	Ext = ".age"

	// Name is the backend name
	Name = "age"
)

var (
	// ErrNoIdentity is returned when no identity is found
	ErrNoIdentity = errors.New("no identity found")

	// ErrInvalidRecipient is returned when a recipient is invalid
	ErrInvalidRecipient = errors.New("invalid recipient")

	// ErrDecryptionFailed is returned when decryption fails
	ErrDecryptionFailed = errors.New("decryption failed")
)

// Age implements the Crypto interface using age encryption
type Age struct {
	identityPath string            // Path to private key file
	publicKey    string            // User's public key (age1...)
	identity     *age.X25519Identity // Cached identity
}

// New creates a new Age crypto backend
func New(identityPath string) (*Age, error) {
	a := &Age{
		identityPath: identityPath,
	}

	// Load identity and public key
	if err := a.loadIdentity(); err != nil {
		return nil, err
	}

	return a, nil
}

// NewWithoutIdentity creates an Age backend without loading identity
// Useful for generating new identities
func NewWithoutIdentity() *Age {
	return &Age{}
}

// GenerateIdentity creates a new age keypair and saves it to the given path
func GenerateIdentity(path string) (publicKey string, err error) {
	// Generate identity
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("failed to generate identity: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	// Write private key
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to create identity file: %w", err)
	}
	defer f.Close()

	// Write with comments (like age-keygen)
	fmt.Fprintf(f, "# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(f, "# public key: %s\n", identity.Recipient().String())
	fmt.Fprintf(f, "%s\n", identity.String())

	return identity.Recipient().String(), nil
}

// Name returns the backend name
func (a *Age) Name() string {
	return Name
}

// PublicKey returns the user's public key
func (a *Age) PublicKey() string {
	return a.publicKey
}

// Encrypt encrypts plaintext for the given recipients
func (a *Age) Encrypt(ctx context.Context, plaintext []byte, recipients []string) ([]byte, error) {
	// Parse recipient public keys
	recps, err := a.parseRecipients(recipients)
	if err != nil {
		return nil, err
	}

	// Always include self so we can decrypt
	if a.publicKey != "" {
		selfRecp, err := age.ParseX25519Recipient(a.publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse self public key: %w", err)
		}
		recps = append(recps, selfRecp)
	}

	// Deduplicate recipients
	recps = dedupeRecipients(recps)

	if len(recps) == 0 {
		return nil, errors.New("no recipients specified")
	}

	// Encrypt
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recps...)
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypter: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("failed to write plaintext: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to close encrypter: %w", err)
	}

	return buf.Bytes(), nil
}

// Decrypt decrypts ciphertext using the user's identity
func (a *Age) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if a.identity == nil {
		return nil, ErrNoIdentity
	}

	// Decrypt
	r, err := age.Decrypt(bytes.NewReader(ciphertext), a.identity)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return io.ReadAll(r)
}

// EncryptToArmor encrypts and returns ASCII-armored output
func (a *Age) EncryptToArmor(ctx context.Context, plaintext []byte, recipients []string) ([]byte, error) {
	// Parse recipient public keys
	recps, err := a.parseRecipients(recipients)
	if err != nil {
		return nil, err
	}

	// Always include self
	if a.publicKey != "" {
		selfRecp, err := age.ParseX25519Recipient(a.publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse self public key: %w", err)
		}
		recps = append(recps, selfRecp)
	}

	recps = dedupeRecipients(recps)

	if len(recps) == 0 {
		return nil, errors.New("no recipients specified")
	}

	var buf bytes.Buffer
	armorWriter := NewArmorWriter(&buf)

	w, err := age.Encrypt(armorWriter, recps...)
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypter: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("failed to write plaintext: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to close encrypter: %w", err)
	}

	if err := armorWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close armor: %w", err)
	}

	return buf.Bytes(), nil
}

// DecryptFromArmor decrypts ASCII-armored ciphertext
func (a *Age) DecryptFromArmor(ctx context.Context, armoredCiphertext []byte) ([]byte, error) {
	if a.identity == nil {
		return nil, ErrNoIdentity
	}

	armorReader := NewArmorReader(bytes.NewReader(armoredCiphertext))

	r, err := age.Decrypt(armorReader, a.identity)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return io.ReadAll(r)
}

// loadIdentity loads the private key from file
func (a *Age) loadIdentity() error {
	f, err := os.Open(a.identityPath)
	if err != nil {
		return fmt.Errorf("failed to open identity file: %w", err)
	}
	defer f.Close()

	identities, err := age.ParseIdentities(f)
	if err != nil {
		return fmt.Errorf("failed to parse identity: %w", err)
	}

	if len(identities) == 0 {
		return ErrNoIdentity
	}

	// Find first X25519 identity
	for _, id := range identities {
		if x, ok := id.(*age.X25519Identity); ok {
			a.identity = x
			a.publicKey = x.Recipient().String()
			return nil
		}
	}

	return ErrNoIdentity
}

// parseRecipients parses recipient public keys
func (a *Age) parseRecipients(recipients []string) ([]age.Recipient, error) {
	var recps []age.Recipient

	for _, r := range recipients {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}

		recp, err := age.ParseX25519Recipient(r)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidRecipient, r)
		}
		recps = append(recps, recp)
	}

	return recps, nil
}

// dedupeRecipients removes duplicate recipients
func dedupeRecipients(recps []age.Recipient) []age.Recipient {
	seen := make(map[string]bool)
	var result []age.Recipient

	for _, r := range recps {
		// Type assert to X25519Recipient to get string representation
		var key string
		if x, ok := r.(*age.X25519Recipient); ok {
			key = x.String()
		} else {
			// For other recipient types, use a unique identifier
			key = fmt.Sprintf("%T:%p", r, r)
		}
		if !seen[key] {
			seen[key] = true
			result = append(result, r)
		}
	}

	return result
}

// ValidatePublicKey checks if a public key is valid
func ValidatePublicKey(key string) bool {
	_, err := age.ParseX25519Recipient(key)
	return err == nil
}
