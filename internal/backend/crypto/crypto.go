package crypto

import "context"

// Crypto defines the interface for encryption backends
type Crypto interface {
	// Encrypt encrypts plaintext for the given recipients
	Encrypt(ctx context.Context, plaintext []byte, recipients []string) ([]byte, error)

	// Decrypt decrypts ciphertext using the user's identity
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)

	// PublicKey returns the user's public key
	PublicKey() string

	// Name returns the backend name
	Name() string
}
