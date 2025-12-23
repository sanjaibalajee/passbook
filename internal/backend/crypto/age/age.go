package age

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	// Ext is the file extension for encrypted files
	Ext = ".age"

	// Name is the backend name
	Name = "age"

	// Argon2 parameters for key derivation (OWASP recommended)
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32

	// Salt size for Argon2
	saltSize = 16

	// Encrypted key file markers
	encryptedKeyHeader = "-----BEGIN PASSBOOK ENCRYPTED KEY-----"
	encryptedKeyFooter = "-----END PASSBOOK ENCRYPTED KEY-----"
)

var (
	// ErrNoIdentity is returned when no identity is found
	ErrNoIdentity = errors.New("no identity found")

	// ErrInvalidRecipient is returned when a recipient is invalid
	ErrInvalidRecipient = errors.New("invalid recipient")

	// ErrDecryptionFailed is returned when decryption fails
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrInvalidPassphrase is returned when the passphrase is wrong
	ErrInvalidPassphrase = errors.New("invalid passphrase")

	// ErrPassphraseRequired is returned when a passphrase is needed
	ErrPassphraseRequired = errors.New("passphrase required for encrypted key")

	// ErrKeyNotEncrypted is returned when trying to decrypt an unencrypted key
	ErrKeyNotEncrypted = errors.New("key is not passphrase-protected")
)

// Age implements the Crypto interface using age encryption
type Age struct {
	identityPath string              // Path to private key file
	publicKey    string              // User's public key (age1...)
	identity     *age.X25519Identity // Cached identity
	isEncrypted  bool                // Whether the key file is passphrase-protected
}

// New creates a new Age crypto backend
// If the key is passphrase-protected, it will prompt for the passphrase
func New(identityPath string) (*Age, error) {
	a := &Age{
		identityPath: identityPath,
	}

	// Check if key is encrypted
	encrypted, err := IsKeyEncrypted(identityPath)
	if err != nil {
		return nil, err
	}
	a.isEncrypted = encrypted

	if encrypted {
		// Prompt for passphrase
		passphrase, err := PromptPassphrase("Enter passphrase to unlock key: ")
		if err != nil {
			return nil, err
		}
		if err := a.loadIdentityWithPassphrase(passphrase); err != nil {
			return nil, err
		}
		// Note: passphrase is a string, can't be zeroed. The underlying bytes
		// in loadIdentityWithPassphrase are zeroed after use.
	} else {
		// Load unencrypted identity
		if err := a.loadIdentity(); err != nil {
			return nil, err
		}
	}

	return a, nil
}

// NewWithPassphrase creates a new Age crypto backend with explicit passphrase
func NewWithPassphrase(identityPath, passphrase string) (*Age, error) {
	a := &Age{
		identityPath: identityPath,
		isEncrypted:  true,
	}

	if err := a.loadIdentityWithPassphrase(passphrase); err != nil {
		return nil, err
	}

	return a, nil
}

// NewWithoutIdentity creates an Age backend without loading identity
// Useful for generating new identities
func NewWithoutIdentity() *Age {
	return &Age{}
}

// IsEncrypted returns whether the key file is passphrase-protected
func (a *Age) IsEncrypted() bool {
	return a.isEncrypted
}

// GenerateIdentity creates a new age keypair and saves it to the given path (unencrypted)
func GenerateIdentity(path string) (publicKey string, err error) {
	return GenerateIdentityWithPassphrase(path, "")
}

// GenerateIdentityWithPassphrase creates a new age keypair with optional passphrase protection
func GenerateIdentityWithPassphrase(path, passphrase string) (publicKey string, err error) {
	// Generate identity
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("failed to generate identity: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	if passphrase != "" {
		// Save encrypted
		if err := saveEncryptedIdentity(path, identity, passphrase); err != nil {
			return "", err
		}
	} else {
		// Save unencrypted (legacy format)
		if err := saveUnencryptedIdentity(path, identity); err != nil {
			return "", err
		}
	}

	return identity.Recipient().String(), nil
}

// saveUnencryptedIdentity saves an identity without encryption
func saveUnencryptedIdentity(path string, identity *age.X25519Identity) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create identity file: %w", err)
	}
	defer f.Close()

	// Write with comments (like age-keygen)
	fmt.Fprintf(f, "# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(f, "# public key: %s\n", identity.Recipient().String())
	fmt.Fprintf(f, "%s\n", identity.String())

	return nil
}

// saveEncryptedIdentity saves an identity with passphrase protection
func saveEncryptedIdentity(path string, identity *age.X25519Identity, passphrase string) error {
	// Generate random salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key using Argon2id
	key := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Create ChaCha20-Poly1305 cipher
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Prepare plaintext: private key string
	plaintext := []byte(identity.String())

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Zero out key and plaintext
	for i := range key {
		key[i] = 0
	}
	for i := range plaintext {
		plaintext[i] = 0
	}

	// Create file
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create identity file: %w", err)
	}
	defer f.Close()

	// Write header with metadata
	fmt.Fprintf(f, "%s\n", encryptedKeyHeader)
	fmt.Fprintf(f, "# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(f, "# public key: %s\n", identity.Recipient().String())
	fmt.Fprintf(f, "# encryption: argon2id+chacha20poly1305\n")

	// Encode salt, nonce, and ciphertext as base64
	fmt.Fprintf(f, "salt: %s\n", base64.StdEncoding.EncodeToString(salt))
	fmt.Fprintf(f, "nonce: %s\n", base64.StdEncoding.EncodeToString(nonce))
	fmt.Fprintf(f, "data: %s\n", base64.StdEncoding.EncodeToString(ciphertext))

	fmt.Fprintf(f, "%s\n", encryptedKeyFooter)

	return nil
}

// EncryptExistingKey encrypts an existing unencrypted key file with a passphrase
func EncryptExistingKey(path, passphrase string) error {
	// Load existing identity
	a := &Age{identityPath: path}
	if err := a.loadIdentity(); err != nil {
		return fmt.Errorf("failed to load identity: %w", err)
	}

	// Save with encryption
	return saveEncryptedIdentity(path, a.identity, passphrase)
}

// DecryptKeyFile decrypts an encrypted key file and saves it unencrypted
func DecryptKeyFile(path, passphrase string) error {
	// Load encrypted identity
	a := &Age{identityPath: path}
	if err := a.loadIdentityWithPassphrase(passphrase); err != nil {
		return fmt.Errorf("failed to decrypt identity: %w", err)
	}

	// Save unencrypted
	return saveUnencryptedIdentity(path, a.identity)
}

// ChangePassphrase changes the passphrase on an encrypted key file
func ChangePassphrase(path, oldPassphrase, newPassphrase string) error {
	// Load with old passphrase
	a := &Age{identityPath: path}
	if err := a.loadIdentityWithPassphrase(oldPassphrase); err != nil {
		return fmt.Errorf("failed to decrypt with old passphrase: %w", err)
	}

	// Save with new passphrase
	return saveEncryptedIdentity(path, a.identity, newPassphrase)
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

// EncryptToArmor encrypts and returns ASCII-armored output using age's built-in armor
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
	armorWriter := armor.NewWriter(&buf)

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

// DecryptFromArmor decrypts ASCII-armored ciphertext using age's built-in armor
func (a *Age) DecryptFromArmor(ctx context.Context, armoredCiphertext []byte) ([]byte, error) {
	if a.identity == nil {
		return nil, ErrNoIdentity
	}

	armorReader := armor.NewReader(bytes.NewReader(armoredCiphertext))

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

// loadIdentityWithPassphrase loads an encrypted private key file
func (a *Age) loadIdentityWithPassphrase(passphrase string) error {
	data, err := os.ReadFile(a.identityPath)
	if err != nil {
		return fmt.Errorf("failed to read identity file: %w", err)
	}

	// Parse the encrypted file format
	var salt, nonce, ciphertext []byte
	var publicKey string

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "# public key:") {
			publicKey = strings.TrimSpace(strings.TrimPrefix(line, "# public key:"))
		} else if strings.HasPrefix(line, "salt:") {
			saltStr := strings.TrimSpace(strings.TrimPrefix(line, "salt:"))
			salt, err = base64.StdEncoding.DecodeString(saltStr)
			if err != nil {
				return fmt.Errorf("failed to decode salt: %w", err)
			}
		} else if strings.HasPrefix(line, "nonce:") {
			nonceStr := strings.TrimSpace(strings.TrimPrefix(line, "nonce:"))
			nonce, err = base64.StdEncoding.DecodeString(nonceStr)
			if err != nil {
				return fmt.Errorf("failed to decode nonce: %w", err)
			}
		} else if strings.HasPrefix(line, "data:") {
			dataStr := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			ciphertext, err = base64.StdEncoding.DecodeString(dataStr)
			if err != nil {
				return fmt.Errorf("failed to decode ciphertext: %w", err)
			}
		}
	}

	if salt == nil || nonce == nil || ciphertext == nil {
		return ErrKeyNotEncrypted
	}

	// Derive key using Argon2id
	key := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Create ChaCha20-Poly1305 cipher
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Decrypt
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Zero out key before returning
		for i := range key {
			key[i] = 0
		}
		return ErrInvalidPassphrase
	}

	// Zero out key
	for i := range key {
		key[i] = 0
	}

	// Parse the decrypted private key
	privateKeyStr := strings.TrimSpace(string(plaintext))

	// Zero out plaintext
	for i := range plaintext {
		plaintext[i] = 0
	}

	// Parse identity
	identity, err := age.ParseX25519Identity(privateKeyStr)
	if err != nil {
		return fmt.Errorf("failed to parse decrypted identity: %w", err)
	}

	a.identity = identity
	a.publicKey = publicKey
	if a.publicKey == "" {
		a.publicKey = identity.Recipient().String()
	}

	return nil
}

// IsKeyEncrypted checks if an identity file is passphrase-protected
func IsKeyEncrypted(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return bytes.Contains(data, []byte(encryptedKeyHeader)), nil
}

// PromptPassphrase prompts the user for a passphrase securely
func PromptPassphrase(prompt string) (string, error) {
	fmt.Print(prompt)

	// Try to read from terminal securely (no echo)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		password, err := term.ReadPassword(fd)
		fmt.Println() // Print newline after password input
		if err != nil {
			return "", fmt.Errorf("failed to read passphrase: %w", err)
		}
		return string(password), nil
	}

	// Fallback for non-terminal (e.g., pipes)
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read passphrase: %w", err)
	}
	return strings.TrimSpace(password), nil
}

// PromptPassphraseConfirm prompts for a passphrase with confirmation
func PromptPassphraseConfirm(prompt string) (string, error) {
	passphrase, err := PromptPassphrase(prompt)
	if err != nil {
		return "", err
	}

	confirm, err := PromptPassphrase("Confirm passphrase: ")
	if err != nil {
		return "", err
	}

	if passphrase != confirm {
		return "", errors.New("passphrases do not match")
	}

	return passphrase, nil
}

// GetPublicKeyFromFile extracts the public key from an identity file without loading the private key
func GetPublicKeyFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "# public key:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# public key:")), nil
		}
	}

	return "", errors.New("public key not found in identity file")
}

// IsArmored checks if data is ASCII-armored (using age's format)
func IsArmored(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN AGE ENCRYPTED FILE-----"))
}

// ZeroBytes securely zeros a byte slice
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
