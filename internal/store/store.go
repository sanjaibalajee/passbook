package store

import (
	"context"
	"errors"

	"passbook/internal/backend/crypto/age"
	"passbook/internal/backend/storage/gitfs"
	"passbook/internal/config"
	"passbook/internal/models"
	"passbook/internal/rbac"
	"passbook/internal/recipients"
)

var (
	// ErrNotFound is returned when a resource is not found
	ErrNotFound = errors.New("not found")

	// ErrAccessDenied is returned when access is denied
	ErrAccessDenied = errors.New("access denied")

	// ErrAlreadyExists is returned when a resource already exists
	ErrAlreadyExists = errors.New("already exists")

	// ErrInvalidInput is returned for invalid input
	ErrInvalidInput = errors.New("invalid input")
)

// Store provides access to passbook data
type Store struct {
	cfg     *config.Config
	crypto  *age.Age
	storage *gitfs.Git
	rbac    *rbac.Engine
}

// New creates a new store
func New(cfg *config.Config) (*Store, error) {
	// Initialize crypto
	crypto, err := age.New(cfg.IdentityPath())
	if err != nil {
		return nil, err
	}

	// Initialize storage
	storage, err := gitfs.New(cfg.StorePath)
	if err != nil {
		return nil, err
	}

	s := &Store{
		cfg:     cfg,
		crypto:  crypto,
		storage: storage,
	}

	// Initialize RBAC with self as user store
	s.rbac = rbac.NewEngine(s)

	return s, nil
}

// RBAC returns the RBAC engine
func (s *Store) RBAC() *rbac.Engine {
	return s.rbac
}

// Crypto returns the crypto backend
func (s *Store) Crypto() *age.Age {
	return s.crypto
}

// Storage returns the storage backend
func (s *Store) Storage() *gitfs.Git {
	return s.storage
}

// Sync synchronizes with git remote
func (s *Store) Sync(ctx context.Context) error {
	return s.storage.Sync(ctx)
}

// Push pushes to git remote
func (s *Store) Push(ctx context.Context) error {
	return s.storage.Push(ctx)
}

// Pull pulls from git remote
func (s *Store) Pull(ctx context.Context) error {
	return s.storage.Pull(ctx)
}

// GetRecipients loads the main recipients file
func (s *Store) GetRecipients(ctx context.Context) (*recipients.Recipients, error) {
	data, err := s.storage.Get(ctx, recipients.RecipientsFile)
	if err != nil {
		return nil, err
	}
	return recipients.Parse(data)
}

// SaveRecipients saves the main recipients file
func (s *Store) SaveRecipients(ctx context.Context, recps *recipients.Recipients) error {
	return s.storage.Set(ctx, recipients.RecipientsFile, recps.Marshal())
}

// Commit creates a git commit
func (s *Store) Commit(ctx context.Context, message string) error {
	return s.storage.Commit(ctx, message)
}

// encryptForRecipients encrypts data for the given recipients
func (s *Store) encryptForRecipients(ctx context.Context, data []byte, recipientKeys []string) ([]byte, error) {
	return s.crypto.Encrypt(ctx, data, recipientKeys)
}

// decrypt decrypts data
func (s *Store) decrypt(ctx context.Context, data []byte) ([]byte, error) {
	return s.crypto.Decrypt(ctx, data)
}

// getRecipientKeysForStage returns public keys for users who can access a stage
func (s *Store) getRecipientKeysForStage(stage models.Stage) ([]string, error) {
	return s.rbac.GetStageRecipients(stage)
}

// getAllRecipientKeys returns all user public keys
func (s *Store) getAllRecipientKeys() ([]string, error) {
	return s.rbac.GetAllRecipients()
}
