package store

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"passbook/internal/backend/crypto/age"
	"passbook/internal/models"
)

const (
	credentialsDir = "credentials"
)

// ListCredentials returns all credentials
func (s *Store) ListCredentials(ctx context.Context) ([]models.CredentialSummary, error) {
	files, err := s.storage.List(ctx, credentialsDir)
	if err != nil {
		return nil, err
	}

	var summaries []models.CredentialSummary
	for _, file := range files {
		if !strings.HasSuffix(file, age.Ext) {
			continue
		}

		cred, err := s.loadCredential(ctx, file)
		if err != nil {
			continue // Skip files we can't decrypt
		}

		summaries = append(summaries, cred.ToSummary())
	}

	return summaries, nil
}

// ListCredentialsByWebsite returns credentials for a specific website
func (s *Store) ListCredentialsByWebsite(ctx context.Context, website string) ([]models.CredentialSummary, error) {
	prefix := filepath.Join(credentialsDir, website)
	files, err := s.storage.List(ctx, prefix)
	if err != nil {
		return nil, err
	}

	var summaries []models.CredentialSummary
	for _, file := range files {
		if !strings.HasSuffix(file, age.Ext) {
			continue
		}

		cred, err := s.loadCredential(ctx, file)
		if err != nil {
			continue
		}

		summaries = append(summaries, cred.ToSummary())
	}

	return summaries, nil
}

// GetCredential returns a credential by website and name
func (s *Store) GetCredential(ctx context.Context, website, name string) (*models.Credential, error) {
	path := fmt.Sprintf("%s/%s/%s%s", credentialsDir, website, name, age.Ext)
	return s.loadCredential(ctx, path)
}

// CreateCredential creates a new credential
func (s *Store) CreateCredential(ctx context.Context, cred *models.Credential, createdBy string) error {
	// Validate
	if cred.Website == "" {
		return fmt.Errorf("%w: website is required", ErrInvalidInput)
	}
	if cred.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}

	// Check if exists
	path := cred.FullPath()
	if s.storage.Exists(ctx, path) {
		return ErrAlreadyExists
	}

	// Set metadata
	if cred.ID == "" {
		cred.ID = uuid.New().String()
	}
	cred.CreatedBy = createdBy
	cred.CreatedAt = time.Now()
	cred.UpdatedAt = time.Now()

	// Save
	return s.saveCredential(ctx, cred)
}

// UpdateCredential updates a credential
func (s *Store) UpdateCredential(ctx context.Context, cred *models.Credential) error {
	// Check if exists
	path := cred.FullPath()
	if !s.storage.Exists(ctx, path) {
		return ErrNotFound
	}

	cred.UpdatedAt = time.Now()

	return s.saveCredential(ctx, cred)
}

// DeleteCredential removes a credential
func (s *Store) DeleteCredential(ctx context.Context, website, name string) error {
	path := fmt.Sprintf("%s/%s/%s%s", credentialsDir, website, name, age.Ext)
	if !s.storage.Exists(ctx, path) {
		return ErrNotFound
	}

	return s.storage.Delete(ctx, path)
}

// loadCredential loads and decrypts a credential
func (s *Store) loadCredential(ctx context.Context, path string) (*models.Credential, error) {
	data, err := s.storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}

	plaintext, err := s.crypto.Decrypt(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt credential: %w", err)
	}

	var cred models.Credential
	if err := yaml.Unmarshal(plaintext, &cred); err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	return &cred, nil
}

// saveCredential encrypts and saves a credential
func (s *Store) saveCredential(ctx context.Context, cred *models.Credential) error {
	var keys []string
	var err error

	// Check if credential has explicit permissions
	if cred.Permissions != nil && cred.Permissions.Count() > 0 && !cred.Permissions.UseRoleBasedAccess {
		// Use explicit recipient list (only those who can read)
		keys = cred.Permissions.GetReadRecipients()
	} else {
		// Fall back to all recipients (role-based access)
		keys, err = s.getAllRecipientKeys()
		if err != nil {
			return err
		}
	}

	if len(keys) == 0 {
		return fmt.Errorf("no recipients specified for credential")
	}

	// Serialize
	data, err := yaml.Marshal(cred)
	if err != nil {
		return err
	}

	// Encrypt
	encrypted, err := s.encryptForRecipients(ctx, data, keys)
	if err != nil {
		return err
	}

	// Save
	path := cred.FullPath()
	return s.storage.Set(ctx, path, encrypted)
}

// AddCredentialRecipient adds a recipient to a credential
func (s *Store) AddCredentialRecipient(ctx context.Context, website, name, email, publicKey string, access models.AccessLevel) error {
	cred, err := s.GetCredential(ctx, website, name)
	if err != nil {
		return err
	}

	cred.GetPermissions().AddRecipient(email, publicKey, access)
	cred.UpdatedAt = time.Now()

	return s.saveCredential(ctx, cred)
}

// RemoveCredentialRecipient removes a recipient from a credential
func (s *Store) RemoveCredentialRecipient(ctx context.Context, website, name, email string) error {
	cred, err := s.GetCredential(ctx, website, name)
	if err != nil {
		return err
	}

	if !cred.GetPermissions().RemoveRecipient(email) {
		return fmt.Errorf("recipient %s not found", email)
	}
	cred.UpdatedAt = time.Now()

	return s.saveCredential(ctx, cred)
}

// ListCredentialRecipients lists recipients for a credential
func (s *Store) ListCredentialRecipients(ctx context.Context, website, name string) ([]models.RecipientPermission, error) {
	cred, err := s.GetCredential(ctx, website, name)
	if err != nil {
		return nil, err
	}

	if cred.Permissions == nil {
		return []models.RecipientPermission{}, nil
	}

	return cred.Permissions.ListRecipients(), nil
}

// ListWebsites returns all websites that have credentials
func (s *Store) ListWebsites(ctx context.Context) ([]string, error) {
	return s.storage.ListDirs(ctx, credentialsDir)
}
