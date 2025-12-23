package reencrypt

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"passbook/internal/backend/crypto/age"
)

// Stats holds re-encryption statistics
type Stats struct {
	TotalFiles      int
	SuccessfulFiles int
	FailedFiles     int
	SkippedFiles    int
	Errors          []string
}

// ReEncryptor handles re-encryption of secrets
type ReEncryptor struct {
	storePath string
	crypto    *age.Age
}

// NewReEncryptor creates a new re-encryptor
func NewReEncryptor(storePath string, crypto *age.Age) *ReEncryptor {
	return &ReEncryptor{
		storePath: storePath,
		crypto:    crypto,
	}
}

// ReEncryptAll re-encrypts all secrets with the new recipient list
func (r *ReEncryptor) ReEncryptAll(ctx context.Context, newRecipients []string) (*Stats, error) {
	stats := &Stats{}

	// Find all .age files in credentials/ and projects/
	dirs := []string{
		filepath.Join(r.storePath, "credentials"),
		filepath.Join(r.storePath, "projects"),
	}

	for _, dir := range dirs {
		if err := r.reEncryptDir(ctx, dir, newRecipients, stats); err != nil {
			return stats, err
		}
	}

	return stats, nil
}

// ReEncryptCredentials re-encrypts only credential files
func (r *ReEncryptor) ReEncryptCredentials(ctx context.Context, newRecipients []string) (*Stats, error) {
	stats := &Stats{}
	dir := filepath.Join(r.storePath, "credentials")
	if err := r.reEncryptDir(ctx, dir, newRecipients, stats); err != nil {
		return stats, err
	}
	return stats, nil
}

// ReEncryptProjects re-encrypts only project/env files
func (r *ReEncryptor) ReEncryptProjects(ctx context.Context, newRecipients []string) (*Stats, error) {
	stats := &Stats{}
	dir := filepath.Join(r.storePath, "projects")
	if err := r.reEncryptDir(ctx, dir, newRecipients, stats); err != nil {
		return stats, err
	}
	return stats, nil
}

// reEncryptDir recursively re-encrypts all .age files in a directory
func (r *ReEncryptor) reEncryptDir(ctx context.Context, dir string, recipients []string, stats *Stats) error {
	// Check if directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil // Directory doesn't exist, nothing to re-encrypt
	}

	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			stats.Errors = append(stats.Errors, fmt.Sprintf("walk error at %s: %v", path, err))
			return nil // Continue walking
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only process .age files
		if !strings.HasSuffix(path, age.Ext) {
			return nil
		}

		stats.TotalFiles++

		// Re-encrypt the file
		if err := r.reEncryptFile(ctx, path, recipients); err != nil {
			stats.FailedFiles++
			stats.Errors = append(stats.Errors, fmt.Sprintf("failed to re-encrypt %s: %v", path, err))
			return nil // Continue with other files
		}

		stats.SuccessfulFiles++
		return nil
	})
}

// reEncryptFile decrypts and re-encrypts a single file
func (r *ReEncryptor) reEncryptFile(ctx context.Context, path string, recipients []string) error {
	// Read encrypted file
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Decrypt
	plaintext, err := r.crypto.Decrypt(ctx, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	// Re-encrypt with new recipients
	newCiphertext, err := r.crypto.Encrypt(ctx, plaintext, recipients)
	if err != nil {
		// Zero out plaintext before returning
		age.ZeroBytes(plaintext)
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	// Zero out plaintext
	age.ZeroBytes(plaintext)

	// Write back
	if err := os.WriteFile(path, newCiphertext, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// ReEncryptFile re-encrypts a single file with new recipients
func (r *ReEncryptor) ReEncryptFile(ctx context.Context, path string, recipients []string) error {
	return r.reEncryptFile(ctx, path, recipients)
}

// GetAllAgeFiles returns all .age files in the store
func (r *ReEncryptor) GetAllAgeFiles() ([]string, error) {
	var files []string

	dirs := []string{
		filepath.Join(r.storePath, "credentials"),
		filepath.Join(r.storePath, "projects"),
	}

	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() && strings.HasSuffix(path, age.Ext) {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return files, nil
}

// RemoveRecipient removes a specific public key from the list
func RemoveRecipient(recipients []string, keyToRemove string) []string {
	var result []string
	for _, r := range recipients {
		if r != keyToRemove {
			result = append(result, r)
		}
	}
	return result
}

// FilterVerifiedRecipients returns only recipients that are not pending verification
func FilterVerifiedRecipients(recipients []string, pendingKeys map[string]bool) []string {
	var result []string
	for _, r := range recipients {
		if !pendingKeys[r] {
			result = append(result, r)
		}
	}
	return result
}
