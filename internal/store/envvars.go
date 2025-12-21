package store

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"passbook/internal/backend/crypto/age"
	"passbook/internal/models"
)

const (
	projectsDir = "projects"
)

// GetEnvFile returns environment variables for a project and stage
func (s *Store) GetEnvFile(ctx context.Context, project string, stage models.Stage) (*models.EnvFile, error) {
	if !stage.IsValid() {
		return nil, fmt.Errorf("%w: invalid stage", ErrInvalidInput)
	}

	path := fmt.Sprintf("%s/%s/%s.env%s", projectsDir, project, stage, age.Ext)

	data, err := s.storage.Get(ctx, path)
	if err != nil {
		return nil, ErrNotFound
	}

	plaintext, err := s.crypto.Decrypt(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt env file: %w", err)
	}

	var envFile models.EnvFile
	if err := yaml.Unmarshal(plaintext, &envFile); err != nil {
		return nil, fmt.Errorf("failed to parse env file: %w", err)
	}

	return &envFile, nil
}

// SetEnvVar sets an environment variable
func (s *Store) SetEnvVar(ctx context.Context, project string, stage models.Stage, key, value string, isSecret bool, updatedBy string) error {
	if !stage.IsValid() {
		return fmt.Errorf("%w: invalid stage", ErrInvalidInput)
	}
	if key == "" {
		return fmt.Errorf("%w: key is required", ErrInvalidInput)
	}

	// Get or create env file
	envFile, err := s.GetEnvFile(ctx, project, stage)
	if err != nil {
		envFile = &models.EnvFile{
			Project: project,
			Stage:   stage,
			Vars:    []models.EnvVar{},
		}
	}

	// Update variable
	envFile.Set(key, value, isSecret)
	envFile.UpdatedBy = updatedBy
	envFile.UpdatedAt = time.Now()

	return s.saveEnvFile(ctx, envFile)
}

// DeleteEnvVar removes an environment variable
func (s *Store) DeleteEnvVar(ctx context.Context, project string, stage models.Stage, key string, updatedBy string) error {
	envFile, err := s.GetEnvFile(ctx, project, stage)
	if err != nil {
		return err
	}

	if !envFile.Delete(key) {
		return ErrNotFound
	}

	envFile.UpdatedBy = updatedBy
	envFile.UpdatedAt = time.Now()

	return s.saveEnvFile(ctx, envFile)
}

// ImportEnvFile imports environment variables from parsed data
func (s *Store) ImportEnvFile(ctx context.Context, project string, stage models.Stage, vars []models.EnvVar, updatedBy string) error {
	// Get or create env file
	envFile, err := s.GetEnvFile(ctx, project, stage)
	if err != nil {
		envFile = &models.EnvFile{
			Project: project,
			Stage:   stage,
			Vars:    []models.EnvVar{},
		}
	}

	// Merge variables
	for _, v := range vars {
		envFile.Set(v.Key, v.Value, v.IsSecret)
	}

	envFile.UpdatedBy = updatedBy
	envFile.UpdatedAt = time.Now()

	return s.saveEnvFile(ctx, envFile)
}

// saveEnvFile encrypts and saves an env file
func (s *Store) saveEnvFile(ctx context.Context, envFile *models.EnvFile) error {
	var keys []string
	var err error

	// Check if env file has explicit permissions
	if envFile.Permissions != nil && envFile.Permissions.Count() > 0 && !envFile.Permissions.UseRoleBasedAccess {
		// Use explicit recipient list (only those who can read)
		keys = envFile.Permissions.GetReadRecipients()
	} else {
		// Fall back to stage-based recipients
		keys, err = s.getRecipientKeysForStage(envFile.Stage)
		if err != nil {
			return err
		}
	}

	if len(keys) == 0 {
		return fmt.Errorf("no recipients specified for env file")
	}

	// Serialize
	data, err := yaml.Marshal(envFile)
	if err != nil {
		return err
	}

	// Encrypt
	encrypted, err := s.encryptForRecipients(ctx, data, keys)
	if err != nil {
		return err
	}

	// Save
	path := envFile.FullPath()
	if err := s.storage.Set(ctx, path, encrypted); err != nil {
		return err
	}

	// Save recipients file (for reference)
	recipientsPath := envFile.RecipientsPath()
	recipientsData := s.formatRecipientsFile(keys)
	return s.storage.Set(ctx, recipientsPath, recipientsData)
}

// AddEnvRecipient adds a recipient to an env file
func (s *Store) AddEnvRecipient(ctx context.Context, project string, stage models.Stage, email, publicKey string, access models.AccessLevel) error {
	envFile, err := s.GetEnvFile(ctx, project, stage)
	if err != nil {
		return err
	}

	envFile.GetPermissions().AddRecipient(email, publicKey, access)
	envFile.UpdatedAt = time.Now()

	return s.saveEnvFile(ctx, envFile)
}

// RemoveEnvRecipient removes a recipient from an env file
func (s *Store) RemoveEnvRecipient(ctx context.Context, project string, stage models.Stage, email string) error {
	envFile, err := s.GetEnvFile(ctx, project, stage)
	if err != nil {
		return err
	}

	if !envFile.GetPermissions().RemoveRecipient(email) {
		return fmt.Errorf("recipient %s not found", email)
	}
	envFile.UpdatedAt = time.Now()

	return s.saveEnvFile(ctx, envFile)
}

// ListEnvRecipients lists recipients for an env file
func (s *Store) ListEnvRecipients(ctx context.Context, project string, stage models.Stage) ([]models.RecipientPermission, error) {
	envFile, err := s.GetEnvFile(ctx, project, stage)
	if err != nil {
		return nil, err
	}

	if envFile.Permissions == nil {
		return []models.RecipientPermission{}, nil
	}

	return envFile.Permissions.ListRecipients(), nil
}

// formatRecipientsFile formats recipient keys for a .recipients file
func (s *Store) formatRecipientsFile(keys []string) []byte {
	var lines []string
	lines = append(lines, "# Stage recipients")
	lines = append(lines, "# Users who can decrypt this environment")
	lines = append(lines, "")

	for _, key := range keys {
		lines = append(lines, key)
	}

	return []byte(strings.Join(lines, "\n") + "\n")
}

// ListEnvStages returns available stages for a project
func (s *Store) ListEnvStages(ctx context.Context, project string) ([]models.Stage, error) {
	prefix := filepath.Join(projectsDir, project)
	files, err := s.storage.List(ctx, prefix)
	if err != nil {
		return nil, err
	}

	stageMap := make(map[models.Stage]bool)
	for _, file := range files {
		base := filepath.Base(file)
		// Match pattern: {stage}.env.age
		if strings.HasSuffix(base, ".env"+age.Ext) {
			stageName := strings.TrimSuffix(base, ".env"+age.Ext)
			stage := models.Stage(stageName)
			if stage.IsValid() {
				stageMap[stage] = true
			}
		}
	}

	var stages []models.Stage
	for _, stage := range models.AllStages() {
		if stageMap[stage] {
			stages = append(stages, stage)
		}
	}

	return stages, nil
}
