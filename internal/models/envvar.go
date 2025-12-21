package models

import (
	"fmt"
	"strings"
	"time"
)

// EnvVar represents a single environment variable
type EnvVar struct {
	// Variable key (e.g., "DATABASE_URL")
	Key string `json:"key" yaml:"key"`

	// Variable value (stored encrypted)
	Value string `json:"value" yaml:"value"`

	// Optional description
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Is this a secret? (affects display behavior)
	IsSecret bool `json:"is_secret" yaml:"is_secret"`
}

// EnvFile represents all env vars for a project+stage
type EnvFile struct {
	// Project name
	Project string `json:"project" yaml:"project"`

	// Stage (dev/staging/prod)
	Stage Stage `json:"stage" yaml:"stage"`

	// Environment variables
	Vars []EnvVar `json:"vars" yaml:"vars"`

	// Per-secret access control (who can read/write this env file)
	// If nil or empty, falls back to stage-based role access
	Permissions *SecretPermissions `json:"permissions,omitempty" yaml:"permissions,omitempty"`

	// Metadata
	CreatedBy string    `json:"created_by" yaml:"created_by"`
	UpdatedBy string    `json:"updated_by" yaml:"updated_by"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
}

// GetPermissions returns permissions, initializing if nil
func (e *EnvFile) GetPermissions() *SecretPermissions {
	if e.Permissions == nil {
		e.Permissions = NewSecretPermissions()
	}
	return e.Permissions
}

// CanUserRead checks if a user can read this env file
func (e *EnvFile) CanUserRead(email string) bool {
	if e.Permissions == nil || e.Permissions.UseRoleBasedAccess || e.Permissions.Count() == 0 {
		return true // Fall back to stage-based role access
	}
	return e.Permissions.CanRead(email)
}

// CanUserWrite checks if a user can write this env file
func (e *EnvFile) CanUserWrite(email string) bool {
	if e.Permissions == nil || e.Permissions.UseRoleBasedAccess || e.Permissions.Count() == 0 {
		return true // Fall back to stage-based role access
	}
	return e.Permissions.CanWrite(email)
}

// Path returns the storage path for this env file
// Example: "projects/my-app/dev.env"
func (e *EnvFile) Path() string {
	return fmt.Sprintf("projects/%s/%s.env", e.Project, e.Stage)
}

// FullPath returns the full storage path with extension
func (e *EnvFile) FullPath() string {
	return e.Path() + ".age"
}

// RecipientsPath returns the path to the recipients file for this env
func (e *EnvFile) RecipientsPath() string {
	return e.Path() + ".recipients"
}

// Get returns a variable value by key
func (e *EnvFile) Get(key string) (string, bool) {
	for _, v := range e.Vars {
		if v.Key == key {
			return v.Value, true
		}
	}
	return "", false
}

// Set adds or updates a variable
func (e *EnvFile) Set(key, value string, isSecret bool) {
	for i, v := range e.Vars {
		if v.Key == key {
			e.Vars[i].Value = value
			e.Vars[i].IsSecret = isSecret
			return
		}
	}
	e.Vars = append(e.Vars, EnvVar{Key: key, Value: value, IsSecret: isSecret})
}

// Delete removes a variable
func (e *EnvFile) Delete(key string) bool {
	for i, v := range e.Vars {
		if v.Key == key {
			e.Vars = append(e.Vars[:i], e.Vars[i+1:]...)
			return true
		}
	}
	return false
}

// ToMap converts to a map for env injection
func (e *EnvFile) ToMap() map[string]string {
	m := make(map[string]string, len(e.Vars))
	for _, v := range e.Vars {
		m[v.Key] = v.Value
	}
	return m
}

// ToDotEnv converts to .env file format
func (e *EnvFile) ToDotEnv() string {
	var buf strings.Builder
	for _, v := range e.Vars {
		// Escape special characters in value
		value := strings.ReplaceAll(v.Value, "\\", "\\\\")
		value = strings.ReplaceAll(value, "\"", "\\\"")
		buf.WriteString(fmt.Sprintf("%s=\"%s\"\n", v.Key, value))
	}
	return buf.String()
}

// ToExport converts to shell export format
func (e *EnvFile) ToExport() string {
	var buf strings.Builder
	for _, v := range e.Vars {
		// Escape special characters in value
		value := strings.ReplaceAll(v.Value, "'", "'\"'\"'")
		buf.WriteString(fmt.Sprintf("export %s='%s'\n", v.Key, value))
	}
	return buf.String()
}

// ParseDotEnv parses a .env file format string
func ParseDotEnv(content string) []EnvVar {
	var vars []EnvVar
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}

		// Unescape
		value = strings.ReplaceAll(value, "\\\"", "\"")
		value = strings.ReplaceAll(value, "\\\\", "\\")

		vars = append(vars, EnvVar{
			Key:      key,
			Value:    value,
			IsSecret: true, // Default to secret
		})
	}

	return vars
}
