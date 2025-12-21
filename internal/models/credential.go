package models

import (
	"fmt"
	"time"
)

// Credential stores website login information
type Credential struct {
	// Unique identifier (auto-generated)
	ID string `json:"id" yaml:"id"`

	// Website domain (e.g., "github.com", "aws.amazon.com")
	Website string `json:"website" yaml:"website"`

	// Account identifier/label (e.g., "team-account", "personal")
	Name string `json:"name" yaml:"name"`

	// Login username or email
	Username string `json:"username" yaml:"username"`

	// Password (stored encrypted)
	Password string `json:"password" yaml:"password"`

	// Optional URL (full login URL)
	URL string `json:"url,omitempty" yaml:"url,omitempty"`

	// Optional notes
	Notes string `json:"notes,omitempty" yaml:"notes,omitempty"`

	// Tags for organization
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty"`

	// Custom metadata key-value pairs
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Per-secret access control (who can read/write this credential)
	Permissions *SecretPermissions `json:"permissions,omitempty" yaml:"permissions,omitempty"`

	// Who created this credential
	CreatedBy string `json:"created_by" yaml:"created_by"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
}

// GetPermissions returns permissions, initializing if nil
func (c *Credential) GetPermissions() *SecretPermissions {
	if c.Permissions == nil {
		c.Permissions = NewSecretPermissions()
	}
	return c.Permissions
}

// CanUserRead checks if a user can read this credential
func (c *Credential) CanUserRead(email string) bool {
	if c.Permissions == nil || c.Permissions.UseRoleBasedAccess || c.Permissions.Count() == 0 {
		return true // Fall back to role-based access
	}
	return c.Permissions.CanRead(email)
}

// CanUserWrite checks if a user can write this credential
func (c *Credential) CanUserWrite(email string) bool {
	if c.Permissions == nil || c.Permissions.UseRoleBasedAccess || c.Permissions.Count() == 0 {
		return true // Fall back to role-based access
	}
	return c.Permissions.CanWrite(email)
}

// Path returns the storage path for this credential
// Example: "credentials/github.com/team-account"
func (c *Credential) Path() string {
	return fmt.Sprintf("credentials/%s/%s", c.Website, c.Name)
}

// FullPath returns the full storage path with extension
func (c *Credential) FullPath() string {
	return c.Path() + ".age"
}

// CredentialSummary is a lightweight version for listing
type CredentialSummary struct {
	ID        string    `json:"id"`
	Website   string    `json:"website"`
	Name      string    `json:"name"`
	Username  string    `json:"username"`
	Tags      []string  `json:"tags"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ToSummary converts a Credential to a CredentialSummary
func (c *Credential) ToSummary() CredentialSummary {
	return CredentialSummary{
		ID:        c.ID,
		Website:   c.Website,
		Name:      c.Name,
		Username:  c.Username,
		Tags:      c.Tags,
		UpdatedAt: c.UpdatedAt,
	}
}
