package models

// AccessLevel represents read or write access
type AccessLevel string

const (
	// AccessRead allows reading/decrypting the secret
	AccessRead AccessLevel = "read"

	// AccessWrite allows reading and modifying the secret
	AccessWrite AccessLevel = "write"
)

// IsValid checks if the access level is valid
func (a AccessLevel) IsValid() bool {
	return a == AccessRead || a == AccessWrite
}

// CanWrite checks if this access level allows writing
func (a AccessLevel) CanWrite() bool {
	return a == AccessWrite
}

// RecipientPermission defines access for a single recipient
type RecipientPermission struct {
	// Email of the recipient
	Email string `json:"email" yaml:"email"`

	// Public key of the recipient (age1...)
	PublicKey string `json:"public_key" yaml:"public_key"`

	// Access level (read or write)
	Access AccessLevel `json:"access" yaml:"access"`
}

// SecretPermissions manages per-secret access control
type SecretPermissions struct {
	// List of recipients with their access levels
	Recipients []RecipientPermission `json:"recipients" yaml:"recipients"`

	// If true, use default role-based access instead of explicit recipients
	UseRoleBasedAccess bool `json:"use_role_based_access,omitempty" yaml:"use_role_based_access,omitempty"`
}

// NewSecretPermissions creates empty permissions
func NewSecretPermissions() *SecretPermissions {
	return &SecretPermissions{
		Recipients: []RecipientPermission{},
	}
}

// AddRecipient adds a recipient with specified access
func (p *SecretPermissions) AddRecipient(email, publicKey string, access AccessLevel) {
	// Check if already exists
	for i, r := range p.Recipients {
		if r.Email == email || r.PublicKey == publicKey {
			// Update existing
			p.Recipients[i].Access = access
			return
		}
	}
	// Add new
	p.Recipients = append(p.Recipients, RecipientPermission{
		Email:     email,
		PublicKey: publicKey,
		Access:    access,
	})
}

// RemoveRecipient removes a recipient
func (p *SecretPermissions) RemoveRecipient(email string) bool {
	for i, r := range p.Recipients {
		if r.Email == email {
			p.Recipients = append(p.Recipients[:i], p.Recipients[i+1:]...)
			return true
		}
	}
	return false
}

// GetAccess returns the access level for a recipient
func (p *SecretPermissions) GetAccess(email string) (AccessLevel, bool) {
	for _, r := range p.Recipients {
		if r.Email == email {
			return r.Access, true
		}
	}
	return "", false
}

// GetAccessByKey returns the access level for a public key
func (p *SecretPermissions) GetAccessByKey(publicKey string) (AccessLevel, bool) {
	for _, r := range p.Recipients {
		if r.PublicKey == publicKey {
			return r.Access, true
		}
	}
	return "", false
}

// CanRead checks if a recipient can read
func (p *SecretPermissions) CanRead(email string) bool {
	access, found := p.GetAccess(email)
	return found && (access == AccessRead || access == AccessWrite)
}

// CanWrite checks if a recipient can write
func (p *SecretPermissions) CanWrite(email string) bool {
	access, found := p.GetAccess(email)
	return found && access == AccessWrite
}

// GetReadRecipients returns public keys of all recipients who can read
func (p *SecretPermissions) GetReadRecipients() []string {
	var keys []string
	for _, r := range p.Recipients {
		// Both read and write can read
		keys = append(keys, r.PublicKey)
	}
	return keys
}

// GetWriteRecipients returns public keys of recipients who can write
func (p *SecretPermissions) GetWriteRecipients() []string {
	var keys []string
	for _, r := range p.Recipients {
		if r.Access == AccessWrite {
			keys = append(keys, r.PublicKey)
		}
	}
	return keys
}

// ListRecipients returns all recipients with their access
func (p *SecretPermissions) ListRecipients() []RecipientPermission {
	result := make([]RecipientPermission, len(p.Recipients))
	copy(result, p.Recipients)
	return result
}

// Count returns the number of recipients
func (p *SecretPermissions) Count() int {
	return len(p.Recipients)
}

// HasRecipient checks if a recipient exists
func (p *SecretPermissions) HasRecipient(email string) bool {
	_, found := p.GetAccess(email)
	return found
}

// Clone creates a copy of the permissions
func (p *SecretPermissions) Clone() *SecretPermissions {
	clone := &SecretPermissions{
		Recipients:         make([]RecipientPermission, len(p.Recipients)),
		UseRoleBasedAccess: p.UseRoleBasedAccess,
	}
	copy(clone.Recipients, p.Recipients)
	return clone
}
