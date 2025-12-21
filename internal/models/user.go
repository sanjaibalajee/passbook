package models

import "time"

// User represents a team member
type User struct {
	// Unique identifier (UUID)
	ID string `json:"id" yaml:"id"`

	// Email address (must match org's allowed domain)
	Email string `json:"email" yaml:"email"`

	// Display name
	Name string `json:"name" yaml:"name"`

	// Age public key (age1...)
	PublicKey string `json:"public_key" yaml:"public_key"`

	// When user joined
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`

	// Last login timestamp
	LastLoginAt time.Time `json:"last_login_at" yaml:"last_login_at"`

	// User's assigned roles
	Roles []Role `json:"roles" yaml:"roles"`
}

// CanAccessStage checks if user can access a specific stage
func (u *User) CanAccessStage(stage Stage) bool {
	for _, role := range u.Roles {
		if role.CanAccessStage(stage) {
			return true
		}
	}
	return false
}

// HasRole checks if user has a specific role
func (u *User) HasRole(role Role) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// IsAdmin checks if user has admin role
func (u *User) IsAdmin() bool {
	return u.HasRole(RoleAdmin)
}

// CanManageTeam checks if user can manage team members
func (u *User) CanManageTeam() bool {
	for _, role := range u.Roles {
		if role.CanManageTeam() {
			return true
		}
	}
	return false
}

// CanWriteCredentials checks if user can modify credentials
func (u *User) CanWriteCredentials() bool {
	for _, role := range u.Roles {
		if role.CanWriteCredentials() {
			return true
		}
	}
	return false
}

// UserList is a list of users for serialization
type UserList struct {
	Users []User `json:"users" yaml:"users"`
}
