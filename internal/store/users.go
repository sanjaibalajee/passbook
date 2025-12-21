package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"passbook/internal/models"
	"passbook/internal/recipients"
)

const (
	usersFile = ".passbook-users.age"
)

// UserList wraps users for serialization
type UserList struct {
	Users []models.User `yaml:"users"`
}

// ListUsers returns all users
func (s *Store) ListUsers() ([]models.User, error) {
	ctx := context.Background()

	// Load encrypted users file
	data, err := s.storage.Get(ctx, usersFile)
	if err != nil {
		// Return empty list if file doesn't exist
		return []models.User{}, nil
	}

	// Decrypt
	plaintext, err := s.crypto.Decrypt(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt users: %w", err)
	}

	// Parse
	var userList UserList
	if err := yaml.Unmarshal(plaintext, &userList); err != nil {
		return nil, fmt.Errorf("failed to parse users: %w", err)
	}

	return userList.Users, nil
}

// GetUser returns a user by email
func (s *Store) GetUser(email string) (*models.User, error) {
	users, err := s.ListUsers()
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		if strings.EqualFold(user.Email, email) {
			return &user, nil
		}
	}

	return nil, ErrNotFound
}

// GetUserByPublicKey returns a user by public key
func (s *Store) GetUserByPublicKey(publicKey string) (*models.User, error) {
	users, err := s.ListUsers()
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		if user.PublicKey == publicKey {
			return &user, nil
		}
	}

	return nil, ErrNotFound
}

// CreateUser creates a new user
func (s *Store) CreateUser(ctx context.Context, email, name, publicKey string, roles []models.Role) (*models.User, error) {
	// Validate email domain
	if !s.cfg.IsAllowedEmail(email) {
		return nil, fmt.Errorf("%w: email domain not allowed", ErrInvalidInput)
	}

	// Check if user exists
	if _, err := s.GetUser(email); err == nil {
		return nil, ErrAlreadyExists
	}

	// Validate roles
	if len(roles) == 0 {
		roles = []models.Role{models.RoleDev}
	}
	for _, role := range roles {
		if !role.IsValid() {
			return nil, fmt.Errorf("%w: invalid role %s", ErrInvalidInput, role)
		}
	}

	// Create user
	user := models.User{
		ID:        uuid.New().String(),
		Email:     email,
		Name:      name,
		PublicKey: publicKey,
		Roles:     roles,
		CreatedAt: time.Now(),
	}

	// Add to users list
	users, err := s.ListUsers()
	if err != nil {
		return nil, err
	}
	users = append(users, user)

	// Save users
	if err := s.saveUsers(ctx, users); err != nil {
		return nil, err
	}

	// Add to recipients file
	recps, err := s.GetRecipients(ctx)
	if err != nil {
		recps = recipients.New()
	}
	recps.Add(publicKey, email)
	if err := s.SaveRecipients(ctx, recps); err != nil {
		return nil, err
	}

	return &user, nil
}

// UpdateUser updates a user
func (s *Store) UpdateUser(ctx context.Context, email string, updateFn func(*models.User)) error {
	users, err := s.ListUsers()
	if err != nil {
		return err
	}

	found := false
	for i := range users {
		if strings.EqualFold(users[i].Email, email) {
			updateFn(&users[i])
			found = true
			break
		}
	}

	if !found {
		return ErrNotFound
	}

	return s.saveUsers(ctx, users)
}

// DeleteUser removes a user
func (s *Store) DeleteUser(ctx context.Context, email string) error {
	users, err := s.ListUsers()
	if err != nil {
		return err
	}

	var publicKey string
	newUsers := make([]models.User, 0, len(users))
	for _, user := range users {
		if strings.EqualFold(user.Email, email) {
			publicKey = user.PublicKey
			continue
		}
		newUsers = append(newUsers, user)
	}

	if len(newUsers) == len(users) {
		return ErrNotFound
	}

	// Save users
	if err := s.saveUsers(ctx, newUsers); err != nil {
		return err
	}

	// Remove from recipients
	recps, err := s.GetRecipients(ctx)
	if err == nil && publicKey != "" {
		recps.Remove(publicKey)
		if err := s.SaveRecipients(ctx, recps); err != nil {
			return err
		}
	}

	return nil
}

// GrantRole grants a role to a user
func (s *Store) GrantRole(ctx context.Context, email string, role models.Role) error {
	if !role.IsValid() {
		return fmt.Errorf("%w: invalid role %s", ErrInvalidInput, role)
	}

	return s.UpdateUser(ctx, email, func(user *models.User) {
		// Check if already has role
		for _, r := range user.Roles {
			if r == role {
				return
			}
		}
		user.Roles = append(user.Roles, role)
	})
}

// RevokeRole revokes a role from a user
func (s *Store) RevokeRole(ctx context.Context, email string, role models.Role) error {
	return s.UpdateUser(ctx, email, func(user *models.User) {
		newRoles := make([]models.Role, 0, len(user.Roles))
		for _, r := range user.Roles {
			if r != role {
				newRoles = append(newRoles, r)
			}
		}
		user.Roles = newRoles
	})
}

// saveUsers saves the users file
func (s *Store) saveUsers(ctx context.Context, users []models.User) error {
	// Get all recipient keys (everyone can read user list)
	keys, err := s.getAllRecipientKeys()
	if err != nil {
		return err
	}

	// Add current user's key if not in list
	myKey := s.crypto.PublicKey()
	if myKey != "" {
		found := false
		for _, k := range keys {
			if k == myKey {
				found = true
				break
			}
		}
		if !found {
			keys = append(keys, myKey)
		}
	}

	// Serialize
	userList := UserList{Users: users}
	data, err := yaml.Marshal(userList)
	if err != nil {
		return err
	}

	// Encrypt
	encrypted, err := s.encryptForRecipients(ctx, data, keys)
	if err != nil {
		return err
	}

	// Save
	return s.storage.Set(ctx, usersFile, encrypted)
}
