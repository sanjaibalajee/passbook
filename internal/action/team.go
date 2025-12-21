package action

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"passbook/internal/backend/crypto/age"
	"passbook/internal/models"
	"passbook/pkg/termio"
)

// loadUsers loads the users file
func (a *Action) loadUsers() (*models.UserList, error) {
	usersPath := filepath.Join(a.cfg.StorePath, ".passbook-users")
	data, err := os.ReadFile(usersPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &models.UserList{Users: []models.User{}}, nil
		}
		return nil, err
	}

	var userList models.UserList
	if err := yaml.Unmarshal(data, &userList); err != nil {
		return nil, err
	}

	return &userList, nil
}

// saveUsers saves the users file
func (a *Action) saveUsers(userList *models.UserList) error {
	usersPath := filepath.Join(a.cfg.StorePath, ".passbook-users")
	data, err := yaml.Marshal(userList)
	if err != nil {
		return err
	}
	return os.WriteFile(usersPath, data, 0600)
}

// getCurrentUser finds the current user by public key
func (a *Action) getCurrentUser() (*models.User, error) {
	userList, err := a.loadUsers()
	if err != nil {
		return nil, err
	}

	for _, u := range userList.Users {
		if u.PublicKey == a.cfg.Identity.PublicKey {
			return &u, nil
		}
	}

	return nil, fmt.Errorf("current user not found in team")
}

// TeamList lists team members
func (a *Action) TeamList(c *cli.Context) error {
	userList, err := a.loadUsers()
	if err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	fmt.Println("Team Members")
	fmt.Println("============")
	fmt.Println()

	if len(userList.Users) == 0 {
		fmt.Println("No team members found.")
		return nil
	}

	fmt.Printf("%-30s %-20s %s\n", "EMAIL", "ROLES", "PUBLIC KEY")
	fmt.Printf("%-30s %-20s %s\n", "-----", "-----", "----------")

	for _, user := range userList.Users {
		// Format roles
		roles := ""
		for i, r := range user.Roles {
			if i > 0 {
				roles += ", "
			}
			roles += string(r)
		}

		// Truncate public key
		key := user.PublicKey
		if len(key) > 20 {
			key = key[:20] + "..."
		}

		// Mark current user
		email := user.Email
		if user.PublicKey == a.cfg.Identity.PublicKey {
			email += " (you)"
		}

		fmt.Printf("%-30s %-20s %s\n", email, roles, key)
	}

	return nil
}

// TeamInvite invites a new member
func (a *Action) TeamInvite(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("usage: passbook team invite EMAIL [--role ROLE]")
	}

	email := c.Args().First()
	roles := c.StringSlice("role")

	if len(roles) == 0 {
		roles = []string{"dev"}
	}

	// Check if current user is admin
	currentUser, err := a.getCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	if !currentUser.IsAdmin() {
		return fmt.Errorf("permission denied: only admins can invite members")
	}

	// Validate email domain
	if !a.cfg.IsAllowedEmail(email) {
		return fmt.Errorf("email domain not allowed: must be @%s", a.cfg.Org.AllowedDomain)
	}

	// Validate roles
	var userRoles []models.Role
	for _, r := range roles {
		role := models.Role(r)
		if !role.IsValid() {
			return fmt.Errorf("invalid role: %s (valid: dev, staging-access, prod-access, admin)", r)
		}
		userRoles = append(userRoles, role)
	}

	// Load users
	userList, err := a.loadUsers()
	if err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	// Check if user already exists
	for i, u := range userList.Users {
		if u.Email == email {
			// User exists - update their roles
			fmt.Printf("User %s already exists.\n", email)

			// Merge roles (add new ones, don't remove existing)
			existingRoles := make(map[models.Role]bool)
			for _, r := range u.Roles {
				existingRoles[r] = true
			}
			for _, r := range userRoles {
				if !existingRoles[r] {
					userList.Users[i].Roles = append(userList.Users[i].Roles, r)
				}
			}

			// Check if user has no public key - offer to add one
			if u.PublicKey == "" {
				fmt.Println("This user has no public key set.")
				fmt.Println()
				fmt.Println("How should we set up their encryption key?")
				fmt.Println("  1. Generate a new key for them")
				fmt.Println("  2. Enter their existing public key")
				fmt.Println("  3. Skip (leave as pending)")
				fmt.Println()

				choice, err := termio.Prompt("Choose [1/2/3]: ")
				if err != nil {
					return err
				}

				switch choice {
				case "1":
					keyDir := filepath.Join(a.cfg.StorePath, ".pending-keys")
					if err := os.MkdirAll(keyDir, 0700); err != nil {
						return fmt.Errorf("failed to create key directory: %w", err)
					}
					privateKeyPath := filepath.Join(keyDir, email+".key")
					pubKey, err := age.GenerateIdentity(privateKeyPath)
					if err != nil {
						return fmt.Errorf("failed to generate key: %w", err)
					}
					userList.Users[i].PublicKey = pubKey
					fmt.Printf("\n✓ Generated key pair\n")
					fmt.Printf("  Private key: %s\n", privateKeyPath)
					fmt.Printf("  Public key: %s\n", pubKey)
				case "2":
					pubKey, err := termio.Prompt("Enter their public key (age1...): ")
					if err != nil {
						return err
					}
					if pubKey == "" || len(pubKey) < 10 || pubKey[:4] != "age1" {
						return fmt.Errorf("invalid public key format")
					}
					userList.Users[i].PublicKey = pubKey
				}
			}

			// Save users
			if err := a.saveUsers(userList); err != nil {
				return fmt.Errorf("failed to save users: %w", err)
			}

			// Update recipients file if they now have a key
			if userList.Users[i].PublicKey != "" {
				if err := a.updateRecipientsFile(userList); err != nil {
					return fmt.Errorf("failed to update recipients: %w", err)
				}
			}

			// Git commit
			if err := a.GitCommitAndSync(fmt.Sprintf("Update user: %s", email)); err != nil {
				fmt.Printf("Warning: %v\n", err)
			}

			fmt.Printf("✓ Updated %s with roles: %v\n", email, userList.Users[i].Roles)
			return nil
		}
	}

	fmt.Printf("Inviting: %s\n", email)
	fmt.Printf("Roles: %v\n", roles)
	fmt.Println()

	// Ask how to handle the key
	fmt.Println("How should we set up their encryption key?")
	fmt.Println("  1. Generate a new key for them (they'll need to import it)")
	fmt.Println("  2. Enter their existing public key")
	fmt.Println("  3. Create as pending (they'll generate key when they clone)")
	fmt.Println()

	choice, err := termio.Prompt("Choose [1/2/3]: ")
	if err != nil {
		return err
	}

	var pubKey string
	var privateKeyPath string

	switch choice {
	case "1":
		// Generate new key
		keyDir := filepath.Join(a.cfg.StorePath, ".pending-keys")
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			return fmt.Errorf("failed to create key directory: %w", err)
		}

		privateKeyPath = filepath.Join(keyDir, email+".key")
		pubKey, err = age.GenerateIdentity(privateKeyPath)
		if err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}

		fmt.Printf("\n✓ Generated key pair for %s\n", email)
		fmt.Printf("  Private key saved to: %s\n", privateKeyPath)
		fmt.Printf("  Public key: %s\n", pubKey)
		fmt.Println("\n  Send them the private key file securely!")
		fmt.Println("  They should save it as: ~/.config/passbook/identity")

	case "2":
		// Enter existing key
		pubKey, err = termio.Prompt("Enter their public key (age1...): ")
		if err != nil {
			return err
		}
		if pubKey == "" {
			return fmt.Errorf("public key is required")
		}
		if len(pubKey) < 10 || pubKey[:4] != "age1" {
			return fmt.Errorf("invalid public key format (should start with 'age1')")
		}

	case "3", "":
		// Create as pending - no key yet
		fmt.Println("\nCreating as pending user (no key yet).")
		fmt.Println("They will generate their key when they run 'passbook clone'.")
		pubKey = "" // Empty key means pending

	default:
		return fmt.Errorf("invalid choice: %s", choice)
	}

	// Create new user
	newUser := models.User{
		ID:        uuid.New().String(),
		Email:     email,
		Name:      email, // Use email as name for now
		PublicKey: pubKey,
		CreatedAt: time.Now(),
		Roles:     userRoles,
	}

	userList.Users = append(userList.Users, newUser)

	// Save users
	if err := a.saveUsers(userList); err != nil {
		return fmt.Errorf("failed to save users: %w", err)
	}

	// Update recipients file (only if they have a key)
	if pubKey != "" {
		if err := a.updateRecipientsFile(userList); err != nil {
			return fmt.Errorf("failed to update recipients: %w", err)
		}
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Add team member: %s", email)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("\n✓ Invited %s with roles: %v\n", email, roles)

	if pubKey == "" {
		fmt.Println("\nNext steps for the new user:")
		fmt.Println("  1. Run: passbook clone <repo-url>")
		fmt.Println("  2. Their key will be generated automatically")
		fmt.Println("  3. An admin will need to re-sync to add their key to secrets")
	} else if privateKeyPath != "" {
		fmt.Println("\nNext steps:")
		fmt.Println("  1. Send them the private key file securely")
		fmt.Println("  2. They should run: passbook clone <repo-url>")
		fmt.Println("  3. When prompted, import the key file")
	}

	return nil
}

// updateRecipientsFile updates .passbook-recipients from users
func (a *Action) updateRecipientsFile(userList *models.UserList) error {
	recipientsPath := filepath.Join(a.cfg.StorePath, ".passbook-recipients")

	var content string
	content += "# Passbook Recipients - Team Members\n"
	content += "# Format: <age-public-key> # <email>\n\n"

	for _, user := range userList.Users {
		content += fmt.Sprintf("%s # %s\n", user.PublicKey, user.Email)
	}

	return os.WriteFile(recipientsPath, []byte(content), 0600)
}

// TeamRevoke revokes a member's access
func (a *Action) TeamRevoke(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("usage: passbook team revoke EMAIL")
	}

	email := c.Args().First()
	force := c.Bool("force")

	// Check if current user is admin
	currentUser, err := a.getCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	if !currentUser.IsAdmin() {
		return fmt.Errorf("permission denied: only admins can revoke access")
	}

	// Can't revoke yourself
	if currentUser.Email == email {
		return fmt.Errorf("cannot revoke your own access")
	}

	// Load users
	userList, err := a.loadUsers()
	if err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	// Find user
	var found bool
	var newUsers []models.User
	for _, u := range userList.Users {
		if u.Email == email {
			found = true
			continue // Skip this user
		}
		newUsers = append(newUsers, u)
	}

	if !found {
		return fmt.Errorf("user %s not found", email)
	}

	// Confirm
	if !force {
		confirm, err := termio.Confirm(fmt.Sprintf("Revoke access for %s?", email), false)
		if err != nil {
			return err
		}
		if !confirm {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	userList.Users = newUsers

	// Save users
	if err := a.saveUsers(userList); err != nil {
		return fmt.Errorf("failed to save users: %w", err)
	}

	// Update recipients file
	if err := a.updateRecipientsFile(userList); err != nil {
		return fmt.Errorf("failed to update recipients: %w", err)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Revoke team member: %s", email)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("✓ Revoked access for %s\n", email)
	fmt.Println("\nIMPORTANT: This user may still have copies of secrets they previously accessed.")
	fmt.Println("Consider rotating any sensitive credentials they had access to.")

	return nil
}

// TeamGrant grants a role to a member
func (a *Action) TeamGrant(c *cli.Context) error {
	if c.NArg() < 2 {
		return fmt.Errorf("usage: passbook team grant EMAIL ROLE")
	}

	email := c.Args().Get(0)
	roleStr := c.Args().Get(1)

	// Check if current user is admin
	currentUser, err := a.getCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	if !currentUser.IsAdmin() {
		return fmt.Errorf("permission denied: only admins can grant roles")
	}

	// Validate role
	role := models.Role(roleStr)
	if !role.IsValid() {
		return fmt.Errorf("invalid role: %s (valid: dev, staging-access, prod-access, admin)", roleStr)
	}

	// Load users
	userList, err := a.loadUsers()
	if err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	// Find and update user
	var found bool
	for i, u := range userList.Users {
		if u.Email == email {
			found = true
			// Check if already has role
			for _, r := range u.Roles {
				if r == role {
					return fmt.Errorf("user %s already has role %s", email, role)
				}
			}
			userList.Users[i].Roles = append(userList.Users[i].Roles, role)
			break
		}
	}

	if !found {
		return fmt.Errorf("user %s not found", email)
	}

	// Save users
	if err := a.saveUsers(userList); err != nil {
		return fmt.Errorf("failed to save users: %w", err)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Grant %s role to %s", role, email)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("✓ Granted %s role to %s\n", role, email)

	return nil
}

// TeamRoles shows a member's roles
func (a *Action) TeamRoles(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("usage: passbook team roles EMAIL")
	}

	email := c.Args().First()

	// Load users
	userList, err := a.loadUsers()
	if err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	// Find user
	for _, u := range userList.Users {
		if u.Email == email {
			fmt.Printf("Roles for %s:\n", email)
			fmt.Println("-------------")
			for _, r := range u.Roles {
				desc := getRoleDescription(r)
				fmt.Printf("  - %s: %s\n", r, desc)
			}
			return nil
		}
	}

	return fmt.Errorf("user %s not found", email)
}

// getRoleDescription returns a description for a role
func getRoleDescription(role models.Role) string {
	switch role {
	case models.RoleDev:
		return "Access to dev environment only"
	case models.RoleStagingAccess:
		return "Access to dev + staging environments"
	case models.RoleProdAccess:
		return "Access to all environments + write credentials"
	case models.RoleAdmin:
		return "Full access + team management"
	default:
		return "Unknown role"
	}
}
