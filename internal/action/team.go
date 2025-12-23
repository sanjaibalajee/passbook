package action

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"passbook/internal/audit"
	"passbook/internal/auth"
	"passbook/internal/backend/crypto/age"
	"passbook/internal/models"
	reencrypt_pkg "passbook/internal/reencrypt"
	"passbook/internal/verification"
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
		// Enter existing key with verification
		pubKey, err = termio.Prompt("Enter their public key (age1...): ")
		if err != nil {
			return err
		}
		if pubKey == "" {
			return fmt.Errorf("public key is required")
		}
		if !age.ValidatePublicKey(pubKey) {
			return fmt.Errorf("invalid public key format (should start with 'age1')")
		}

		// Ask if they want to verify key ownership
		skipVerify := c.Bool("skip-verify")
		if !skipVerify {
			fmt.Println("\nKey ownership verification is recommended to ensure")
			fmt.Println("the user actually controls this private key.")
			fmt.Println()
			verify, err := termio.Confirm("Require key ownership verification?", true)
			if err != nil {
				return err
			}

			if verify {
				// Create verification challenge
				verifier := verification.NewVerifier(a.cfg.StorePath)
				pv, err := verifier.CreateChallenge(email, pubKey)
				if err != nil {
					return fmt.Errorf("failed to create verification challenge: %w", err)
				}

				fmt.Println("\n" + verification.GenerateVerificationInstructions(pv.EncryptedChallenge))
				fmt.Println()
				fmt.Println("The user must decrypt this challenge and provide the response.")
				fmt.Println("They can run: passbook verify-key --challenge <encrypted_challenge>")
				fmt.Println()

				// For now, mark as pending verification
				fmt.Println("User will be added as PENDING until they verify key ownership.")
				fmt.Println("Run 'passbook team verify EMAIL RESPONSE' to complete verification.")

				// Create user with pending status (no key in recipients yet)
				newUser := models.User{
					ID:        uuid.New().String(),
					Email:     email,
					Name:      email,
					PublicKey: pubKey, // Store key but don't add to recipients yet
					CreatedAt: time.Now(),
					Roles:     userRoles,
				}
				// Add a marker that this user is pending verification
				if newUser.Metadata == nil {
					newUser.Metadata = make(map[string]string)
				}
				newUser.Metadata["verification_pending"] = "true"

				userList.Users = append(userList.Users, newUser)

				if err := a.saveUsers(userList); err != nil {
					return fmt.Errorf("failed to save users: %w", err)
				}

				if err := a.GitCommitAndSync(fmt.Sprintf("Add pending team member: %s (awaiting verification)", email)); err != nil {
					fmt.Printf("Warning: %v\n", err)
				}

				fmt.Printf("\n✓ Added %s as pending (awaiting key verification)\n", email)
				return nil
			}
		}
		// Skip verification - add directly (existing behavior)
		fmt.Println("\nSkipping key verification - adding user directly.")

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
// Only includes verified users with public keys
func (a *Action) updateRecipientsFile(userList *models.UserList) error {
	recipientsPath := filepath.Join(a.cfg.StorePath, ".passbook-recipients")

	var content string
	content += "# Passbook Recipients - Team Members\n"
	content += "# Format: <age-public-key> # <email>\n\n"

	for _, user := range userList.Users {
		// Skip users without public keys
		if user.PublicKey == "" {
			continue
		}
		// Skip users pending verification
		if user.IsPendingVerification() {
			continue
		}
		content += fmt.Sprintf("%s # %s\n", user.PublicKey, user.Email)
	}

	return os.WriteFile(recipientsPath, []byte(content), 0600)
}

// ReEncryptAll re-encrypts all secrets with current recipients
func (a *Action) ReEncryptAll(c *cli.Context) error {
	// Check if current user is admin
	currentUser, err := a.getCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	if !currentUser.IsAdmin() {
		return fmt.Errorf("permission denied: only admins can re-encrypt secrets")
	}

	// Load users
	userList, err := a.loadUsers()
	if err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	// Build recipient list (only verified users)
	var recipients []string
	for _, u := range userList.Users {
		if u.PublicKey != "" && !u.IsPendingVerification() {
			recipients = append(recipients, u.PublicKey)
		}
	}

	if len(recipients) == 0 {
		return fmt.Errorf("no verified recipients found")
	}

	fmt.Printf("Re-encrypting secrets for %d recipients...\n", len(recipients))

	// Confirm
	force := c.Bool("force")
	if !force {
		confirm, err := termio.Confirm("This will re-encrypt all secrets. Continue?", false)
		if err != nil {
			return err
		}
		if !confirm {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	// Load crypto backend
	crypto, err := age.New(a.cfg.IdentityPath())
	if err != nil {
		return fmt.Errorf("failed to load crypto backend: %w", err)
	}

	// Re-encrypt
	reencryptor := reencrypt_pkg.NewReEncryptor(a.cfg.StorePath, crypto)
	stats, err := reencryptor.ReEncryptAll(context.Background(), recipients)
	if err != nil {
		return fmt.Errorf("re-encryption failed: %w", err)
	}

	fmt.Printf("\nRe-encryption complete:\n")
	fmt.Printf("  Total files: %d\n", stats.TotalFiles)
	fmt.Printf("  Successful:  %d\n", stats.SuccessfulFiles)
	fmt.Printf("  Failed:      %d\n", stats.FailedFiles)

	if len(stats.Errors) > 0 {
		fmt.Println("\nErrors:")
		for _, e := range stats.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}

	// Log audit event
	a.logAudit(audit.EventReEncrypt, "all",
		"total", fmt.Sprintf("%d", stats.TotalFiles),
		"successful", fmt.Sprintf("%d", stats.SuccessfulFiles),
		"failed", fmt.Sprintf("%d", stats.FailedFiles))

	// Git commit
	if stats.SuccessfulFiles > 0 {
		if err := a.GitCommitAndSync("Re-encrypt all secrets"); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
	}

	return nil
}

// TeamRevoke revokes a member's access
func (a *Action) TeamRevoke(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("usage: passbook team revoke EMAIL")
	}

	email := c.Args().First()
	force := c.Bool("force")
	reencryptSecrets := c.Bool("reencrypt")

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

	// Find user and get their public key
	var found bool
	var revokedKey string
	var newUsers []models.User
	for _, u := range userList.Users {
		if u.Email == email {
			found = true
			revokedKey = u.PublicKey
			continue // Skip this user
		}
		newUsers = append(newUsers, u)
	}

	if !found {
		return fmt.Errorf("user %s not found", email)
	}

	// Confirm
	if !force {
		msg := fmt.Sprintf("Revoke access for %s?", email)
		if reencryptSecrets {
			msg = fmt.Sprintf("Revoke access for %s and re-encrypt all secrets?", email)
		}
		confirm, err := termio.Confirm(msg, false)
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

	// Log audit event
	a.logAudit(audit.EventUserRemoved, email)

	fmt.Printf("✓ Revoked access for %s\n", email)

	// Re-encrypt if requested
	if reencryptSecrets && revokedKey != "" {
		fmt.Println("\nRe-encrypting all secrets without the revoked user's key...")

		// Get new recipient list (all remaining users)
		var newRecipients []string
		for _, u := range userList.Users {
			if u.PublicKey != "" && !u.IsPendingVerification() {
				newRecipients = append(newRecipients, u.PublicKey)
			}
		}

		// Load crypto backend
		crypto, err := age.New(a.cfg.IdentityPath())
		if err != nil {
			return fmt.Errorf("failed to load crypto backend: %w", err)
		}

		// Re-encrypt all secrets
		reencryptor := reencrypt_pkg.NewReEncryptor(a.cfg.StorePath, crypto)
		stats, err := reencryptor.ReEncryptAll(context.Background(), newRecipients)
		if err != nil {
			return fmt.Errorf("re-encryption failed: %w", err)
		}

		fmt.Printf("\nRe-encryption complete:\n")
		fmt.Printf("  Total files: %d\n", stats.TotalFiles)
		fmt.Printf("  Successful:  %d\n", stats.SuccessfulFiles)
		fmt.Printf("  Failed:      %d\n", stats.FailedFiles)

		if len(stats.Errors) > 0 {
			fmt.Println("\nErrors:")
			for _, e := range stats.Errors {
				fmt.Printf("  - %s\n", e)
			}
		}
	}

	// Git commit
	commitMsg := fmt.Sprintf("Revoke team member: %s", email)
	if reencryptSecrets {
		commitMsg = fmt.Sprintf("Revoke team member: %s (with re-encryption)", email)
	}
	if err := a.GitCommitAndSync(commitMsg); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	if !reencryptSecrets && revokedKey != "" {
		fmt.Println("\nWARNING: The revoked user can still decrypt secrets encrypted before this revocation.")
		fmt.Println("To remove their access to existing secrets, run:")
		fmt.Printf("  passbook team revoke %s --reencrypt\n", email)
		fmt.Println("\nOr re-encrypt all secrets manually:")
		fmt.Println("  passbook reencrypt --all")
	}

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

	// Log audit event
	a.logAudit(audit.EventRoleGranted, email, "role", string(role))

	fmt.Printf("✓ Granted %s role to %s\n", role, email)

	return nil
}

// TeamUngrant removes a role from a member
func (a *Action) TeamUngrant(c *cli.Context) error {
	if c.NArg() < 2 {
		return fmt.Errorf("usage: passbook team ungrant EMAIL ROLE")
	}

	email := c.Args().Get(0)
	roleStr := c.Args().Get(1)

	// Check if current user is admin
	currentUser, err := a.getCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	if !currentUser.IsAdmin() {
		return fmt.Errorf("permission denied: only admins can remove roles")
	}

	// Prevent removing own admin role
	if currentUser.Email == email && roleStr == "admin" {
		return fmt.Errorf("cannot remove your own admin role")
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
	var hadRole bool
	for i, u := range userList.Users {
		if u.Email == email {
			found = true
			// Remove the role
			newRoles := make([]models.Role, 0, len(u.Roles))
			for _, r := range u.Roles {
				if r == role {
					hadRole = true
					continue // Skip this role (remove it)
				}
				newRoles = append(newRoles, r)
			}

			if !hadRole {
				return fmt.Errorf("user %s does not have role %s", email, role)
			}

			// Ensure user has at least one role
			if len(newRoles) == 0 {
				return fmt.Errorf("cannot remove last role from user. Use 'team revoke' to remove the user entirely")
			}

			userList.Users[i].Roles = newRoles
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
	if err := a.GitCommitAndSync(fmt.Sprintf("Remove %s role from %s", role, email)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	// Log audit event
	a.logAudit(audit.EventRoleRevoked, email, "role", string(role))

	fmt.Printf("✓ Removed %s role from %s\n", role, email)

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

// TeamVerify verifies a pending member's key ownership
func (a *Action) TeamVerify(c *cli.Context) error {
	if c.NArg() < 2 {
		return fmt.Errorf("usage: passbook team verify EMAIL RESPONSE")
	}

	email := c.Args().Get(0)
	response := c.Args().Get(1)

	// Check if current user is admin
	currentUser, err := a.getCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	if !currentUser.IsAdmin() {
		return fmt.Errorf("permission denied: only admins can verify members")
	}

	// Load users
	userList, err := a.loadUsers()
	if err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	// Find the pending user
	var foundIdx int = -1
	for i, u := range userList.Users {
		if u.Email == email {
			foundIdx = i
			break
		}
	}

	if foundIdx == -1 {
		return fmt.Errorf("user %s not found", email)
	}

	user := &userList.Users[foundIdx]

	if !user.IsPendingVerification() {
		return fmt.Errorf("user %s is not pending verification", email)
	}

	// Verify the response
	verifier := verification.NewVerifier(a.cfg.StorePath)
	if err := verifier.VerifyResponse(email, response); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// Mark as verified
	user.SetVerified()

	// Save users
	if err := a.saveUsers(userList); err != nil {
		return fmt.Errorf("failed to save users: %w", err)
	}

	// Now add to recipients file
	if err := a.updateRecipientsFile(userList); err != nil {
		return fmt.Errorf("failed to update recipients: %w", err)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Verify team member: %s", email)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("✓ Successfully verified %s\n", email)
	fmt.Println("Their public key has been added to the recipients list.")
	fmt.Println("\nNote: They will be able to decrypt new secrets encrypted after this point.")
	fmt.Println("To give them access to existing secrets, you need to re-encrypt them.")

	return nil
}

// TeamPending lists pending verifications
func (a *Action) TeamPending(c *cli.Context) error {
	// Load users
	userList, err := a.loadUsers()
	if err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	fmt.Println("Pending Verifications")
	fmt.Println("====================")
	fmt.Println()

	var hasPending bool
	for _, user := range userList.Users {
		if user.IsPendingVerification() {
			hasPending = true
			fmt.Printf("Email: %s\n", user.Email)
			key := user.PublicKey
			if len(key) > 30 {
				key = key[:30] + "..."
			}
			fmt.Printf("  Public Key: %s\n", key)

			// Check if verification exists
			verifier := verification.NewVerifier(a.cfg.StorePath)
			pv, err := verifier.GetPendingVerification(user.Email)
			if err == nil {
				fmt.Printf("  Challenge expires: %s\n", pv.ExpiresAt.Format(time.RFC3339))
			} else {
				fmt.Printf("  Challenge: expired or not created\n")
			}
			fmt.Println()
		}
	}

	if !hasPending {
		fmt.Println("No pending verifications.")
	}

	return nil
}

// VerifyKey is the command new users run to prove key ownership
func (a *Action) VerifyKey(c *cli.Context) error {
	challengeFile := c.String("challenge-file")
	challenge := c.String("challenge")

	if challengeFile == "" && challenge == "" {
		return fmt.Errorf("usage: passbook verify-key --challenge-file FILE or --challenge BASE64_STRING")
	}

	var encryptedChallenge string
	if challengeFile != "" {
		data, err := os.ReadFile(challengeFile)
		if err != nil {
			return fmt.Errorf("failed to read challenge file: %w", err)
		}
		encryptedChallenge = string(data)
	} else {
		encryptedChallenge = challenge
	}

	// Decrypt the challenge using user's identity
	response, err := verification.DecryptChallenge(a.cfg.IdentityPath(), encryptedChallenge)
	if err != nil {
		return fmt.Errorf("failed to decrypt challenge: %w", err)
	}

	fmt.Println("Successfully decrypted the challenge!")
	fmt.Println()
	fmt.Println("Send this response to your admin:")
	fmt.Println()
	fmt.Println(response)
	fmt.Println()
	fmt.Println("They can complete verification by running:")
	fmt.Printf("  passbook team verify YOUR_EMAIL %s\n", response)

	return nil
}

// TeamJoin allows a new user to request to join the team using GitHub auth
func (a *Action) TeamJoin(c *cli.Context) error {
	fmt.Println("Join Team Request")
	fmt.Println("=================")
	fmt.Println()
	fmt.Println("This will verify your identity using GitHub and generate")
	fmt.Println("a request for an admin to add you to the team.")
	fmt.Println()

	// Check if user already has an identity
	if !a.cfg.HasIdentity() {
		fmt.Println("Generating your encryption keypair...")
		pubKey, err := age.GenerateIdentity(a.cfg.IdentityPath())
		if err != nil {
			return fmt.Errorf("failed to generate identity: %w", err)
		}
		a.cfg.Identity.PublicKey = pubKey
		fmt.Printf("Public Key: %s\n", pubKey)
		fmt.Println()
	}

	// Authenticate with GitHub
	fmt.Println("Authenticating with GitHub to verify your email...")
	fmt.Println()

	githubAuth := auth.NewGitHubAuth(a.cfg.ConfigDir, a.cfg.Org.AllowedDomain)
	session, err := githubAuth.Authenticate()
	if err != nil {
		switch err {
		case auth.ErrEmailNotVerified:
			return fmt.Errorf("your GitHub email is not verified. Please verify at github.com")
		case auth.ErrEmailDomainMismatch:
			return fmt.Errorf("no verified email matching @%s found in your GitHub account", a.cfg.Org.AllowedDomain)
		default:
			return fmt.Errorf("GitHub authentication failed: %w", err)
		}
	}

	// Update config with verified email
	a.cfg.Identity.Email = session.Email
	if err := a.cfg.Save(); err != nil {
		fmt.Printf("Warning: failed to save config: %v\n", err)
	}

	fmt.Println()
	fmt.Println("GitHub verification successful!")
	fmt.Println()
	fmt.Println("Your verified identity:")
	fmt.Printf("  Email:      %s\n", session.Email)
	fmt.Printf("  GitHub:     @%s\n", session.GitHubLogin)
	fmt.Printf("  Public Key: %s\n", a.cfg.Identity.PublicKey)
	fmt.Println()
	fmt.Println("Ask an admin to run:")
	fmt.Printf("  passbook team invite %s\n", session.Email)
	fmt.Println()
	fmt.Println("Then provide them your public key when prompted.")
	fmt.Println()
	fmt.Println("Alternatively, they can add you directly with:")
	fmt.Printf("  passbook team add-verified %s %s\n", session.Email, a.cfg.Identity.PublicKey)

	return nil
}

// TeamAddVerified adds a GitHub-verified user to the team (admin only)
// This is used when the new user has already authenticated via GitHub
func (a *Action) TeamAddVerified(c *cli.Context) error {
	if c.NArg() < 2 {
		return fmt.Errorf("usage: passbook team add-verified EMAIL PUBLIC_KEY [--role ROLE]")
	}

	email := c.Args().Get(0)
	publicKey := c.Args().Get(1)
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
		return fmt.Errorf("permission denied: only admins can add members")
	}

	// Validate email domain
	if !a.cfg.IsAllowedEmail(email) {
		return fmt.Errorf("email domain not allowed: must be @%s", a.cfg.Org.AllowedDomain)
	}

	// Validate public key
	if !age.ValidatePublicKey(publicKey) {
		return fmt.Errorf("invalid public key format")
	}

	// Validate roles
	var userRoles []models.Role
	for _, r := range roles {
		role := models.Role(r)
		if !role.IsValid() {
			return fmt.Errorf("invalid role: %s", r)
		}
		userRoles = append(userRoles, role)
	}

	// Load users
	userList, err := a.loadUsers()
	if err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	// Check if user already exists
	for _, u := range userList.Users {
		if u.Email == email {
			return fmt.Errorf("user %s already exists", email)
		}
	}

	// Create new user (verified via GitHub, no pending status)
	newUser := models.User{
		ID:        uuid.New().String(),
		Email:     email,
		Name:      email,
		PublicKey: publicKey,
		CreatedAt: time.Now(),
		Roles:     userRoles,
	}

	userList.Users = append(userList.Users, newUser)

	// Save users
	if err := a.saveUsers(userList); err != nil {
		return fmt.Errorf("failed to save users: %w", err)
	}

	// Update recipients file
	if err := a.updateRecipientsFile(userList); err != nil {
		return fmt.Errorf("failed to update recipients: %w", err)
	}

	// Log audit event
	a.logAudit(audit.EventUserAdded, email, "roles", fmt.Sprintf("%v", roles), "method", "github-verified")

	fmt.Printf("✓ Added %s to the team with roles: %v\n", email, roles)
	fmt.Println()

	// Ask if user wants to re-encrypt existing secrets
	fmt.Println("The new member can decrypt new secrets encrypted after this point.")
	fmt.Println("To give them access to existing secrets, they need to be re-encrypted.")
	fmt.Println()

	doReencrypt, err := termio.Confirm("Re-encrypt all secrets now?", true)
	if err != nil {
		fmt.Printf("Warning: failed to read input: %v\n", err)
		doReencrypt = false
	}

	if doReencrypt {
		fmt.Println()
		fmt.Println("Re-encrypting all secrets...")

		// Gather all recipients (verified users with public keys)
		var recipients []string
		for _, u := range userList.Users {
			if u.PublicKey != "" && !u.IsPendingVerification() {
				recipients = append(recipients, u.PublicKey)
			}
		}

		// Load crypto backend
		crypto, err := age.New(a.cfg.IdentityPath())
		if err != nil {
			return fmt.Errorf("failed to load crypto backend: %w", err)
		}

		reencryptor := reencrypt_pkg.NewReEncryptor(a.cfg.StorePath, crypto)
		stats, err := reencryptor.ReEncryptAll(context.Background(), recipients)
		if err != nil {
			return fmt.Errorf("re-encryption failed: %w", err)
		}

		fmt.Printf("✓ Re-encrypted %d files (%d successful)\n",
			stats.TotalFiles, stats.SuccessfulFiles)

		// Git commit with re-encryption
		if err := a.GitCommitAndSync(fmt.Sprintf("Add verified team member: %s (with re-encryption)", email)); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
	} else {
		// Git commit without re-encryption
		if err := a.GitCommitAndSync(fmt.Sprintf("Add verified team member: %s", email)); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
		fmt.Println()
		fmt.Println("You can re-encrypt later with: passbook reencrypt")
	}

	return nil
}
