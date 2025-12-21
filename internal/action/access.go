package action

import (
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"

	"passbook/internal/models"
)

// CredAccessList lists who has access to a credential
func (a *Action) CredAccessList(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("usage: passbook cred access list WEBSITE/NAME")
	}

	path := c.Args().First()
	website, name, err := parseCredentialPath(path)
	if err != nil {
		return err
	}

	// Load credential
	cred, err := a.loadCredential(c.Context, website, name)
	if err != nil {
		return fmt.Errorf("failed to load credential: %w", err)
	}

	fmt.Printf("Access for credential: %s/%s\n", website, name)
	fmt.Println("========================================")
	fmt.Println()

	// Check if using per-secret permissions
	if cred.Permissions == nil || cred.Permissions.UseRoleBasedAccess || cred.Permissions.Count() == 0 {
		fmt.Println("Using role-based access (all team members can access)")
		fmt.Println()

		// List all team members
		userList, err := a.loadUsers()
		if err != nil {
			return fmt.Errorf("failed to load users: %w", err)
		}

		fmt.Printf("%-35s %-10s\n", "EMAIL", "ACCESS")
		fmt.Printf("%-35s %-10s\n", "-----", "------")

		for _, user := range userList.Users {
			// Check if user can write credentials
			access := "read"
			for _, role := range user.Roles {
				if role.CanWriteCredentials() {
					access = "write"
					break
				}
			}

			email := user.Email
			if user.PublicKey == a.cfg.Identity.PublicKey {
				email += " (you)"
			}
			fmt.Printf("%-35s %-10s\n", email, access)
		}
	} else {
		fmt.Println("Using per-secret access control")
		fmt.Println()

		fmt.Printf("%-35s %-10s\n", "EMAIL", "ACCESS")
		fmt.Printf("%-35s %-10s\n", "-----", "------")

		for _, perm := range cred.Permissions.Recipients {
			fmt.Printf("%-35s %-10s\n", perm.Email, perm.Access)
		}
	}

	return nil
}

// CredAccessGrant grants access to a credential
func (a *Action) CredAccessGrant(c *cli.Context) error {
	if c.NArg() < 2 {
		return fmt.Errorf("usage: passbook cred access grant WEBSITE/NAME EMAIL [--level read|write]")
	}

	path := c.Args().Get(0)
	email := c.Args().Get(1)
	level := c.String("level")

	website, name, err := parseCredentialPath(path)
	if err != nil {
		return err
	}

	// Validate access level
	access := models.AccessLevel(level)
	if !access.IsValid() {
		return fmt.Errorf("invalid access level: %s (use 'read' or 'write')", level)
	}

	// Check permission - must have write access to grant access
	currentUser, err := a.getCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	canWrite := false
	for _, role := range currentUser.Roles {
		if role.CanWriteCredentials() {
			canWrite = true
			break
		}
	}
	if !canWrite {
		return fmt.Errorf("permission denied: you need write access to grant access")
	}

	// Find the target user
	userList, err := a.loadUsers()
	if err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	var targetUser *models.User
	for _, u := range userList.Users {
		if u.Email == email {
			targetUser = &u
			break
		}
	}
	if targetUser == nil {
		return fmt.Errorf("user not found: %s", email)
	}

	if targetUser.PublicKey == "" {
		return fmt.Errorf("user %s has no public key", email)
	}

	// Load credential
	cred, err := a.loadCredential(c.Context, website, name)
	if err != nil {
		return fmt.Errorf("failed to load credential: %w", err)
	}

	// Initialize permissions if needed
	if cred.Permissions == nil {
		cred.Permissions = models.NewSecretPermissions()
	}
	cred.Permissions.UseRoleBasedAccess = false

	// Grant access
	cred.Permissions.AddRecipient(email, targetUser.PublicKey, access)

	// Make sure current user has access too
	if !cred.Permissions.HasRecipient(currentUser.Email) {
		cred.Permissions.AddRecipient(currentUser.Email, currentUser.PublicKey, models.AccessWrite)
	}

	// Save credential
	if err := a.saveCredentialWithPermissions(c.Context, cred); err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Grant %s access to %s for %s/%s", access, email, website, name)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("✓ Granted %s access to %s for %s/%s\n", access, email, website, name)

	return nil
}

// CredAccessRevoke revokes access from a credential
func (a *Action) CredAccessRevoke(c *cli.Context) error {
	if c.NArg() < 2 {
		return fmt.Errorf("usage: passbook cred access revoke WEBSITE/NAME EMAIL")
	}

	path := c.Args().Get(0)
	email := c.Args().Get(1)

	website, name, err := parseCredentialPath(path)
	if err != nil {
		return err
	}

	// Check permission
	currentUser, err := a.getCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	canWrite := false
	for _, role := range currentUser.Roles {
		if role.CanWriteCredentials() {
			canWrite = true
			break
		}
	}
	if !canWrite {
		return fmt.Errorf("permission denied: you need write access to revoke access")
	}

	// Can't revoke your own access
	if email == currentUser.Email {
		return fmt.Errorf("cannot revoke your own access")
	}

	// Load credential
	cred, err := a.loadCredential(c.Context, website, name)
	if err != nil {
		return fmt.Errorf("failed to load credential: %w", err)
	}

	// Check if using per-secret permissions
	if cred.Permissions == nil || cred.Permissions.UseRoleBasedAccess {
		return fmt.Errorf("credential is using role-based access; grant specific access first to switch to per-secret access")
	}

	// Revoke access
	if !cred.Permissions.RemoveRecipient(email) {
		return fmt.Errorf("user %s does not have explicit access", email)
	}

	// Save credential
	if err := a.saveCredentialWithPermissions(c.Context, cred); err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Revoke access from %s for %s/%s", email, website, name)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("✓ Revoked access from %s for %s/%s\n", email, website, name)

	return nil
}

// EnvAccessList lists who has access to an environment
func (a *Action) EnvAccessList(c *cli.Context) error {
	if c.NArg() < 2 {
		return fmt.Errorf("usage: passbook env access list PROJECT STAGE")
	}

	project := c.Args().Get(0)
	stage := models.Stage(c.Args().Get(1))

	if !stage.IsValid() {
		return fmt.Errorf("invalid stage: %s (use dev, staging, or prod)", stage)
	}

	fmt.Printf("Access for environment: %s/%s\n", project, stage)
	fmt.Println("========================================")
	fmt.Println()

	// Try to load env file
	envFile, err := a.loadEnvFile(c.Context, project, stage)
	if err != nil {
		// Env file might not exist yet - show role-based access
		fmt.Println("Environment not found. Showing role-based access:")
		fmt.Println()
	}

	// Check if using per-secret permissions
	if envFile == nil || envFile.Permissions == nil || envFile.Permissions.UseRoleBasedAccess || envFile.Permissions.Count() == 0 {
		fmt.Printf("Using stage-based access (users with access to %s stage)\n", stage)
		fmt.Println()

		// List users who can access this stage
		userList, err := a.loadUsers()
		if err != nil {
			return fmt.Errorf("failed to load users: %w", err)
		}

		fmt.Printf("%-35s %-15s %-10s\n", "EMAIL", "ROLE", "ACCESS")
		fmt.Printf("%-35s %-15s %-10s\n", "-----", "----", "------")

		for _, user := range userList.Users {
			// Check if user can access this stage
			canAccess := false
			highestRole := ""
			for _, role := range user.Roles {
				if role.CanAccessStage(stage) {
					canAccess = true
					highestRole = string(role)
				}
			}

			if canAccess {
				email := user.Email
				if user.PublicKey == a.cfg.Identity.PublicKey {
					email += " (you)"
				}
				fmt.Printf("%-35s %-15s %-10s\n", email, highestRole, "read/write")
			}
		}
	} else {
		fmt.Println("Using per-secret access control")
		fmt.Println()

		fmt.Printf("%-35s %-10s\n", "EMAIL", "ACCESS")
		fmt.Printf("%-35s %-10s\n", "-----", "------")

		for _, perm := range envFile.Permissions.Recipients {
			fmt.Printf("%-35s %-10s\n", perm.Email, perm.Access)
		}
	}

	return nil
}

// EnvAccessGrant grants access to an environment
func (a *Action) EnvAccessGrant(c *cli.Context) error {
	if c.NArg() < 3 {
		return fmt.Errorf("usage: passbook env access grant PROJECT STAGE EMAIL [--level read|write]")
	}

	project := c.Args().Get(0)
	stage := models.Stage(c.Args().Get(1))
	email := c.Args().Get(2)
	level := c.String("level")

	if !stage.IsValid() {
		return fmt.Errorf("invalid stage: %s (use dev, staging, or prod)", stage)
	}

	// Validate access level
	access := models.AccessLevel(level)
	if !access.IsValid() {
		return fmt.Errorf("invalid access level: %s (use 'read' or 'write')", level)
	}

	// Check permission - must have access to this stage
	currentUser, err := a.getCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	hasAccess := false
	for _, role := range currentUser.Roles {
		if role.CanAccessStage(stage) {
			hasAccess = true
			break
		}
	}
	if !hasAccess {
		return fmt.Errorf("permission denied: you don't have access to %s stage", stage)
	}

	// Find the target user
	userList, err := a.loadUsers()
	if err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	var targetUser *models.User
	for _, u := range userList.Users {
		if u.Email == email {
			targetUser = &u
			break
		}
	}
	if targetUser == nil {
		return fmt.Errorf("user not found: %s", email)
	}

	if targetUser.PublicKey == "" {
		return fmt.Errorf("user %s has no public key", email)
	}

	// Load or create env file
	envFile, err := a.loadEnvFile(c.Context, project, stage)
	if err != nil {
		// Create empty env file
		envFile = &models.EnvFile{
			Project:   project,
			Stage:     stage,
			Vars:      []models.EnvVar{},
			CreatedBy: currentUser.Email,
			UpdatedBy: currentUser.Email,
		}
	}

	// Initialize permissions if needed
	if envFile.Permissions == nil {
		envFile.Permissions = models.NewSecretPermissions()
	}
	envFile.Permissions.UseRoleBasedAccess = false

	// Grant access
	envFile.Permissions.AddRecipient(email, targetUser.PublicKey, access)

	// Make sure current user has access too
	if !envFile.Permissions.HasRecipient(currentUser.Email) {
		envFile.Permissions.AddRecipient(currentUser.Email, currentUser.PublicKey, models.AccessWrite)
	}

	// Save env file
	if err := a.saveEnvFileWithPermissions(c.Context, envFile); err != nil {
		return fmt.Errorf("failed to save environment: %w", err)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Grant %s access to %s for %s/%s", access, email, project, stage)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("✓ Granted %s access to %s for %s/%s\n", access, email, project, stage)

	return nil
}

// EnvAccessRevoke revokes access from an environment
func (a *Action) EnvAccessRevoke(c *cli.Context) error {
	if c.NArg() < 3 {
		return fmt.Errorf("usage: passbook env access revoke PROJECT STAGE EMAIL")
	}

	project := c.Args().Get(0)
	stage := models.Stage(c.Args().Get(1))
	email := c.Args().Get(2)

	if !stage.IsValid() {
		return fmt.Errorf("invalid stage: %s (use dev, staging, or prod)", stage)
	}

	// Check permission
	currentUser, err := a.getCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	hasAccess := false
	for _, role := range currentUser.Roles {
		if role.CanAccessStage(stage) {
			hasAccess = true
			break
		}
	}
	if !hasAccess {
		return fmt.Errorf("permission denied: you don't have access to %s stage", stage)
	}

	// Can't revoke your own access
	if email == currentUser.Email {
		return fmt.Errorf("cannot revoke your own access")
	}

	// Load env file
	envFile, err := a.loadEnvFile(c.Context, project, stage)
	if err != nil {
		return fmt.Errorf("failed to load environment: %w", err)
	}

	// Check if using per-secret permissions
	if envFile.Permissions == nil || envFile.Permissions.UseRoleBasedAccess {
		return fmt.Errorf("environment is using stage-based access; grant specific access first to switch to per-secret access")
	}

	// Revoke access
	if !envFile.Permissions.RemoveRecipient(email) {
		return fmt.Errorf("user %s does not have explicit access", email)
	}

	// Save env file
	if err := a.saveEnvFileWithPermissions(c.Context, envFile); err != nil {
		return fmt.Errorf("failed to save environment: %w", err)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Revoke access from %s for %s/%s", email, project, stage)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("✓ Revoked access from %s for %s/%s\n", email, project, stage)

	return nil
}

// parseCredentialPath parses "website/name" into separate parts
func parseCredentialPath(path string) (website, name string, err error) {
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid path format, expected WEBSITE/NAME")
	}
	return parts[0], parts[1], nil
}
