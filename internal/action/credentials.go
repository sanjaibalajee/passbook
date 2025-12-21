package action

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"passbook/internal/backend/crypto/age"
	"passbook/internal/models"
	"passbook/pkg/pwgen"
	"passbook/pkg/termio"
)

// CredList lists all credentials
func (a *Action) CredList(c *cli.Context) error {
	websiteFilter := c.String("website")
	tagsFilter := c.StringSlice("tag")

	credentialsDir := filepath.Join(a.cfg.StorePath, "credentials")

	// Check if credentials directory exists
	if _, err := os.Stat(credentialsDir); os.IsNotExist(err) {
		fmt.Println("No credentials found.")
		fmt.Println("\nAdd one with: passbook cred add github.com")
		return nil
	}

	fmt.Println("Credentials")
	fmt.Println("===========")
	fmt.Println()

	// Walk credentials directory
	var count int
	err := filepath.Walk(credentialsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-.age files
		if info.IsDir() || !strings.HasSuffix(info.Name(), age.Ext) {
			return nil
		}

		// Parse path: credentials/website/name.age
		relPath, _ := filepath.Rel(credentialsDir, path)
		parts := strings.Split(relPath, string(filepath.Separator))
		if len(parts) != 2 {
			return nil
		}

		website := parts[0]
		name := strings.TrimSuffix(parts[1], age.Ext)

		// Apply website filter
		if websiteFilter != "" && website != websiteFilter {
			return nil
		}

		// Try to decrypt and get metadata
		cred, err := a.loadCredential(c.Context, website, name)
		if err != nil {
			// Show even if can't decrypt
			fmt.Printf("  %s/%s (encrypted)\n", website, name)
			count++
			return nil
		}

		// Apply tag filter
		if len(tagsFilter) > 0 {
			hasTag := false
			for _, filterTag := range tagsFilter {
				for _, credTag := range cred.Tags {
					if credTag == filterTag {
						hasTag = true
						break
					}
				}
			}
			if !hasTag {
				return nil
			}
		}

		// Display
		fmt.Printf("  %s/%s\n", website, name)
		fmt.Printf("    Username: %s\n", cred.Username)
		if len(cred.Tags) > 0 {
			fmt.Printf("    Tags: %s\n", strings.Join(cred.Tags, ", "))
		}
		count++

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to list credentials: %w", err)
	}

	if count == 0 {
		fmt.Println("No credentials found.")
		fmt.Println("\nAdd one with: passbook cred add github.com")
	} else {
		fmt.Printf("\nTotal: %d credential(s)\n", count)
	}

	return nil
}

// CredShow shows a credential
func (a *Action) CredShow(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("usage: passbook cred show WEBSITE/NAME")
	}

	path := c.Args().First()
	clip := c.Bool("clip")
	passwordOnly := c.Bool("password")

	website, name, err := parseCredentialPath(path)
	if err != nil {
		return err
	}

	cred, err := a.loadCredential(c.Context, website, name)
	if err != nil {
		return fmt.Errorf("failed to load credential: %w", err)
	}

	if clip || passwordOnly {
		if clip {
			if err := clipboard.WriteAll(cred.Password); err != nil {
				return fmt.Errorf("failed to copy to clipboard: %w", err)
			}
			fmt.Printf("Password copied to clipboard (clears in %d seconds)\n", a.cfg.Preferences.ClipboardTimeout)

			// Clear clipboard after timeout
			go func() {
				time.Sleep(time.Duration(a.cfg.Preferences.ClipboardTimeout) * time.Second)
				clipboard.WriteAll("")
			}()
		} else {
			fmt.Println(cred.Password)
		}
		return nil
	}

	// Show full credential
	fmt.Printf("Credential: %s/%s\n", website, name)
	fmt.Println("========================")
	fmt.Printf("Username: %s\n", cred.Username)
	fmt.Printf("Password: %s\n", cred.Password)
	if cred.URL != "" {
		fmt.Printf("URL:      %s\n", cred.URL)
	}
	if cred.Notes != "" {
		fmt.Printf("Notes:    %s\n", cred.Notes)
	}
	if len(cred.Tags) > 0 {
		fmt.Printf("Tags:     %s\n", strings.Join(cred.Tags, ", "))
	}
	fmt.Printf("Created:  %s\n", cred.CreatedAt.Format("2006-01-02 15:04"))
	fmt.Printf("Updated:  %s\n", cred.UpdatedAt.Format("2006-01-02 15:04"))

	return nil
}

// CredAdd adds a new credential
func (a *Action) CredAdd(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("usage: passbook cred add WEBSITE [--name NAME]")
	}

	website := c.Args().First()
	name := c.String("name")
	username := c.String("username")
	password := c.String("password")
	generate := c.Bool("generate")
	length := c.Int("length")

	// Prompt for name if not provided
	if name == "" {
		var err error
		name, err = termio.PromptDefault("Account name: ", "default")
		if err != nil {
			return err
		}
	}

	// Check if credential already exists
	credPath := filepath.Join(a.cfg.StorePath, "credentials", website, name+age.Ext)
	if _, err := os.Stat(credPath); err == nil {
		return fmt.Errorf("credential %s/%s already exists", website, name)
	}

	// Prompt for username if not provided
	if username == "" {
		var err error
		username, err = termio.Prompt("Username/Email: ")
		if err != nil {
			return err
		}
	}

	// Generate or prompt for password
	if generate {
		var err error
		password, err = pwgen.GenerateSimple(length)
		if err != nil {
			return fmt.Errorf("failed to generate password: %w", err)
		}
		fmt.Printf("Generated password: %s\n", password)
	} else if password == "" {
		var err error
		password, err = termio.PromptPassword("Password: ")
		if err != nil {
			return err
		}
	}

	if password == "" {
		return fmt.Errorf("password is required")
	}

	// Get current user
	currentUser, err := a.getCurrentUser()
	if err != nil {
		// Use public key as fallback
		currentUser = &models.User{
			Email:     "unknown",
			PublicKey: a.cfg.Identity.PublicKey,
		}
	}

	// Create credential
	cred := &models.Credential{
		ID:        uuid.New().String(),
		Website:   website,
		Name:      name,
		Username:  username,
		Password:  password,
		CreatedBy: currentUser.Email,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save credential
	if err := a.saveCredential(c.Context, cred); err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Add credential: %s/%s", website, name)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("\n✓ Added credential: %s/%s\n", website, name)

	return nil
}

// CredEdit edits a credential
func (a *Action) CredEdit(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("usage: passbook cred edit WEBSITE/NAME")
	}

	path := c.Args().First()
	website, name, err := parseCredentialPath(path)
	if err != nil {
		return err
	}

	// Load existing credential
	cred, err := a.loadCredential(c.Context, website, name)
	if err != nil {
		return fmt.Errorf("failed to load credential: %w", err)
	}

	fmt.Printf("Editing credential: %s/%s\n", website, name)
	fmt.Println("(Press Enter to keep current value)")
	fmt.Println()

	// Prompt for new values
	newUsername, err := termio.PromptDefault("Username: ", cred.Username)
	if err != nil {
		return err
	}

	fmt.Printf("Current password: %s\n", cred.Password)
	newPassword, err := termio.Prompt("New password (or Enter to keep): ")
	if err != nil {
		return err
	}
	if newPassword == "" {
		newPassword = cred.Password
	}

	newNotes, err := termio.PromptDefault("Notes: ", cred.Notes)
	if err != nil {
		return err
	}

	// Update credential
	cred.Username = newUsername
	cred.Password = newPassword
	cred.Notes = newNotes
	cred.UpdatedAt = time.Now()

	// Save
	if err := a.saveCredential(c.Context, cred); err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Update credential: %s/%s", website, name)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("\n✓ Updated credential: %s/%s\n", website, name)

	return nil
}

// CredRemove removes a credential
func (a *Action) CredRemove(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("usage: passbook cred rm WEBSITE/NAME")
	}

	path := c.Args().First()
	force := c.Bool("force")

	website, name, err := parseCredentialPath(path)
	if err != nil {
		return err
	}

	credPath := filepath.Join(a.cfg.StorePath, "credentials", website, name+age.Ext)

	// Check if exists
	if _, err := os.Stat(credPath); os.IsNotExist(err) {
		return fmt.Errorf("credential %s/%s not found", website, name)
	}

	// Confirm
	if !force {
		confirm, err := termio.Confirm(fmt.Sprintf("Delete credential %s/%s?", website, name), false)
		if err != nil {
			return err
		}
		if !confirm {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	// Delete file
	if err := os.Remove(credPath); err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	// Remove empty website directory
	websiteDir := filepath.Join(a.cfg.StorePath, "credentials", website)
	entries, _ := os.ReadDir(websiteDir)
	if len(entries) == 0 {
		os.Remove(websiteDir)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Delete credential: %s/%s", website, name)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("✓ Deleted credential: %s/%s\n", website, name)

	return nil
}

// CredCopy copies password to clipboard
func (a *Action) CredCopy(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("usage: passbook cred copy WEBSITE/NAME")
	}

	path := c.Args().First()
	website, name, err := parseCredentialPath(path)
	if err != nil {
		return err
	}

	cred, err := a.loadCredential(c.Context, website, name)
	if err != nil {
		return fmt.Errorf("failed to load credential: %w", err)
	}

	if err := clipboard.WriteAll(cred.Password); err != nil {
		return fmt.Errorf("failed to copy to clipboard: %w", err)
	}

	timeout := a.cfg.Preferences.ClipboardTimeout
	fmt.Printf("✓ Password copied to clipboard (clears in %d seconds)\n", timeout)

	// Clear clipboard after timeout
	go func() {
		time.Sleep(time.Duration(timeout) * time.Second)
		clipboard.WriteAll("")
	}()

	return nil
}

// loadCredential loads and decrypts a credential
func (a *Action) loadCredential(ctx context.Context, website, name string) (*models.Credential, error) {
	credPath := filepath.Join(a.cfg.StorePath, "credentials", website, name+age.Ext)

	// Read encrypted file
	encrypted, err := os.ReadFile(credPath)
	if err != nil {
		return nil, err
	}

	// Decrypt
	ageBackend, err := age.New(a.cfg.IdentityPath())
	if err != nil {
		return nil, fmt.Errorf("failed to load identity: %w", err)
	}

	plaintext, err := ageBackend.Decrypt(ctx, encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	// Parse YAML
	var cred models.Credential
	if err := yaml.Unmarshal(plaintext, &cred); err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	return &cred, nil
}

// saveCredential encrypts and saves a credential
func (a *Action) saveCredential(ctx context.Context, cred *models.Credential) error {
	// Serialize to YAML
	data, err := yaml.Marshal(cred)
	if err != nil {
		return err
	}

	// Get recipients (all team members)
	recipients, err := a.getAllRecipientKeys()
	if err != nil {
		return fmt.Errorf("failed to get recipients: %w", err)
	}

	// Encrypt
	ageBackend, err := age.New(a.cfg.IdentityPath())
	if err != nil {
		return fmt.Errorf("failed to load identity: %w", err)
	}

	encrypted, err := ageBackend.Encrypt(ctx, data, recipients)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	// Create directory
	credDir := filepath.Join(a.cfg.StorePath, "credentials", cred.Website)
	if err := os.MkdirAll(credDir, 0700); err != nil {
		return err
	}

	// Write file
	credPath := filepath.Join(credDir, cred.Name+age.Ext)
	return os.WriteFile(credPath, encrypted, 0600)
}

// getAllRecipientKeys returns all recipient public keys from the team
func (a *Action) getAllRecipientKeys() ([]string, error) {
	userList, err := a.loadUsers()
	if err != nil {
		return nil, err
	}

	var keys []string
	for _, user := range userList.Users {
		if user.PublicKey != "" {
			keys = append(keys, user.PublicKey)
		}
	}

	// Always include self
	if a.cfg.Identity.PublicKey != "" {
		found := false
		for _, k := range keys {
			if k == a.cfg.Identity.PublicKey {
				found = true
				break
			}
		}
		if !found {
			keys = append(keys, a.cfg.Identity.PublicKey)
		}
	}

	return keys, nil
}

// saveCredentialWithPermissions encrypts and saves a credential using per-secret permissions
func (a *Action) saveCredentialWithPermissions(ctx context.Context, cred *models.Credential) error {
	// Serialize to YAML
	data, err := yaml.Marshal(cred)
	if err != nil {
		return err
	}

	// Get recipients from permissions
	var recipients []string
	if cred.Permissions != nil && !cred.Permissions.UseRoleBasedAccess && cred.Permissions.Count() > 0 {
		// Use per-secret permissions
		for _, perm := range cred.Permissions.Recipients {
			if perm.PublicKey != "" {
				recipients = append(recipients, perm.PublicKey)
			}
		}
	} else {
		// Fall back to all team members
		recipients, err = a.getAllRecipientKeys()
		if err != nil {
			return fmt.Errorf("failed to get recipients: %w", err)
		}
	}

	// Always include self
	if a.cfg.Identity.PublicKey != "" {
		found := false
		for _, k := range recipients {
			if k == a.cfg.Identity.PublicKey {
				found = true
				break
			}
		}
		if !found {
			recipients = append(recipients, a.cfg.Identity.PublicKey)
		}
	}

	// Encrypt
	ageBackend, err := age.New(a.cfg.IdentityPath())
	if err != nil {
		return fmt.Errorf("failed to load identity: %w", err)
	}

	encrypted, err := ageBackend.Encrypt(ctx, data, recipients)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	// Create directory
	credDir := filepath.Join(a.cfg.StorePath, "credentials", cred.Website)
	if err := os.MkdirAll(credDir, 0700); err != nil {
		return err
	}

	// Write file
	credPath := filepath.Join(credDir, cred.Name+age.Ext)
	return os.WriteFile(credPath, encrypted, 0600)
}
