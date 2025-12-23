package action

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"passbook/internal/backend/crypto/age"
	"passbook/internal/config"
	"passbook/internal/models"
	"passbook/pkg/termio"
)

// Init initializes a new passbook store
func (a *Action) Init(c *cli.Context) error {
	fmt.Println("Initializing passbook store...")
	fmt.Println()

	remote := c.String("remote")
	domain := c.String("domain")
	org := c.String("org")

	if org == "" {
		org = "My Organization"
	}

	storePath := a.cfg.StorePath
	identityPath := a.cfg.IdentityPath()

	// Check if already initialized
	if a.cfg.IsInitialized() {
		return fmt.Errorf("passbook is already initialized at %s", storePath)
	}

	fmt.Printf("Store path:    %s\n", storePath)
	fmt.Printf("Organization:  %s\n", org)
	if domain != "" {
		fmt.Printf("Allowed domain: @%s\n", domain)
	}
	if remote != "" {
		fmt.Printf("Git remote:    %s\n", remote)
	}
	fmt.Println()

	// 1. Create store directory
	fmt.Print("Creating store directory... ")
	if err := os.MkdirAll(storePath, 0700); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to create store directory: %w", err)
	}
	fmt.Println("OK")

	// 2. Initialize git repo
	fmt.Print("Initializing git repository... ")
	if err := initGitRepo(storePath); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to initialize git repo: %w", err)
	}
	fmt.Println("OK")

	// 3. Add remote if provided
	if remote != "" {
		fmt.Print("Adding git remote... ")
		if err := addGitRemote(storePath, remote); err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("failed to add git remote: %w", err)
		}
		fmt.Println("OK")
	}

	// 4. Generate identity if needed
	var publicKey string
	if !a.cfg.HasIdentity() {
		fmt.Print("Generating age identity... ")
		var err error
		publicKey, err = age.GenerateIdentity(identityPath)
		if err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("failed to generate identity: %w", err)
		}
		fmt.Println("OK")
		fmt.Printf("  Public key: %s\n", publicKey)
	} else {
		// Load existing public key
		fmt.Print("Loading existing identity... ")
		ageBackend, err := age.New(identityPath)
		if err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("failed to load identity: %w", err)
		}
		publicKey = ageBackend.PublicKey()
		fmt.Println("OK")
		fmt.Printf("  Public key: %s\n", publicKey)
	}

	// 5. Create .passbook-config
	fmt.Print("Creating store configuration... ")
	storeConfig := struct {
		Org   config.OrgConfig   `yaml:"org"`
		Git   config.GitConfig   `yaml:"git"`
		Email config.EmailConfig `yaml:"email"`
	}{
		Org: config.OrgConfig{
			Name:          org,
			AllowedDomain: domain,
		},
		Git: config.GitConfig{
			Remote:   remote,
			AutoPush: true,
			AutoSync: true,
			Branch:   "main",
		},
		Email: config.EmailConfig{
			Provider: "console",
		},
	}

	configPath := filepath.Join(storePath, ".passbook-config")
	configData, err := yaml.Marshal(storeConfig)
	if err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to write config: %w", err)
	}
	fmt.Println("OK")

	// 6. Create .passbook-recipients with the admin's key
	fmt.Print("Creating recipients file... ")
	recipientsPath := filepath.Join(storePath, ".passbook-recipients")
	recipientsContent := fmt.Sprintf("# Passbook Recipients - Team Members\n# Format: <age-public-key> # <email>\n\n%s # admin (initial setup)\n", publicKey)
	if err := os.WriteFile(recipientsPath, []byte(recipientsContent), 0600); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to write recipients: %w", err)
	}
	fmt.Println("OK")

	// 6b. Create .passbook-users with admin user
	fmt.Print("Creating users file... ")
	adminUser := models.User{
		ID:        uuid.New().String(),
		Email:     "admin@" + domain, // Placeholder, will be updated on first login
		Name:      "Admin",
		PublicKey: publicKey,
		CreatedAt: time.Now(),
		Roles:     []models.Role{models.RoleAdmin},
	}
	userList := models.UserList{Users: []models.User{adminUser}}
	usersPath := filepath.Join(storePath, ".passbook-users")
	usersData, err := yaml.Marshal(userList)
	if err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to marshal users: %w", err)
	}
	if err := os.WriteFile(usersPath, usersData, 0600); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to write users: %w", err)
	}
	fmt.Println("OK")

	// 7. Create directories
	fmt.Print("Creating directory structure... ")
	dirs := []string{"credentials", "projects"}
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(storePath, dir), 0700); err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("failed to create %s directory: %w", dir, err)
		}
		// Create .gitkeep to track empty directories
		gitkeepPath := filepath.Join(storePath, dir, ".gitkeep")
		if err := os.WriteFile(gitkeepPath, []byte(""), 0600); err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("failed to create .gitkeep: %w", err)
		}
	}
	fmt.Println("OK")

	// 8. Create .gitignore
	fmt.Print("Creating .gitignore... ")
	gitignorePath := filepath.Join(storePath, ".gitignore")
	gitignoreContent := "# Local files\n*.local\n*.tmp\n"
	if err := os.WriteFile(gitignorePath, []byte(gitignoreContent), 0600); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to write .gitignore: %w", err)
	}
	fmt.Println("OK")

	// 9. Initial commit
	fmt.Print("Creating initial commit... ")
	if err := gitCommit(storePath, "Initialize passbook store"); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to create initial commit: %w", err)
	}
	fmt.Println("OK")

	// 10. Save user config with identity
	fmt.Print("Saving user configuration... ")
	a.cfg.Identity.PublicKey = publicKey
	a.cfg.Identity.PrivateKeyPath = identityPath
	if err := a.cfg.Save(); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to save user config: %w", err)
	}
	fmt.Println("OK")

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("  Passbook initialized successfully!")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Printf("Store: %s\n", storePath)
	fmt.Printf("Identity: %s\n", identityPath)
	fmt.Println()

	if remote != "" {
		fmt.Println("Next steps:")
		fmt.Println("  1. Push to remote: cd ~/.passbook && git push -u origin main")
		fmt.Println("  2. Login: passbook login")
		fmt.Println("  3. Add credentials: passbook cred add github.com")
	} else {
		fmt.Println("Next steps:")
		fmt.Println("  1. Login: passbook login")
		fmt.Println("  2. Add credentials: passbook cred add github.com")
		fmt.Println("  3. (Optional) Add a git remote for backup")
	}

	return nil
}

// Clone clones an existing passbook store
func (a *Action) Clone(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("usage: passbook clone GIT_URL")
	}

	gitURL := c.Args().First()
	storePath := a.cfg.StorePath
	identityPath := a.cfg.IdentityPath()

	// Check if already initialized
	if a.cfg.IsInitialized() {
		return fmt.Errorf("passbook is already initialized at %s", storePath)
	}

	fmt.Printf("Cloning passbook store from %s...\n", gitURL)
	fmt.Println()

	// 1. Clone the repo
	fmt.Print("Cloning repository... ")
	cmd := exec.Command("git", "clone", gitURL, storePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to clone repository: %s", string(output))
	}
	fmt.Println("OK")

	// 2. Generate identity if needed
	var publicKey string
	if !a.cfg.HasIdentity() {
		fmt.Print("Generating age identity... ")
		var err error
		publicKey, err = age.GenerateIdentity(identityPath)
		if err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("failed to generate identity: %w", err)
		}
		fmt.Println("OK")
		fmt.Printf("  Public key: %s\n", publicKey)
	} else {
		fmt.Print("Loading existing identity... ")
		ageBackend, err := age.New(identityPath)
		if err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("failed to load identity: %w", err)
		}
		publicKey = ageBackend.PublicKey()
		fmt.Println("OK")
		fmt.Printf("  Public key: %s\n", publicKey)
	}

	// 3. Save user config
	fmt.Print("Saving user configuration... ")
	a.cfg.Identity.PublicKey = publicKey
	a.cfg.Identity.PrivateKeyPath = identityPath
	if err := a.cfg.Save(); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to save user config: %w", err)
	}
	fmt.Println("OK")

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("  Passbook cloned successfully!")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Printf("Store: %s\n", storePath)
	fmt.Printf("Your public key: %s\n", publicKey)
	fmt.Println()
	fmt.Println("IMPORTANT: Ask an admin to add your public key to the team.")
	fmt.Println("Send them this command:")
	fmt.Printf("  passbook team invite YOUR_EMAIL --key %s\n", publicKey)

	return nil
}

// Setup runs the interactive setup wizard
func (a *Action) Setup(c *cli.Context) error {
	fmt.Println("Welcome to Passbook Setup Wizard")
	fmt.Println("================================")
	fmt.Println()

	// Ask what they want to do
	options := []string{
		"Initialize a new store (you're the admin)",
		"Clone an existing store (joining a team)",
	}

	choice, err := termio.Select("What would you like to do?", options, 0)
	if err != nil {
		return err
	}

	fmt.Println()

	if choice == 0 {
		// Initialize new store
		org, err := termio.PromptDefault("Organization name: ", "My Organization")
		if err != nil {
			return err
		}

		domain, err := termio.Prompt("Allowed email domain (e.g., mycompany.com, leave empty for any): ")
		if err != nil {
			return err
		}
		domain = strings.TrimPrefix(domain, "@")

		remote, err := termio.Prompt("Git remote URL (optional, press Enter to skip): ")
		if err != nil {
			return err
		}

		fmt.Println()

		// Create a new context with the values
		newCtx := c.Context
		newC := cli.NewContext(c.App, nil, nil)
		newC.Context = newCtx

		// Set flags manually by creating the init command
		return a.initWithArgs(org, domain, remote)
	} else {
		// Clone existing store
		gitURL, err := termio.Prompt("Git repository URL: ")
		if err != nil {
			return err
		}

		if gitURL == "" {
			return fmt.Errorf("git URL is required")
		}

		fmt.Println()

		return a.cloneWithArgs(gitURL)
	}
}

// initWithArgs runs init with the given arguments
func (a *Action) initWithArgs(org, domain, remote string) error {
	storePath := a.cfg.StorePath
	identityPath := a.cfg.IdentityPath()

	// Check if already initialized
	if a.cfg.IsInitialized() {
		return fmt.Errorf("passbook is already initialized at %s", storePath)
	}

	fmt.Println("Initializing passbook store...")
	fmt.Println()
	fmt.Printf("Store path:    %s\n", storePath)
	fmt.Printf("Organization:  %s\n", org)
	if domain != "" {
		fmt.Printf("Allowed domain: @%s\n", domain)
	}
	if remote != "" {
		fmt.Printf("Git remote:    %s\n", remote)
	}
	fmt.Println()

	// Create store directory
	fmt.Print("Creating store directory... ")
	if err := os.MkdirAll(storePath, 0700); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to create store directory: %w", err)
	}
	fmt.Println("OK")

	// Initialize git repo
	fmt.Print("Initializing git repository... ")
	if err := initGitRepo(storePath); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to initialize git repo: %w", err)
	}
	fmt.Println("OK")

	// Add remote if provided
	if remote != "" {
		fmt.Print("Adding git remote... ")
		if err := addGitRemote(storePath, remote); err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("failed to add git remote: %w", err)
		}
		fmt.Println("OK")
	}

	// Generate identity
	var publicKey string
	if !a.cfg.HasIdentity() {
		fmt.Print("Generating age identity... ")
		var err error
		publicKey, err = age.GenerateIdentity(identityPath)
		if err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("failed to generate identity: %w", err)
		}
		fmt.Println("OK")
		fmt.Printf("  Public key: %s\n", publicKey)
	} else {
		fmt.Print("Loading existing identity... ")
		ageBackend, err := age.New(identityPath)
		if err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("failed to load identity: %w", err)
		}
		publicKey = ageBackend.PublicKey()
		fmt.Println("OK")
		fmt.Printf("  Public key: %s\n", publicKey)
	}

	// Create config
	fmt.Print("Creating store configuration... ")
	storeConfig := struct {
		Org   config.OrgConfig   `yaml:"org"`
		Git   config.GitConfig   `yaml:"git"`
		Email config.EmailConfig `yaml:"email"`
	}{
		Org: config.OrgConfig{
			Name:          org,
			AllowedDomain: domain,
		},
		Git: config.GitConfig{
			Remote:   remote,
			AutoPush: true,
			AutoSync: true,
			Branch:   "main",
		},
		Email: config.EmailConfig{
			Provider: "console",
		},
	}

	configPath := filepath.Join(storePath, ".passbook-config")
	configData, err := yaml.Marshal(storeConfig)
	if err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to write config: %w", err)
	}
	fmt.Println("OK")

	// Create recipients
	fmt.Print("Creating recipients file... ")
	recipientsPath := filepath.Join(storePath, ".passbook-recipients")
	recipientsContent := fmt.Sprintf("# Passbook Recipients\n\n%s # admin\n", publicKey)
	if err := os.WriteFile(recipientsPath, []byte(recipientsContent), 0600); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to write recipients: %w", err)
	}
	fmt.Println("OK")

	// Create directories
	fmt.Print("Creating directory structure... ")
	for _, dir := range []string{"credentials", "projects"} {
		if err := os.MkdirAll(filepath.Join(storePath, dir), 0700); err != nil {
			fmt.Println("FAILED")
			return err
		}
		if err := os.WriteFile(filepath.Join(storePath, dir, ".gitkeep"), []byte(""), 0600); err != nil {
			fmt.Println("FAILED")
			return err
		}
	}
	fmt.Println("OK")

	// Create .gitignore
	fmt.Print("Creating .gitignore... ")
	if err := os.WriteFile(filepath.Join(storePath, ".gitignore"), []byte("*.local\n*.tmp\n"), 0600); err != nil {
		fmt.Println("FAILED")
		return err
	}
	fmt.Println("OK")

	// Initial commit
	fmt.Print("Creating initial commit... ")
	if err := gitCommit(storePath, "Initialize passbook store"); err != nil {
		fmt.Println("FAILED")
		return err
	}
	fmt.Println("OK")

	// Save user config
	fmt.Print("Saving user configuration... ")
	a.cfg.Identity.PublicKey = publicKey
	a.cfg.Identity.PrivateKeyPath = identityPath
	if err := a.cfg.Save(); err != nil {
		fmt.Println("FAILED")
		return err
	}
	fmt.Println("OK")

	fmt.Println()
	fmt.Println("Passbook initialized successfully!")
	return nil
}

// cloneWithArgs runs clone with the given URL
func (a *Action) cloneWithArgs(gitURL string) error {
	storePath := a.cfg.StorePath
	identityPath := a.cfg.IdentityPath()

	if a.cfg.IsInitialized() {
		return fmt.Errorf("passbook is already initialized at %s", storePath)
	}

	fmt.Print("Cloning repository... ")
	cmd := exec.Command("git", "clone", gitURL, storePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to clone: %s", string(output))
	}
	fmt.Println("OK")

	var publicKey string
	if !a.cfg.HasIdentity() {
		fmt.Print("Generating age identity... ")
		var err error
		publicKey, err = age.GenerateIdentity(identityPath)
		if err != nil {
			fmt.Println("FAILED")
			return err
		}
		fmt.Println("OK")
		fmt.Printf("  Public key: %s\n", publicKey)
	} else {
		fmt.Print("Loading existing identity... ")
		ageBackend, err := age.New(identityPath)
		if err != nil {
			fmt.Println("FAILED")
			return err
		}
		publicKey = ageBackend.PublicKey()
		fmt.Println("OK")
	}

	fmt.Print("Saving user configuration... ")
	a.cfg.Identity.PublicKey = publicKey
	a.cfg.Identity.PrivateKeyPath = identityPath
	if err := a.cfg.Save(); err != nil {
		fmt.Println("FAILED")
		return err
	}
	fmt.Println("OK")

	fmt.Println()
	fmt.Println("Cloned successfully!")
	fmt.Printf("Your public key: %s\n", publicKey)
	fmt.Println("Ask an admin to add your key to the team.")
	return nil
}

// Git helper functions

func initGitRepo(path string) error {
	cmd := exec.Command("git", "init")
	cmd.Dir = path
	return cmd.Run()
}

func addGitRemote(path, remote string) error {
	cmd := exec.Command("git", "remote", "add", "origin", remote)
	cmd.Dir = path
	return cmd.Run()
}

func gitCommit(path, message string) error {
	// Add all files
	addCmd := exec.Command("git", "add", "-A")
	addCmd.Dir = path
	if err := addCmd.Run(); err != nil {
		return err
	}

	// Commit
	commitCmd := exec.Command("git", "commit", "-m", message)
	commitCmd.Dir = path
	return commitCmd.Run()
}
