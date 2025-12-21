package action

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"passbook/internal/backend/crypto/age"
	"passbook/internal/models"
)

// EnvList lists projects or stages
func (a *Action) EnvList(c *cli.Context) error {
	projectFilter := c.String("project")

	projectsDir := filepath.Join(a.cfg.StorePath, "projects")

	// Check if projects directory exists
	if _, err := os.Stat(projectsDir); os.IsNotExist(err) {
		fmt.Println("No projects found.")
		fmt.Println("\nCreate one with: passbook project create myapp")
		return nil
	}

	if projectFilter != "" {
		// List stages for specific project
		fmt.Printf("Stages for project: %s\n", projectFilter)
		fmt.Println("========================")
		fmt.Println()

		projectDir := filepath.Join(projectsDir, projectFilter)
		if _, err := os.Stat(projectDir); os.IsNotExist(err) {
			return fmt.Errorf("project %s not found", projectFilter)
		}

		// Get current user to check access
		currentUser, _ := a.getCurrentUser()

		entries, err := os.ReadDir(projectDir)
		if err != nil {
			return fmt.Errorf("failed to read project: %w", err)
		}

		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".env.age") {
				stageName := strings.TrimSuffix(entry.Name(), ".env.age")
				stage := models.Stage(stageName)

				// Check access
				canAccess := "✓"
				if currentUser != nil {
					hasAccess := false
					for _, role := range currentUser.Roles {
						if role.CanAccessStage(stage) {
							hasAccess = true
							break
						}
					}
					if !hasAccess {
						canAccess = "✗ (no access)"
					}
				}

				fmt.Printf("  %s %s\n", stageName, canAccess)
			}
		}
	} else {
		// List all projects
		fmt.Println("Projects")
		fmt.Println("========")
		fmt.Println()

		entries, err := os.ReadDir(projectsDir)
		if err != nil {
			return fmt.Errorf("failed to read projects: %w", err)
		}

		if len(entries) == 0 {
			fmt.Println("No projects found.")
			fmt.Println("\nCreate one with: passbook project create myapp")
			return nil
		}

		for _, entry := range entries {
			if entry.IsDir() {
				// Count stages
				stageCount := 0
				projectDir := filepath.Join(projectsDir, entry.Name())
				stageEntries, _ := os.ReadDir(projectDir)
				for _, se := range stageEntries {
					if strings.HasSuffix(se.Name(), ".env.age") {
						stageCount++
					}
				}
				fmt.Printf("  %s (%d stages)\n", entry.Name(), stageCount)
			}
		}
	}

	return nil
}

// EnvShow shows environment variables
func (a *Action) EnvShow(c *cli.Context) error {
	if c.NArg() < 2 {
		return fmt.Errorf("usage: passbook env show PROJECT STAGE")
	}

	project := c.Args().Get(0)
	stage := models.Stage(c.Args().Get(1))
	asExport := c.Bool("export")
	asDotenv := c.Bool("dotenv")

	// Validate stage
	if !stage.IsValid() {
		return fmt.Errorf("invalid stage: %s (valid: dev, staging, prod)", stage)
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
		return fmt.Errorf("access denied: you don't have permission to access %s environment", stage)
	}

	// Load env file
	envFile, err := a.loadEnvFile(c.Context, project, stage)
	if err != nil {
		return fmt.Errorf("failed to load environment: %w", err)
	}

	// Output in requested format
	if asExport {
		fmt.Print(envFile.ToExport())
	} else if asDotenv {
		fmt.Print(envFile.ToDotEnv())
	} else {
		fmt.Printf("Environment: %s/%s\n", project, stage)
		fmt.Println("========================")
		fmt.Printf("Updated: %s by %s\n\n", envFile.UpdatedAt.Format("2006-01-02 15:04"), envFile.UpdatedBy)

		if len(envFile.Vars) == 0 {
			fmt.Println("No variables set.")
		} else {
			for _, v := range envFile.Vars {
				value := v.Value
				if v.IsSecret {
					value = "********"
				}
				fmt.Printf("  %-30s = %s\n", v.Key, value)
			}
		}
	}

	return nil
}

// EnvSet sets an environment variable
func (a *Action) EnvSet(c *cli.Context) error {
	if c.NArg() < 3 {
		return fmt.Errorf("usage: passbook env set PROJECT STAGE KEY=VALUE")
	}

	project := c.Args().Get(0)
	stage := models.Stage(c.Args().Get(1))
	kvPair := c.Args().Get(2)
	isSecret := c.Bool("secret")

	// Validate stage
	if !stage.IsValid() {
		return fmt.Errorf("invalid stage: %s (valid: dev, staging, prod)", stage)
	}

	// Parse KEY=VALUE
	parts := strings.SplitN(kvPair, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid format, expected KEY=VALUE")
	}
	key, value := parts[0], parts[1]

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
		return fmt.Errorf("access denied: you don't have permission to modify %s environment", stage)
	}

	// Load or create env file
	envFile, err := a.loadEnvFile(c.Context, project, stage)
	if err != nil {
		// Create new env file if doesn't exist
		envFile = &models.EnvFile{
			Project:   project,
			Stage:     stage,
			Vars:      []models.EnvVar{},
			CreatedBy: currentUser.Email,
			UpdatedBy: currentUser.Email,
			UpdatedAt: time.Now(),
		}
	}

	// Update variable
	envFile.Set(key, value, isSecret)
	envFile.UpdatedBy = currentUser.Email
	envFile.UpdatedAt = time.Now()

	// Save
	if err := a.saveEnvFile(c.Context, envFile); err != nil {
		return fmt.Errorf("failed to save environment: %w", err)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Set %s in %s/%s", key, project, stage)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("✓ Set %s in %s/%s\n", key, project, stage)

	return nil
}

// EnvRemove removes an environment variable
func (a *Action) EnvRemove(c *cli.Context) error {
	if c.NArg() < 3 {
		return fmt.Errorf("usage: passbook env rm PROJECT STAGE KEY")
	}

	project := c.Args().Get(0)
	stage := models.Stage(c.Args().Get(1))
	key := c.Args().Get(2)

	// Validate stage
	if !stage.IsValid() {
		return fmt.Errorf("invalid stage: %s (valid: dev, staging, prod)", stage)
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
		return fmt.Errorf("access denied: you don't have permission to modify %s environment", stage)
	}

	// Load env file
	envFile, err := a.loadEnvFile(c.Context, project, stage)
	if err != nil {
		return fmt.Errorf("failed to load environment: %w", err)
	}

	// Remove variable
	if !envFile.Delete(key) {
		return fmt.Errorf("variable %s not found", key)
	}

	envFile.UpdatedBy = currentUser.Email
	envFile.UpdatedAt = time.Now()

	// Save
	if err := a.saveEnvFile(c.Context, envFile); err != nil {
		return fmt.Errorf("failed to save environment: %w", err)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Remove %s from %s/%s", key, project, stage)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("✓ Removed %s from %s/%s\n", key, project, stage)

	return nil
}

// EnvExport exports environment to file
func (a *Action) EnvExport(c *cli.Context) error {
	if c.NArg() < 2 {
		return fmt.Errorf("usage: passbook env export PROJECT STAGE")
	}

	project := c.Args().Get(0)
	stage := models.Stage(c.Args().Get(1))
	output := c.String("output")
	format := c.String("format")

	// Validate stage
	if !stage.IsValid() {
		return fmt.Errorf("invalid stage: %s (valid: dev, staging, prod)", stage)
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
		return fmt.Errorf("access denied: you don't have permission to access %s environment", stage)
	}

	// Load env file
	envFile, err := a.loadEnvFile(c.Context, project, stage)
	if err != nil {
		return fmt.Errorf("failed to load environment: %w", err)
	}

	// Format output
	var content string
	switch format {
	case "dotenv", "":
		content = envFile.ToDotEnv()
	case "export":
		content = envFile.ToExport()
	case "json":
		data, err := json.MarshalIndent(envFile.ToMap(), "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		content = string(data) + "\n"
	default:
		return fmt.Errorf("unknown format: %s (valid: dotenv, export, json)", format)
	}

	// Write output
	if output != "" {
		if err := os.WriteFile(output, []byte(content), 0600); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		fmt.Printf("✓ Exported %s/%s to %s\n", project, stage, output)
	} else {
		fmt.Print(content)
	}

	return nil
}

// EnvImport imports environment from file
func (a *Action) EnvImport(c *cli.Context) error {
	if c.NArg() < 3 {
		return fmt.Errorf("usage: passbook env import PROJECT STAGE FILE")
	}

	project := c.Args().Get(0)
	stage := models.Stage(c.Args().Get(1))
	file := c.Args().Get(2)

	// Validate stage
	if !stage.IsValid() {
		return fmt.Errorf("invalid stage: %s (valid: dev, staging, prod)", stage)
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
		return fmt.Errorf("access denied: you don't have permission to modify %s environment", stage)
	}

	// Read file
	content, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Parse
	vars := models.ParseDotEnv(string(content))
	if len(vars) == 0 {
		return fmt.Errorf("no variables found in %s", file)
	}

	// Load or create env file
	envFile, err := a.loadEnvFile(c.Context, project, stage)
	if err != nil {
		envFile = &models.EnvFile{
			Project:   project,
			Stage:     stage,
			Vars:      []models.EnvVar{},
			CreatedBy: currentUser.Email,
			UpdatedBy: currentUser.Email,
			UpdatedAt: time.Now(),
		}
	}

	// Merge variables
	for _, v := range vars {
		envFile.Set(v.Key, v.Value, v.IsSecret)
	}
	envFile.UpdatedBy = currentUser.Email
	envFile.UpdatedAt = time.Now()

	// Save
	if err := a.saveEnvFile(c.Context, envFile); err != nil {
		return fmt.Errorf("failed to save environment: %w", err)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Import %d variables into %s/%s", len(vars), project, stage)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("✓ Imported %d variables into %s/%s\n", len(vars), project, stage)

	return nil
}

// EnvExec runs a command with environment variables
func (a *Action) EnvExec(c *cli.Context) error {
	// Find -- separator
	args := c.Args().Slice()
	sepIdx := -1
	for i, arg := range args {
		if arg == "--" {
			sepIdx = i
			break
		}
	}

	if sepIdx < 2 || sepIdx == len(args)-1 {
		return fmt.Errorf("usage: passbook env exec PROJECT STAGE -- COMMAND [ARGS...]")
	}

	project := args[0]
	stage := models.Stage(args[1])
	cmdArgs := args[sepIdx+1:]

	// Validate stage
	if !stage.IsValid() {
		return fmt.Errorf("invalid stage: %s (valid: dev, staging, prod)", stage)
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
		return fmt.Errorf("access denied: you don't have permission to access %s environment", stage)
	}

	// Load env file
	envFile, err := a.loadEnvFile(c.Context, project, stage)
	if err != nil {
		return fmt.Errorf("failed to load environment: %w", err)
	}

	// Build command
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = os.Environ()

	// Add env vars
	for _, v := range envFile.Vars {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", v.Key, v.Value))
	}

	// Connect stdio
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Run
	return cmd.Run()
}

// loadEnvFile loads and decrypts an env file
func (a *Action) loadEnvFile(ctx context.Context, project string, stage models.Stage) (*models.EnvFile, error) {
	envPath := filepath.Join(a.cfg.StorePath, "projects", project, string(stage)+".env.age")

	// Read encrypted file
	encrypted, err := os.ReadFile(envPath)
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
	var envFile models.EnvFile
	if err := yaml.Unmarshal(plaintext, &envFile); err != nil {
		return nil, fmt.Errorf("failed to parse env file: %w", err)
	}

	return &envFile, nil
}

// saveEnvFile encrypts and saves an env file
func (a *Action) saveEnvFile(ctx context.Context, envFile *models.EnvFile) error {
	// Serialize to YAML
	data, err := yaml.Marshal(envFile)
	if err != nil {
		return err
	}

	// Get recipients for this stage
	recipients, err := a.getStageRecipients(envFile.Stage)
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
	envDir := filepath.Join(a.cfg.StorePath, "projects", envFile.Project)
	if err := os.MkdirAll(envDir, 0700); err != nil {
		return err
	}

	// Write file
	envPath := filepath.Join(envDir, string(envFile.Stage)+".env.age")
	return os.WriteFile(envPath, encrypted, 0600)
}

// getStageRecipients returns public keys of users who can access a stage
func (a *Action) getStageRecipients(stage models.Stage) ([]string, error) {
	userList, err := a.loadUsers()
	if err != nil {
		return nil, err
	}

	var keys []string
	for _, user := range userList.Users {
		if user.PublicKey == "" {
			continue
		}
		for _, role := range user.Roles {
			if role.CanAccessStage(stage) {
				keys = append(keys, user.PublicKey)
				break
			}
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

// parseDotEnvFile parses a .env file
func parseDotEnvFile(path string) ([]models.EnvVar, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var vars []models.EnvVar
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

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

		vars = append(vars, models.EnvVar{
			Key:      key,
			Value:    value,
			IsSecret: true,
		})
	}

	return vars, scanner.Err()
}

// saveEnvFileWithPermissions encrypts and saves an env file using per-secret permissions
func (a *Action) saveEnvFileWithPermissions(ctx context.Context, envFile *models.EnvFile) error {
	// Serialize to YAML
	data, err := yaml.Marshal(envFile)
	if err != nil {
		return err
	}

	// Get recipients from permissions
	var recipients []string
	if envFile.Permissions != nil && !envFile.Permissions.UseRoleBasedAccess && envFile.Permissions.Count() > 0 {
		// Use per-secret permissions
		for _, perm := range envFile.Permissions.Recipients {
			if perm.PublicKey != "" {
				recipients = append(recipients, perm.PublicKey)
			}
		}
	} else {
		// Fall back to stage-based recipients
		recipients, err = a.getStageRecipients(envFile.Stage)
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
	envDir := filepath.Join(a.cfg.StorePath, "projects", envFile.Project)
	if err := os.MkdirAll(envDir, 0700); err != nil {
		return err
	}

	// Write file
	envPath := filepath.Join(envDir, string(envFile.Stage)+".env.age")
	return os.WriteFile(envPath, encrypted, 0600)
}
