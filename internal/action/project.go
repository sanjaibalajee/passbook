package action

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"passbook/internal/models"
	"passbook/pkg/termio"
)

// Project represents project metadata
type Project struct {
	Name        string         `yaml:"name"`
	Description string         `yaml:"description,omitempty"`
	Stages      []models.Stage `yaml:"stages"`
	CreatedBy   string         `yaml:"created_by"`
	CreatedAt   time.Time      `yaml:"created_at"`
}

// ProjectList lists all projects
func (a *Action) ProjectList(c *cli.Context) error {
	projectsDir := filepath.Join(a.cfg.StorePath, "projects")

	// Check if projects directory exists
	if _, err := os.Stat(projectsDir); os.IsNotExist(err) {
		fmt.Println("No projects found.")
		fmt.Println("\nCreate one with: passbook project create myapp")
		return nil
	}

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
		if !entry.IsDir() {
			continue
		}

		projectDir := filepath.Join(projectsDir, entry.Name())

		// Try to load project metadata
		project, _ := loadProject(projectDir)

		// Count stages
		var stages []string
		stageEntries, _ := os.ReadDir(projectDir)
		for _, se := range stageEntries {
			if strings.HasSuffix(se.Name(), ".env.age") {
				stage := strings.TrimSuffix(se.Name(), ".env.age")
				stages = append(stages, stage)
			}
		}

		fmt.Printf("  %s\n", entry.Name())
		if project != nil && project.Description != "" {
			fmt.Printf("    Description: %s\n", project.Description)
		}
		if len(stages) > 0 {
			fmt.Printf("    Stages: %s\n", strings.Join(stages, ", "))
		}
	}

	return nil
}

// ProjectCreate creates a new project
func (a *Action) ProjectCreate(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("usage: passbook project create NAME")
	}

	name := c.Args().First()
	description := c.String("description")
	stageStrs := c.StringSlice("stage")

	if len(stageStrs) == 0 {
		stageStrs = []string{"dev", "staging", "prod"}
	}

	// Validate stages
	var stages []models.Stage
	for _, s := range stageStrs {
		stage := models.Stage(s)
		if !stage.IsValid() {
			return fmt.Errorf("invalid stage: %s (valid: dev, staging, prod)", s)
		}
		stages = append(stages, stage)
	}

	// Check permission (prod-access or admin can create projects)
	currentUser, err := a.getCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	canCreate := false
	for _, role := range currentUser.Roles {
		if role == models.RoleAdmin || role == models.RoleProdAccess {
			canCreate = true
			break
		}
	}
	if !canCreate {
		return fmt.Errorf("permission denied: only prod-access or admin can create projects")
	}

	// Check if project already exists
	projectDir := filepath.Join(a.cfg.StorePath, "projects", name)
	if _, err := os.Stat(projectDir); err == nil {
		return fmt.Errorf("project %s already exists", name)
	}

	// Create project directory
	if err := os.MkdirAll(projectDir, 0700); err != nil {
		return fmt.Errorf("failed to create project directory: %w", err)
	}

	// Create project metadata file
	project := &Project{
		Name:        name,
		Description: description,
		Stages:      stages,
		CreatedBy:   currentUser.Email,
		CreatedAt:   time.Now(),
	}

	projectData, err := yaml.Marshal(project)
	if err != nil {
		return fmt.Errorf("failed to marshal project: %w", err)
	}

	projectFile := filepath.Join(projectDir, ".passbook-project")
	if err := os.WriteFile(projectFile, projectData, 0600); err != nil {
		return fmt.Errorf("failed to write project file: %w", err)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Create project: %s", name)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("✓ Created project: %s\n", name)
	fmt.Printf("  Stages: %s\n", strings.Join(stageStrs, ", "))
	fmt.Println("\nAdd environment variables with:")
	fmt.Printf("  passbook env set %s dev DATABASE_URL=...\n", name)

	return nil
}

// ProjectRemove removes a project
func (a *Action) ProjectRemove(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("usage: passbook project rm NAME")
	}

	name := c.Args().First()
	force := c.Bool("force")

	// Check permission (admin only can delete projects)
	currentUser, err := a.getCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	if !currentUser.IsAdmin() {
		return fmt.Errorf("permission denied: only admins can delete projects")
	}

	// Check if project exists
	projectDir := filepath.Join(a.cfg.StorePath, "projects", name)
	if _, err := os.Stat(projectDir); os.IsNotExist(err) {
		return fmt.Errorf("project %s not found", name)
	}

	// Count env files to show what will be deleted
	envCount := 0
	entries, _ := os.ReadDir(projectDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".env.age") {
			envCount++
		}
	}

	// Confirm
	if !force {
		msg := fmt.Sprintf("Delete project %s", name)
		if envCount > 0 {
			msg += fmt.Sprintf(" (%d environment files)", envCount)
		}
		msg += "?"

		confirm, err := termio.Confirm(msg, false)
		if err != nil {
			return err
		}
		if !confirm {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	// Delete project directory
	if err := os.RemoveAll(projectDir); err != nil {
		return fmt.Errorf("failed to delete project: %w", err)
	}

	// Git commit
	if err := a.GitCommitAndSync(fmt.Sprintf("Delete project: %s", name)); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("✓ Deleted project: %s\n", name)

	return nil
}

// loadProject loads project metadata from a directory
func loadProject(projectDir string) (*Project, error) {
	projectFile := filepath.Join(projectDir, ".passbook-project")
	data, err := os.ReadFile(projectFile)
	if err != nil {
		return nil, err
	}

	var project Project
	if err := yaml.Unmarshal(data, &project); err != nil {
		return nil, err
	}

	return &project, nil
}
