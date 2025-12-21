package store

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"passbook/internal/models"
)

const (
	projectMetaFile = ".passbook-project"
)

// ListProjects returns all projects
func (s *Store) ListProjects(ctx context.Context) ([]models.Project, error) {
	dirs, err := s.storage.ListDirs(ctx, projectsDir)
	if err != nil {
		return nil, err
	}

	var projects []models.Project
	for _, dir := range dirs {
		project, err := s.GetProject(ctx, dir)
		if err != nil {
			// Create a basic project entry if metadata doesn't exist
			projects = append(projects, models.Project{
				Name:   dir,
				Stages: models.AllStages(),
			})
			continue
		}
		projects = append(projects, *project)
	}

	return projects, nil
}

// GetProject returns a project by name
func (s *Store) GetProject(ctx context.Context, name string) (*models.Project, error) {
	path := filepath.Join(projectsDir, name, projectMetaFile)

	data, err := s.storage.Get(ctx, path)
	if err != nil {
		return nil, ErrNotFound
	}

	var project models.Project
	if err := yaml.Unmarshal(data, &project); err != nil {
		return nil, fmt.Errorf("failed to parse project: %w", err)
	}

	return &project, nil
}

// CreateProject creates a new project
func (s *Store) CreateProject(ctx context.Context, name, description, createdBy string, stages []models.Stage) (*models.Project, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}

	// Validate name (URL-safe)
	for _, c := range name {
		if !isURLSafe(c) {
			return nil, fmt.Errorf("%w: name must be URL-safe (a-z, 0-9, -, _)", ErrInvalidInput)
		}
	}

	// Check if exists
	path := filepath.Join(projectsDir, name, projectMetaFile)
	if s.storage.Exists(ctx, path) {
		return nil, ErrAlreadyExists
	}

	// Default stages
	if len(stages) == 0 {
		stages = models.AllStages()
	}

	// Validate stages
	for _, stage := range stages {
		if !stage.IsValid() {
			return nil, fmt.Errorf("%w: invalid stage %s", ErrInvalidInput, stage)
		}
	}

	project := models.NewProject(name, description, createdBy)
	project.Stages = stages

	// Save project metadata
	data, err := yaml.Marshal(project)
	if err != nil {
		return nil, err
	}

	if err := s.storage.Set(ctx, path, data); err != nil {
		return nil, err
	}

	return project, nil
}

// UpdateProject updates a project
func (s *Store) UpdateProject(ctx context.Context, name string, updateFn func(*models.Project)) error {
	project, err := s.GetProject(ctx, name)
	if err != nil {
		return err
	}

	updateFn(project)

	path := filepath.Join(projectsDir, name, projectMetaFile)
	data, err := yaml.Marshal(project)
	if err != nil {
		return err
	}

	return s.storage.Set(ctx, path, data)
}

// DeleteProject removes a project and all its environment files
func (s *Store) DeleteProject(ctx context.Context, name string) error {
	projectPath := filepath.Join(projectsDir, name)

	// List all files in project
	files, err := s.storage.List(ctx, projectPath)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		return ErrNotFound
	}

	// Delete all files
	for _, file := range files {
		if err := s.storage.Delete(ctx, file); err != nil {
			return err
		}
	}

	return nil
}

// ProjectExists checks if a project exists
func (s *Store) ProjectExists(ctx context.Context, name string) bool {
	path := filepath.Join(projectsDir, name, projectMetaFile)
	return s.storage.Exists(ctx, path)
}

// GetProjectWithStages returns a project with its available stages
func (s *Store) GetProjectWithStages(ctx context.Context, name string) (*models.Project, []models.Stage, error) {
	project, err := s.GetProject(ctx, name)
	if err != nil {
		// Try to get just stages
		stages, stageErr := s.ListEnvStages(ctx, name)
		if stageErr != nil {
			return nil, nil, ErrNotFound
		}
		// Create a basic project
		project = &models.Project{
			Name:      name,
			Stages:    stages,
			CreatedAt: time.Time{},
		}
		return project, stages, nil
	}

	stages, err := s.ListEnvStages(ctx, name)
	if err != nil {
		stages = []models.Stage{}
	}

	return project, stages, nil
}

// isURLSafe checks if a character is URL-safe
func isURLSafe(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_'
}
