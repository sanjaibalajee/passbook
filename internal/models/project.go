package models

import (
	"fmt"
	"time"
)

// Project represents an application/service that has env vars
type Project struct {
	// Project name (used in paths, must be URL-safe)
	Name string `json:"name" yaml:"name"`

	// Human-readable description
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Available stages for this project
	Stages []Stage `json:"stages" yaml:"stages"`

	// Who created this project
	CreatedBy string `json:"created_by" yaml:"created_by"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
}

// Path returns the storage path for this project
func (p *Project) Path() string {
	return fmt.Sprintf("projects/%s", p.Name)
}

// MetadataPath returns the path to the project metadata file
func (p *Project) MetadataPath() string {
	return fmt.Sprintf("projects/%s/.passbook-project", p.Name)
}

// HasStage checks if project has the given stage
func (p *Project) HasStage(stage Stage) bool {
	for _, s := range p.Stages {
		if s == stage {
			return true
		}
	}
	return false
}

// NewProject creates a new project with default stages
func NewProject(name, description, createdBy string) *Project {
	return &Project{
		Name:        name,
		Description: description,
		Stages:      AllStages(), // Default to all stages
		CreatedBy:   createdBy,
		CreatedAt:   time.Now(),
	}
}
