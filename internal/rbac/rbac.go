package rbac

import (
	"passbook/internal/models"
)

// Permission represents an action that can be performed
type Permission string

const (
	// Credential permissions
	PermCredentialsRead  Permission = "credentials:read"
	PermCredentialsWrite Permission = "credentials:write"

	// Environment permissions (per stage)
	PermEnvDevRead      Permission = "env:dev:read"
	PermEnvDevWrite     Permission = "env:dev:write"
	PermEnvStagingRead  Permission = "env:staging:read"
	PermEnvStagingWrite Permission = "env:staging:write"
	PermEnvProdRead     Permission = "env:prod:read"
	PermEnvProdWrite    Permission = "env:prod:write"

	// Team permissions
	PermTeamList   Permission = "team:list"
	PermTeamInvite Permission = "team:invite"
	PermTeamRevoke Permission = "team:revoke"
	PermTeamGrant  Permission = "team:grant"

	// Project permissions
	PermProjectList   Permission = "project:list"
	PermProjectCreate Permission = "project:create"
	PermProjectDelete Permission = "project:delete"
)

// RolePermissions defines what each role can do
var RolePermissions = map[models.Role][]Permission{
	models.RoleDev: {
		PermCredentialsRead,
		PermEnvDevRead,
		PermEnvDevWrite,
		PermTeamList,
		PermProjectList,
	},
	models.RoleStagingAccess: {
		PermCredentialsRead,
		PermEnvDevRead,
		PermEnvDevWrite,
		PermEnvStagingRead,
		PermEnvStagingWrite,
		PermTeamList,
		PermProjectList,
	},
	models.RoleProdAccess: {
		PermCredentialsRead,
		PermCredentialsWrite,
		PermEnvDevRead,
		PermEnvDevWrite,
		PermEnvStagingRead,
		PermEnvStagingWrite,
		PermEnvProdRead,
		PermEnvProdWrite,
		PermTeamList,
		PermProjectList,
		PermProjectCreate,
	},
	models.RoleAdmin: {
		// All permissions
		PermCredentialsRead,
		PermCredentialsWrite,
		PermEnvDevRead,
		PermEnvDevWrite,
		PermEnvStagingRead,
		PermEnvStagingWrite,
		PermEnvProdRead,
		PermEnvProdWrite,
		PermTeamList,
		PermTeamInvite,
		PermTeamRevoke,
		PermTeamGrant,
		PermProjectList,
		PermProjectCreate,
		PermProjectDelete,
	},
}

// Engine evaluates permissions
type Engine struct {
	userStore UserStore
}

// UserStore interface for user operations
type UserStore interface {
	ListUsers() ([]models.User, error)
	GetUser(email string) (*models.User, error)
}

// NewEngine creates an RBAC engine
func NewEngine(store UserStore) *Engine {
	return &Engine{userStore: store}
}

// Can checks if user has permission
func (e *Engine) Can(user *models.User, perm Permission) bool {
	if user == nil {
		return false
	}

	for _, role := range user.Roles {
		perms, ok := RolePermissions[role]
		if !ok {
			continue
		}
		for _, p := range perms {
			if p == perm {
				return true
			}
		}
	}
	return false
}

// CanAccessStage checks if user can access a specific stage
func (e *Engine) CanAccessStage(user *models.User, stage models.Stage, write bool) bool {
	if user == nil {
		return false
	}

	var perm Permission
	switch stage {
	case models.StageDev:
		if write {
			perm = PermEnvDevWrite
		} else {
			perm = PermEnvDevRead
		}
	case models.StageStaging:
		if write {
			perm = PermEnvStagingWrite
		} else {
			perm = PermEnvStagingRead
		}
	case models.StageProd:
		if write {
			perm = PermEnvProdWrite
		} else {
			perm = PermEnvProdRead
		}
	default:
		return false
	}

	return e.Can(user, perm)
}

// CanWriteCredentials checks if user can modify credentials
func (e *Engine) CanWriteCredentials(user *models.User) bool {
	return e.Can(user, PermCredentialsWrite)
}

// CanManageTeam checks if user can manage team members
func (e *Engine) CanManageTeam(user *models.User) bool {
	return e.Can(user, PermTeamInvite)
}

// IsAdmin checks if user is an admin
func (e *Engine) IsAdmin(user *models.User) bool {
	if user == nil {
		return false
	}
	return user.HasRole(models.RoleAdmin)
}

// GetStageRecipients returns public keys of users who can access a stage
func (e *Engine) GetStageRecipients(stage models.Stage) ([]string, error) {
	if e.userStore == nil {
		return nil, nil
	}

	users, err := e.userStore.ListUsers()
	if err != nil {
		return nil, err
	}

	var keys []string
	for _, user := range users {
		if e.CanAccessStage(&user, stage, false) {
			keys = append(keys, user.PublicKey)
		}
	}
	return keys, nil
}

// GetAllRecipients returns public keys of all users
func (e *Engine) GetAllRecipients() ([]string, error) {
	if e.userStore == nil {
		return nil, nil
	}

	users, err := e.userStore.ListUsers()
	if err != nil {
		return nil, err
	}

	var keys []string
	for _, user := range users {
		if user.PublicKey != "" {
			keys = append(keys, user.PublicKey)
		}
	}
	return keys, nil
}

// GetStagePermission returns the read permission for a stage
func GetStagePermission(stage models.Stage, write bool) Permission {
	switch stage {
	case models.StageDev:
		if write {
			return PermEnvDevWrite
		}
		return PermEnvDevRead
	case models.StageStaging:
		if write {
			return PermEnvStagingWrite
		}
		return PermEnvStagingRead
	case models.StageProd:
		if write {
			return PermEnvProdWrite
		}
		return PermEnvProdRead
	default:
		return ""
	}
}

// AllPermissions returns all defined permissions
func AllPermissions() []Permission {
	return []Permission{
		PermCredentialsRead,
		PermCredentialsWrite,
		PermEnvDevRead,
		PermEnvDevWrite,
		PermEnvStagingRead,
		PermEnvStagingWrite,
		PermEnvProdRead,
		PermEnvProdWrite,
		PermTeamList,
		PermTeamInvite,
		PermTeamRevoke,
		PermTeamGrant,
		PermProjectList,
		PermProjectCreate,
		PermProjectDelete,
	}
}
