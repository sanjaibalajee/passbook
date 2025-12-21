package models

// Role represents a user's access level
type Role string

const (
	// RoleDev can only access dev environment
	RoleDev Role = "dev"

	// RoleStagingAccess can access dev + staging
	RoleStagingAccess Role = "staging-access"

	// RoleProdAccess can access all stages
	RoleProdAccess Role = "prod-access"

	// RoleAdmin has full access + team management
	RoleAdmin Role = "admin"
)

// Stage represents a deployment environment
type Stage string

const (
	StageDev     Stage = "dev"
	StageStaging Stage = "staging"
	StageProd    Stage = "prod"
)

// AllStages returns all valid stages
func AllStages() []Stage {
	return []Stage{StageDev, StageStaging, StageProd}
}

// AllRoles returns all valid roles
func AllRoles() []Role {
	return []Role{RoleDev, RoleStagingAccess, RoleProdAccess, RoleAdmin}
}

// CanAccessStage checks if this role can access the given stage
func (r Role) CanAccessStage(stage Stage) bool {
	switch r {
	case RoleAdmin, RoleProdAccess:
		return true // Can access all stages
	case RoleStagingAccess:
		return stage == StageDev || stage == StageStaging
	case RoleDev:
		return stage == StageDev
	default:
		return false
	}
}

// CanManageTeam checks if this role can invite/remove members
func (r Role) CanManageTeam() bool {
	return r == RoleAdmin
}

// CanWriteCredentials checks if this role can modify credentials
func (r Role) CanWriteCredentials() bool {
	return r == RoleAdmin || r == RoleProdAccess
}

// RoleHierarchy defines role ordering (higher index = more permissions)
var RoleHierarchy = []Role{RoleDev, RoleStagingAccess, RoleProdAccess, RoleAdmin}

// IsValid checks if the role is valid
func (r Role) IsValid() bool {
	switch r {
	case RoleDev, RoleStagingAccess, RoleProdAccess, RoleAdmin:
		return true
	default:
		return false
	}
}

// IsValid checks if the stage is valid
func (s Stage) IsValid() bool {
	switch s {
	case StageDev, StageStaging, StageProd:
		return true
	default:
		return false
	}
}
