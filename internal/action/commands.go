package action

import (
	"github.com/urfave/cli/v2"
)

// GetCommands returns all CLI commands
func (a *Action) GetCommands() []*cli.Command {
	return []*cli.Command{
		// Setup and initialization
		{
			Name:   "init",
			Usage:  "Initialize a new passbook store",
			Action: a.Init,
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "remote", Aliases: []string{"r"}, Usage: "Git remote URL"},
				&cli.StringFlag{Name: "domain", Aliases: []string{"d"}, Usage: "Allowed email domain"},
				&cli.StringFlag{Name: "org", Aliases: []string{"o"}, Usage: "Organization name"},
			},
		},
		{
			Name:      "clone",
			Usage:     "Clone an existing passbook store",
			ArgsUsage: "GIT_URL",
			Action:    a.Clone,
		},
		{
			Name:   "setup",
			Usage:  "Interactive setup wizard",
			Action: a.Setup,
		},

		// Auth commands
		{
			Name:   "login",
			Usage:  "Login with email (magic link)",
			Action: a.Login,
		},
		{
			Name:   "logout",
			Usage:  "Logout and clear session",
			Action: a.Logout,
		},
		{
			Name:   "whoami",
			Usage:  "Show current user",
			Action: a.WhoAmI,
		},

		// Credential commands
		{
			Name:    "cred",
			Aliases: []string{"credentials", "c"},
			Usage:   "Manage website credentials",
			Subcommands: []*cli.Command{
				{
					Name:   "list",
					Usage:  "List all credentials",
					Action: a.CredList,
					Flags: []cli.Flag{
						&cli.StringFlag{Name: "website", Aliases: []string{"w"}, Usage: "Filter by website"},
						&cli.StringSliceFlag{Name: "tag", Aliases: []string{"t"}, Usage: "Filter by tag"},
					},
				},
				{
					Name:      "show",
					Usage:     "Show a credential",
					ArgsUsage: "WEBSITE/NAME",
					Action:    a.CredShow,
					Flags: []cli.Flag{
						&cli.BoolFlag{Name: "clip", Aliases: []string{"c"}, Usage: "Copy password to clipboard"},
						&cli.BoolFlag{Name: "password", Aliases: []string{"p"}, Usage: "Show only password"},
					},
				},
				{
					Name:      "add",
					Usage:     "Add a new credential",
					ArgsUsage: "WEBSITE",
					Action:    a.CredAdd,
					Flags: []cli.Flag{
						&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Account name"},
						&cli.StringFlag{Name: "username", Aliases: []string{"u"}, Usage: "Username"},
						&cli.StringFlag{Name: "password", Aliases: []string{"p"}, Usage: "Password (or use --generate)"},
						&cli.BoolFlag{Name: "generate", Aliases: []string{"g"}, Usage: "Generate password"},
						&cli.IntFlag{Name: "length", Aliases: []string{"l"}, Value: 24, Usage: "Generated password length"},
					},
				},
				{
					Name:      "edit",
					Usage:     "Edit a credential",
					ArgsUsage: "WEBSITE/NAME",
					Action:    a.CredEdit,
				},
				{
					Name:      "rm",
					Aliases:   []string{"remove", "delete"},
					Usage:     "Remove a credential",
					ArgsUsage: "WEBSITE/NAME",
					Action:    a.CredRemove,
					Flags: []cli.Flag{
						&cli.BoolFlag{Name: "force", Aliases: []string{"f"}, Usage: "Skip confirmation"},
					},
				},
				{
					Name:      "copy",
					Aliases:   []string{"cp"},
					Usage:     "Copy password to clipboard",
					ArgsUsage: "WEBSITE/NAME",
					Action:    a.CredCopy,
				},
				// Access management
				{
					Name:  "access",
					Usage: "Manage access to a credential",
					Subcommands: []*cli.Command{
						{
							Name:      "list",
							Usage:     "List who has access to a credential",
							ArgsUsage: "WEBSITE/NAME",
							Action:    a.CredAccessList,
						},
						{
							Name:      "grant",
							Usage:     "Grant access to a credential",
							ArgsUsage: "WEBSITE/NAME EMAIL",
							Action:    a.CredAccessGrant,
							Flags: []cli.Flag{
								&cli.StringFlag{Name: "level", Aliases: []string{"l"}, Value: "read", Usage: "Access level: read or write"},
							},
						},
						{
							Name:      "revoke",
							Usage:     "Revoke access from a credential",
							ArgsUsage: "WEBSITE/NAME EMAIL",
							Action:    a.CredAccessRevoke,
						},
					},
				},
			},
		},

		// Environment commands
		{
			Name:    "env",
			Aliases: []string{"e"},
			Usage:   "Manage environment variables",
			Subcommands: []*cli.Command{
				{
					Name:   "list",
					Usage:  "List projects or stages",
					Action: a.EnvList,
					Flags: []cli.Flag{
						&cli.StringFlag{Name: "project", Aliases: []string{"p"}, Usage: "Filter by project"},
					},
				},
				{
					Name:      "show",
					Usage:     "Show environment variables",
					ArgsUsage: "PROJECT STAGE",
					Action:    a.EnvShow,
					Flags: []cli.Flag{
						&cli.BoolFlag{Name: "export", Usage: "Format as export statements"},
						&cli.BoolFlag{Name: "dotenv", Usage: "Format as .env file"},
					},
				},
				{
					Name:      "set",
					Usage:     "Set an environment variable",
					ArgsUsage: "PROJECT STAGE KEY=VALUE",
					Action:    a.EnvSet,
					Flags: []cli.Flag{
						&cli.BoolFlag{Name: "secret", Aliases: []string{"s"}, Value: true, Usage: "Mark as secret"},
					},
				},
				{
					Name:      "rm",
					Aliases:   []string{"remove", "delete"},
					Usage:     "Remove an environment variable",
					ArgsUsage: "PROJECT STAGE KEY",
					Action:    a.EnvRemove,
				},
				{
					Name:      "export",
					Usage:     "Export as .env file",
					ArgsUsage: "PROJECT STAGE",
					Action:    a.EnvExport,
					Flags: []cli.Flag{
						&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Output file (default: stdout)"},
						&cli.StringFlag{Name: "format", Aliases: []string{"f"}, Value: "dotenv", Usage: "Format: dotenv, export, json"},
					},
				},
				{
					Name:      "import",
					Usage:     "Import from .env file",
					ArgsUsage: "PROJECT STAGE FILE",
					Action:    a.EnvImport,
				},
				{
					Name:      "exec",
					Usage:     "Run command with environment variables",
					ArgsUsage: "PROJECT STAGE -- COMMAND [ARGS...]",
					Action:    a.EnvExec,
				},
				// Access management
				{
					Name:  "access",
					Usage: "Manage access to environment variables",
					Subcommands: []*cli.Command{
						{
							Name:      "list",
							Usage:     "List who has access to an environment",
							ArgsUsage: "PROJECT STAGE",
							Action:    a.EnvAccessList,
						},
						{
							Name:      "grant",
							Usage:     "Grant access to an environment",
							ArgsUsage: "PROJECT STAGE EMAIL",
							Action:    a.EnvAccessGrant,
							Flags: []cli.Flag{
								&cli.StringFlag{Name: "level", Aliases: []string{"l"}, Value: "read", Usage: "Access level: read or write"},
							},
						},
						{
							Name:      "revoke",
							Usage:     "Revoke access from an environment",
							ArgsUsage: "PROJECT STAGE EMAIL",
							Action:    a.EnvAccessRevoke,
						},
					},
				},
			},
		},

		// Project commands
		{
			Name:  "project",
			Usage: "Manage projects",
			Subcommands: []*cli.Command{
				{
					Name:   "list",
					Usage:  "List all projects",
					Action: a.ProjectList,
				},
				{
					Name:      "create",
					Usage:     "Create a new project",
					ArgsUsage: "NAME",
					Action:    a.ProjectCreate,
					Flags: []cli.Flag{
						&cli.StringFlag{Name: "description", Aliases: []string{"d"}, Usage: "Project description"},
						&cli.StringSliceFlag{Name: "stage", Aliases: []string{"s"}, Usage: "Stages (default: dev,staging,prod)"},
					},
				},
				{
					Name:      "rm",
					Aliases:   []string{"remove", "delete"},
					Usage:     "Remove a project",
					ArgsUsage: "NAME",
					Action:    a.ProjectRemove,
					Flags: []cli.Flag{
						&cli.BoolFlag{Name: "force", Aliases: []string{"f"}, Usage: "Skip confirmation"},
					},
				},
			},
		},

		// Team commands
		{
			Name:  "team",
			Usage: "Manage team members",
			Subcommands: []*cli.Command{
				{
					Name:    "list",
					Aliases: []string{"members"},
					Usage:   "List team members",
					Action:  a.TeamList,
				},
				{
					Name:      "invite",
					Usage:     "Invite a new member",
					ArgsUsage: "EMAIL",
					Action:    a.TeamInvite,
					Flags: []cli.Flag{
						&cli.StringSliceFlag{Name: "role", Aliases: []string{"r"}, Usage: "Roles to assign (dev, staging-access, prod-access, admin)"},
					},
				},
				{
					Name:      "revoke",
					Usage:     "Revoke a member's access",
					ArgsUsage: "EMAIL",
					Action:    a.TeamRevoke,
					Flags: []cli.Flag{
						&cli.BoolFlag{Name: "force", Aliases: []string{"f"}, Usage: "Skip confirmation"},
					},
				},
				{
					Name:      "grant",
					Usage:     "Grant a role to a member",
					ArgsUsage: "EMAIL ROLE",
					Action:    a.TeamGrant,
				},
				{
					Name:      "roles",
					Usage:     "Show a member's roles",
					ArgsUsage: "EMAIL",
					Action:    a.TeamRoles,
				},
			},
		},

		// Sync commands
		{
			Name:   "sync",
			Usage:  "Sync with git remote",
			Action: a.Sync,
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: "push", Usage: "Only push"},
				&cli.BoolFlag{Name: "pull", Usage: "Only pull"},
			},
		},
	}
}
