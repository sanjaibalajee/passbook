package action

import (
	"fmt"

	"github.com/urfave/cli/v2"

	"passbook/internal/auth"
)

// WhoAmI shows the current user
func (a *Action) WhoAmI(c *cli.Context) error {
	fmt.Println("Current User")
	fmt.Println("============")

	// Check GitHub auth status
	githubAuth := auth.NewGitHubAuth(a.cfg.ConfigDir, a.cfg.Org.AllowedDomain)
	if session, err := githubAuth.LoadSession(); err == nil && session != nil {
		fmt.Printf("GitHub:     @%s (%s)\n", session.GitHubLogin, session.Email)
	}

	// Try to get user from team list (by public key)
	user, err := a.getCurrentUser()
	if err == nil {
		fmt.Printf("Email:      %s\n", user.Email)

		// Show roles
		roles := ""
		for i, r := range user.Roles {
			if i > 0 {
				roles += ", "
			}
			roles += string(r)
		}
		fmt.Printf("Roles:      %s\n", roles)

		if user.IsAdmin() {
			fmt.Printf("Status:     Admin\n")
		}

		// Show public key
		key := user.PublicKey
		if len(key) > 30 {
			key = key[:30] + "..."
		}
		fmt.Printf("Public Key: %s\n", key)

		return nil
	}

	// Just show identity info
	if a.cfg.Identity.PublicKey != "" {
		key := a.cfg.Identity.PublicKey
		if len(key) > 30 {
			key = key[:30] + "..."
		}
		fmt.Printf("Public Key: %s\n", key)
		fmt.Println("\nYour key is not in the team yet.")
		fmt.Println("Ask an admin to invite you, or run 'passbook init' to start a new store.")
		return nil
	}

	fmt.Println("Not configured")
	fmt.Println("\nRun 'passbook init' or 'passbook clone' to get started")
	return nil
}

// Login authenticates with GitHub
func (a *Action) Login(c *cli.Context) error {
	githubAuth := auth.NewGitHubAuth(a.cfg.ConfigDir, a.cfg.Org.AllowedDomain)

	session, err := githubAuth.Authenticate()
	if err != nil {
		switch err {
		case auth.ErrEmailNotVerified:
			return fmt.Errorf("your GitHub email is not verified. Please verify your email at github.com")
		case auth.ErrEmailDomainMismatch:
			return fmt.Errorf("no verified email matching domain @%s found in your GitHub account", a.cfg.Org.AllowedDomain)
		case auth.ErrAccessDenied:
			return fmt.Errorf("authentication was denied")
		case auth.ErrExpiredToken:
			return fmt.Errorf("authentication timed out. Please try again")
		default:
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	fmt.Println("Logged in successfully!")
	fmt.Println()
	fmt.Print(session.PrettyPrint())

	// Update user config with email if not set
	if a.cfg.Identity.Email == "" {
		a.cfg.Identity.Email = session.Email
		if err := a.cfg.Save(); err != nil {
			fmt.Printf("Warning: failed to save email to config: %v\n", err)
		}
	}

	return nil
}

// Logout clears the GitHub session
func (a *Action) Logout(c *cli.Context) error {
	githubAuth := auth.NewGitHubAuth(a.cfg.ConfigDir, a.cfg.Org.AllowedDomain)

	if err := githubAuth.ClearSession(); err != nil {
		return fmt.Errorf("failed to logout: %w", err)
	}

	fmt.Println("Logged out successfully")
	return nil
}

// AuthStatus shows authentication status
func (a *Action) AuthStatus(c *cli.Context) error {
	githubAuth := auth.NewGitHubAuth(a.cfg.ConfigDir, a.cfg.Org.AllowedDomain)

	session, err := githubAuth.LoadSession()
	if err != nil {
		fmt.Println("Not authenticated")
		fmt.Println()
		fmt.Println("Run 'passbook login' to authenticate with GitHub")
		return nil
	}

	// Verify session is still valid
	if !githubAuth.IsAuthenticated() {
		fmt.Println("Session expired")
		fmt.Println()
		fmt.Println("Run 'passbook login' to re-authenticate")
		return nil
	}

	fmt.Println("Authenticated")
	fmt.Println()
	fmt.Print(session.PrettyPrint())

	return nil
}
