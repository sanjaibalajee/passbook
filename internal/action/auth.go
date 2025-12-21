package action

import (
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"

	"passbook/internal/auth"
	"passbook/pkg/termio"
)

// Login authenticates the user via magic link
func (a *Action) Login(c *cli.Context) error {
	fmt.Println("Login to Passbook")
	fmt.Println("-----------------")

	// Check if already logged in
	if a.auth != nil && a.auth.IsLoggedIn() {
		session, _ := a.auth.GetCurrentSession()
		fmt.Printf("Already logged in as %s\n", session.Email)
		confirm, err := termio.Confirm("Do you want to log in as a different user?", false)
		if err != nil {
			return err
		}
		if !confirm {
			return nil
		}
		// Logout first
		_ = a.auth.Logout()
	}

	// Prompt for email
	email, err := termio.Prompt("Email: ")
	if err != nil {
		return err
	}
	email = strings.TrimSpace(strings.ToLower(email))

	if email == "" {
		return fmt.Errorf("email is required")
	}

	// Validate email format
	if !strings.Contains(email, "@") {
		return fmt.Errorf("invalid email format")
	}

	// Check domain restriction
	if !a.cfg.IsAllowedEmail(email) {
		return fmt.Errorf("email domain not allowed (must be @%s)", a.cfg.Org.AllowedDomain)
	}

	fmt.Printf("\nSending verification code to %s...\n", email)

	// Request login (sends verification code)
	if err := a.auth.RequestLogin(email); err != nil {
		if err == auth.ErrInvalidDomain {
			return fmt.Errorf("email domain not allowed")
		}
		return fmt.Errorf("failed to send verification code: %w", err)
	}

	// Prompt for verification code
	fmt.Println("\nCheck your email for the verification code.")
	code, err := termio.Prompt("Verification code: ")
	if err != nil {
		return err
	}
	code = strings.TrimSpace(strings.ToUpper(code))

	if code == "" {
		return fmt.Errorf("verification code is required")
	}

	// Verify the code
	session, err := a.auth.VerifyLogin(email, code)
	if err != nil {
		if err == auth.ErrTokenInvalid {
			return fmt.Errorf("invalid verification code")
		}
		if err == auth.ErrTokenExpired {
			return fmt.Errorf("verification code expired")
		}
		return fmt.Errorf("verification failed: %w", err)
	}

	fmt.Printf("\n✓ Logged in as %s\n", session.Email)
	return nil
}

// Logout clears the user's session
func (a *Action) Logout(c *cli.Context) error {
	// Get current user from identity (consistent with whoami)
	user, err := a.getCurrentUser()
	if err != nil {
		fmt.Println("Not logged in (no matching user found)")
		return nil
	}

	// Clear any session data
	if a.auth != nil {
		_ = a.auth.Logout()
	}

	fmt.Printf("✓ Cleared session for %s\n", user.Email)
	fmt.Println()
	fmt.Println("Note: Your identity key is still active.")
	fmt.Println("To switch users, configure a different identity file.")
	return nil
}

// WhoAmI shows the current user
func (a *Action) WhoAmI(c *cli.Context) error {
	fmt.Println("Current User")
	fmt.Println("============")

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

	// Fall back to session info if available
	if a.auth != nil {
		session, err := a.auth.GetCurrentSession()
		if err == nil {
			fmt.Printf("Email:      %s\n", session.Email)
			fmt.Printf("Logged in:  %s\n", session.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("Expires:    %s\n", session.ExpiresAt.Format("2006-01-02 15:04:05"))
			return nil
		}
	}

	// Just show identity info
	if a.cfg.Identity.PublicKey != "" {
		key := a.cfg.Identity.PublicKey
		if len(key) > 30 {
			key = key[:30] + "..."
		}
		fmt.Printf("Public Key: %s\n", key)
		fmt.Println("\nNote: Run 'passbook login' to associate with an email")
		return nil
	}

	fmt.Println("Not configured")
	fmt.Println("\nRun 'passbook init' or 'passbook clone' to get started")
	return nil
}
