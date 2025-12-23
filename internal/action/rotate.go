package action

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/urfave/cli/v2"

	"passbook/internal/audit"
	"passbook/pkg/termio"
)

// RotateSecrets provides guidance and options for rotating secrets after a security incident
func (a *Action) RotateSecrets(c *cli.Context) error {
	fmt.Println("Secret Rotation")
	fmt.Println("===============")
	fmt.Println()
	fmt.Println("This command helps you rotate secrets after a security incident,")
	fmt.Println("such as a team member leaving or a compromised key.")
	fmt.Println()

	// Check if we're dealing with a user revocation
	if c.Bool("after-revoke") {
		return a.rotateAfterRevoke(c)
	}

	// General rotation guidance
	fmt.Println("IMPORTANT: Re-encryption alone is not enough!")
	fmt.Println()
	fmt.Println("When a user is revoked, they may still have access to secrets through:")
	fmt.Println("  1. Old git history (encrypted with their key)")
	fmt.Println("  2. Secrets they've already decrypted and copied")
	fmt.Println("  3. Credentials they've used and may remember")
	fmt.Println()
	fmt.Println("Recommended actions:")
	fmt.Println()
	fmt.Println("  1. Re-encrypt all secrets (removes their key as recipient)")
	fmt.Println("     $ passbook reencrypt")
	fmt.Println()
	fmt.Println("  2. Rotate actual credentials they had access to:")
	fmt.Println("     - Change passwords on affected websites/services")
	fmt.Println("     - Rotate API keys and tokens")
	fmt.Println("     - Update environment variables in production")
	fmt.Println()
	fmt.Println("  3. Clean git history (optional, requires force push):")
	fmt.Println("     $ passbook rotate --clean-history")
	fmt.Println()

	if c.Bool("clean-history") {
		return a.cleanGitHistory(c)
	}

	return nil
}

// rotateAfterRevoke handles rotation after a user was revoked
func (a *Action) rotateAfterRevoke(c *cli.Context) error {
	email := c.String("user")
	if email == "" {
		return fmt.Errorf("--user is required with --after-revoke")
	}

	fmt.Printf("Rotation checklist for revoked user: %s\n", email)
	fmt.Println("=" + strings.Repeat("=", len(email)+39))
	fmt.Println()

	// TODO: In the future, we could track which credentials/envs a user had access to
	// and provide a specific list. For now, provide general guidance.

	fmt.Println("1. [  ] Re-encryption completed (passbook reencrypt)")
	fmt.Println("2. [  ] Audit credentials the user had access to")
	fmt.Println("3. [  ] Rotate passwords on affected services")
	fmt.Println("4. [  ] Rotate API keys and tokens")
	fmt.Println("5. [  ] Update environment variables in production")
	fmt.Println("6. [  ] Review audit log for user's access history")
	fmt.Println("        $ passbook audit log --actor " + email)
	fmt.Println()

	// Log audit event
	a.logAudit(audit.EventKeyRotated, email, "action", "rotation-checklist")

	return nil
}

// cleanGitHistory removes old encrypted files from git history
func (a *Action) cleanGitHistory(c *cli.Context) error {
	fmt.Println("Git History Cleanup")
	fmt.Println("===================")
	fmt.Println()
	fmt.Println("WARNING: This operation rewrites git history!")
	fmt.Println()
	fmt.Println("This will:")
	fmt.Println("  1. Remove old versions of .age files from history")
	fmt.Println("  2. Require force-pushing to remote")
	fmt.Println("  3. Require all team members to re-clone the repository")
	fmt.Println()
	fmt.Println("This is a destructive operation and should only be done when:")
	fmt.Println("  - A key was compromised")
	fmt.Println("  - A user was revoked and had access to sensitive secrets")
	fmt.Println("  - You need to completely remove trace of old encrypted data")
	fmt.Println()

	// Check if git-filter-repo is available
	_, err := exec.LookPath("git-filter-repo")
	if err != nil {
		fmt.Println("NOTICE: git-filter-repo is not installed.")
		fmt.Println()
		fmt.Println("Install it with:")
		fmt.Println("  brew install git-filter-repo   # macOS")
		fmt.Println("  pip install git-filter-repo    # pip")
		fmt.Println()
		fmt.Println("Then run this command again.")
		return nil
	}

	proceed, err := termio.Confirm("Do you want to proceed with history cleanup?", false)
	if err != nil || !proceed {
		fmt.Println("Aborted.")
		return nil
	}

	fmt.Println()
	fmt.Println("Running git-filter-repo to remove old .age file versions...")
	fmt.Println()

	// Run git-filter-repo to remove old versions of .age files
	// This replaces old blob contents with empty files while keeping the tree structure
	cmd := exec.Command("git", "-C", a.cfg.StorePath, "filter-repo",
		"--path-glob", "*.age",
		"--invert-paths",
		"--force")

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running git-filter-repo: %v\n", err)
		fmt.Printf("Output: %s\n", string(output))
		return fmt.Errorf("git history cleanup failed: %w", err)
	}

	fmt.Println("Git history cleaned successfully!")
	fmt.Println()
	fmt.Println("IMPORTANT: You must now:")
	fmt.Println("  1. Force push to remote:  git push --force-with-lease")
	fmt.Println("  2. Have all team members re-clone the repository")
	fmt.Println("  3. Re-add all secrets:    passbook reencrypt")
	fmt.Println()

	// Log audit event
	a.logAudit(audit.EventKeyRotated, "git-history", "action", "history-cleaned")

	return nil
}

// ListExposedSecrets lists secrets that were potentially exposed to a user
func (a *Action) ListExposedSecrets(c *cli.Context) error {
	email := c.Args().First()
	if email == "" {
		return fmt.Errorf("usage: passbook rotate exposed EMAIL")
	}

	fmt.Printf("Secrets potentially exposed to: %s\n", email)
	fmt.Println(strings.Repeat("=", 35+len(email)))
	fmt.Println()

	// Get audit log for this user
	logger := a.getAuditLogger()
	filter := &audit.EventFilter{
		Actor: email,
		Types: []audit.EventType{
			audit.EventCredentialAccess,
			audit.EventEnvAccess,
		},
	}

	events, err := logger.GetEvents(filter)
	if err != nil {
		return fmt.Errorf("failed to read audit log: %w", err)
	}

	if len(events) == 0 {
		fmt.Println("No recorded accesses found in audit log.")
		fmt.Println()
		fmt.Println("Note: Audit logging may not have been enabled when this user had access.")
		fmt.Println("Consider rotating all secrets the user's role had access to.")
		return nil
	}

	// Group by target
	accessed := make(map[string]bool)
	for _, e := range events {
		accessed[e.Target] = true
	}

	fmt.Println("Secrets this user accessed:")
	for target := range accessed {
		fmt.Printf("  - %s\n", target)
	}

	fmt.Println()
	fmt.Printf("Total: %d unique secrets accessed\n", len(accessed))
	fmt.Println()
	fmt.Println("You should consider rotating credentials for all listed items.")

	return nil
}
