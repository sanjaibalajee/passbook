package action

import (
	"fmt"
	"os/exec"

	"github.com/urfave/cli/v2"
)

// Sync synchronizes with git remote
func (a *Action) Sync(c *cli.Context) error {
	pushOnly := c.Bool("push")
	pullOnly := c.Bool("pull")

	storePath := a.cfg.StorePath

	if pullOnly {
		fmt.Print("Pulling from remote... ")
		if err := gitPull(storePath); err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("pull failed: %w", err)
		}
		fmt.Println("OK")
		return nil
	}

	if pushOnly {
		fmt.Print("Pushing to remote... ")
		if err := gitPush(storePath); err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("push failed: %w", err)
		}
		fmt.Println("OK")
		return nil
	}

	// Full sync: pull then push
	fmt.Print("Pulling from remote... ")
	if err := gitPull(storePath); err != nil {
		// Pull might fail on first sync, that's ok
		fmt.Println("skipped (no remote history)")
	} else {
		fmt.Println("OK")
	}

	fmt.Print("Pushing to remote... ")
	if err := gitPush(storePath); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("push failed: %w", err)
	}
	fmt.Println("OK")

	fmt.Println("Sync complete!")
	return nil
}

// GitSync performs a full git sync (pull + push)
// This is called by other commands when autopush is enabled
func (a *Action) GitSync() error {
	if !a.cfg.Git.AutoSync {
		return nil
	}

	storePath := a.cfg.StorePath

	// Try to pull first (ignore errors on empty remote)
	_ = gitPull(storePath)

	// Push changes
	if a.cfg.Git.AutoPush {
		return gitPush(storePath)
	}

	return nil
}

// GitCommitAndSync commits changes and syncs if autopush is enabled
func (a *Action) GitCommitAndSync(message string) error {
	storePath := a.cfg.StorePath

	// Add and commit
	if err := gitCommit(storePath, message); err != nil {
		return fmt.Errorf("commit failed: %w", err)
	}

	// Sync if enabled
	if a.cfg.Git.AutoPush {
		if err := gitPush(storePath); err != nil {
			// Don't fail the command, just warn
			fmt.Printf("Warning: auto-push failed: %v\n", err)
			fmt.Println("Run 'passbook sync' to push manually")
		}
	}

	return nil
}

// Git helper functions

func gitPull(path string) error {
	cmd := exec.Command("git", "pull", "--rebase")
	cmd.Dir = path
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(output))
	}
	return nil
}

func gitPush(path string) error {
	cmd := exec.Command("git", "push")
	cmd.Dir = path
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(output))
	}
	return nil
}
