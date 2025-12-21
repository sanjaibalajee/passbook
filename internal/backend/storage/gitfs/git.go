package gitfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// Name is the backend name
	Name = "gitfs"
)

var (
	// ErrNotARepo is returned when path is not a git repository
	ErrNotARepo = errors.New("not a git repository")

	// ErrNoRemote is returned when no remote is configured
	ErrNoRemote = errors.New("no git remote configured")

	// ErrConflict is returned on merge conflicts
	ErrConflict = errors.New("merge conflict detected")
)

// Git implements git-based storage
type Git struct {
	path   string
	remote string
	branch string
}

// New creates a new git storage
func New(path string) (*Git, error) {
	g := &Git{
		path:   path,
		branch: "main",
	}

	// Check if git repo exists
	if !g.isRepo() {
		return nil, ErrNotARepo
	}

	// Get remote
	g.remote, _ = g.getRemote()

	return g, nil
}

// Init initializes a new git repository
func Init(path, remote string) (*Git, error) {
	// Create directory
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	g := &Git{
		path:   path,
		remote: remote,
		branch: "main",
	}

	// git init
	if err := g.cmd("init"); err != nil {
		return nil, fmt.Errorf("git init failed: %w", err)
	}

	// Configure default branch
	if err := g.cmd("config", "init.defaultBranch", "main"); err != nil {
		// Ignore error for older git versions
	}

	// Set remote if provided
	if remote != "" {
		if err := g.cmd("remote", "add", "origin", remote); err != nil {
			return nil, fmt.Errorf("failed to add remote: %w", err)
		}
	}

	return g, nil
}

// Clone clones an existing repository
func Clone(remote, path string) (*Git, error) {
	cmd := exec.Command("git", "clone", remote, path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git clone failed: %s", string(output))
	}
	return New(path)
}

// Name returns the backend name
func (g *Git) Name() string {
	return Name
}

// Path returns the storage path
func (g *Git) Path() string {
	return g.path
}

// Get reads a file
func (g *Git) Get(ctx context.Context, name string) ([]byte, error) {
	path := filepath.Join(g.path, name)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", name)
		}
		return nil, err
	}
	return data, nil
}

// Set writes a file
func (g *Git) Set(ctx context.Context, name string, data []byte) error {
	path := filepath.Join(g.path, name)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

// Delete removes a file
func (g *Git) Delete(ctx context.Context, name string) error {
	path := filepath.Join(g.path, name)
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Exists checks if a file exists
func (g *Git) Exists(ctx context.Context, name string) bool {
	path := filepath.Join(g.path, name)
	_, err := os.Stat(path)
	return err == nil
}

// List lists files with a prefix
func (g *Git) List(ctx context.Context, prefix string) ([]string, error) {
	var files []string

	root := filepath.Join(g.path, prefix)

	// Check if path exists
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return files, nil
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip hidden files and directories (except .passbook files)
		name := info.Name()
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(name, ".passbook") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.IsDir() {
			relPath, _ := filepath.Rel(g.path, path)
			files = append(files, relPath)
		}
		return nil
	})

	return files, err
}

// ListDirs lists directories with a prefix
func (g *Git) ListDirs(ctx context.Context, prefix string) ([]string, error) {
	var dirs []string

	root := filepath.Join(g.path, prefix)

	if _, err := os.Stat(root); os.IsNotExist(err) {
		return dirs, nil
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			dirs = append(dirs, entry.Name())
		}
	}

	return dirs, nil
}

// Add stages a file
func (g *Git) Add(ctx context.Context, name string) error {
	return g.cmd("add", name)
}

// Commit creates a commit
func (g *Git) Commit(ctx context.Context, message string) error {
	// Add all changes
	if err := g.cmd("add", "-A"); err != nil {
		return fmt.Errorf("git add failed: %w", err)
	}

	// Check if there are changes to commit
	if g.IsClean(ctx) {
		return nil // Nothing to commit
	}

	// Commit
	return g.cmd("commit", "-m", message)
}

// Push pushes to remote
func (g *Git) Push(ctx context.Context) error {
	if g.remote == "" {
		return ErrNoRemote
	}
	return g.cmd("push", "origin", g.branch)
}

// Pull pulls from remote
func (g *Git) Pull(ctx context.Context) error {
	if g.remote == "" {
		return ErrNoRemote
	}

	output, err := g.cmdOutput("pull", "origin", g.branch)
	if err != nil {
		if strings.Contains(output, "CONFLICT") {
			return ErrConflict
		}
		return fmt.Errorf("git pull failed: %s", output)
	}
	return nil
}

// Sync does pull then push
func (g *Git) Sync(ctx context.Context) error {
	if g.remote == "" {
		return ErrNoRemote
	}

	// Pull first (ignore errors on first sync)
	if err := g.Pull(ctx); err != nil && !errors.Is(err, ErrNoRemote) {
		// Only return error if it's a conflict
		if errors.Is(err, ErrConflict) {
			return err
		}
		// Ignore other pull errors (like "no tracking branch")
	}

	// Push
	return g.Push(ctx)
}

// IsClean checks if working tree is clean
func (g *Git) IsClean(ctx context.Context) bool {
	output, err := g.cmdOutput("status", "--porcelain")
	if err != nil {
		return false
	}
	return strings.TrimSpace(output) == ""
}

// cmd runs a git command
func (g *Git) cmd(args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = g.path
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(output))
	}
	return nil
}

// cmdOutput runs a git command and returns output
func (g *Git) cmdOutput(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = g.path
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// isRepo checks if path is a git repo
func (g *Git) isRepo() bool {
	gitDir := filepath.Join(g.path, ".git")
	info, err := os.Stat(gitDir)
	return err == nil && info.IsDir()
}

// getRemote gets the origin remote URL
func (g *Git) getRemote() (string, error) {
	output, err := g.cmdOutput("remote", "get-url", "origin")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

// SetBranch sets the branch name
func (g *Git) SetBranch(branch string) {
	g.branch = branch
}

// GetCurrentBranch returns the current branch name
func (g *Git) GetCurrentBranch() (string, error) {
	output, err := g.cmdOutput("branch", "--show-current")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}
