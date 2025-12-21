package storage

import "context"

// Storage defines the interface for storage backends
type Storage interface {
	// Get reads a file
	Get(ctx context.Context, name string) ([]byte, error)

	// Set writes a file
	Set(ctx context.Context, name string, data []byte) error

	// Delete removes a file
	Delete(ctx context.Context, name string) error

	// Exists checks if a file exists
	Exists(ctx context.Context, name string) bool

	// List lists files with a prefix
	List(ctx context.Context, prefix string) ([]string, error)

	// Name returns the backend name
	Name() string
}

// GitStorage extends Storage with git operations
type GitStorage interface {
	Storage

	// Add stages a file
	Add(ctx context.Context, name string) error

	// Commit creates a commit
	Commit(ctx context.Context, message string) error

	// Push pushes to remote
	Push(ctx context.Context) error

	// Pull pulls from remote
	Pull(ctx context.Context) error

	// Sync does pull then push
	Sync(ctx context.Context) error

	// IsClean checks if working tree is clean
	IsClean(ctx context.Context) bool
}
