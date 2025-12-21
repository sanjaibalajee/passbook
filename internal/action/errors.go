package action

import "errors"

var (
	// ErrNotInitialized is returned when passbook is not initialized
	ErrNotInitialized = errors.New("passbook not initialized, run 'passbook init' or 'passbook clone' first")

	// ErrNotLoggedIn is returned when user is not logged in
	ErrNotLoggedIn = errors.New("not logged in, run 'passbook login' first")

	// ErrAccessDenied is returned when user doesn't have permission
	ErrAccessDenied = errors.New("access denied")

	// ErrNotFound is returned when resource is not found
	ErrNotFound = errors.New("not found")

	// ErrInvalidInput is returned for invalid user input
	ErrInvalidInput = errors.New("invalid input")
)
