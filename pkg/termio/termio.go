package termio

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// Reader reads input from the terminal
type Reader struct {
	in  *os.File
	out *os.File
}

// New creates a new terminal reader
func New() *Reader {
	return &Reader{
		in:  os.Stdin,
		out: os.Stderr, // Use stderr for prompts
	}
}

// Prompt displays a prompt and reads a line of input
func (r *Reader) Prompt(prompt string) (string, error) {
	fmt.Fprint(r.out, prompt)

	scanner := bufio.NewScanner(r.in)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text()), nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", nil
}

// PromptDefault displays a prompt with a default value
func (r *Reader) PromptDefault(prompt, defaultValue string) (string, error) {
	if defaultValue != "" {
		prompt = fmt.Sprintf("%s [%s]: ", strings.TrimSuffix(prompt, ": "), defaultValue)
	}

	value, err := r.Prompt(prompt)
	if err != nil {
		return "", err
	}

	if value == "" {
		return defaultValue, nil
	}
	return value, nil
}

// PromptPassword prompts for a password without echoing
func (r *Reader) PromptPassword(prompt string) (string, error) {
	fmt.Fprint(r.out, prompt)

	// Read password without echo
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}

	fmt.Fprintln(r.out) // Print newline after password
	return string(password), nil
}

// Confirm asks for yes/no confirmation
func (r *Reader) Confirm(prompt string, defaultYes bool) (bool, error) {
	suffix := "[y/N]"
	if defaultYes {
		suffix = "[Y/n]"
	}

	response, err := r.Prompt(fmt.Sprintf("%s %s: ", prompt, suffix))
	if err != nil {
		return false, err
	}

	response = strings.ToLower(strings.TrimSpace(response))

	if response == "" {
		return defaultYes, nil
	}

	return response == "y" || response == "yes", nil
}

// Select displays options and returns the selected one
func (r *Reader) Select(prompt string, options []string, defaultIndex int) (int, error) {
	fmt.Fprintln(r.out, prompt)
	for i, opt := range options {
		marker := "  "
		if i == defaultIndex {
			marker = "> "
		}
		fmt.Fprintf(r.out, "%s%d. %s\n", marker, i+1, opt)
	}

	for {
		input, err := r.Prompt("Select [1-" + fmt.Sprintf("%d", len(options)) + "]: ")
		if err != nil {
			return defaultIndex, err
		}

		if input == "" && defaultIndex >= 0 && defaultIndex < len(options) {
			return defaultIndex, nil
		}

		var selected int
		if _, err := fmt.Sscanf(input, "%d", &selected); err != nil {
			fmt.Fprintln(r.out, "Invalid selection, please enter a number")
			continue
		}

		if selected < 1 || selected > len(options) {
			fmt.Fprintln(r.out, "Selection out of range")
			continue
		}

		return selected - 1, nil
	}
}

// Print prints formatted output
func (r *Reader) Print(format string, args ...interface{}) {
	fmt.Fprintf(r.out, format, args...)
}

// Println prints a line
func (r *Reader) Println(args ...interface{}) {
	fmt.Fprintln(r.out, args...)
}

// Error prints an error message
func (r *Reader) Error(format string, args ...interface{}) {
	fmt.Fprintf(r.out, "Error: "+format+"\n", args...)
}

// Success prints a success message
func (r *Reader) Success(format string, args ...interface{}) {
	fmt.Fprintf(r.out, "✓ "+format+"\n", args...)
}

// Warning prints a warning message
func (r *Reader) Warning(format string, args ...interface{}) {
	fmt.Fprintf(r.out, "⚠ "+format+"\n", args...)
}

// IsTerminal checks if stdin is a terminal
func IsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// TerminalWidth returns the terminal width
func TerminalWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 {
		return 80 // Default width
	}
	return width
}

// Global convenience functions

// Prompt displays a prompt and reads input
func Prompt(prompt string) (string, error) {
	return New().Prompt(prompt)
}

// PromptDefault prompts with a default value
func PromptDefault(prompt, defaultValue string) (string, error) {
	return New().PromptDefault(prompt, defaultValue)
}

// PromptPassword prompts for a password
func PromptPassword(prompt string) (string, error) {
	return New().PromptPassword(prompt)
}

// Confirm asks for confirmation
func Confirm(prompt string, defaultYes bool) (bool, error) {
	return New().Confirm(prompt, defaultYes)
}

// Select displays options and returns selection
func Select(prompt string, options []string, defaultIndex int) (int, error) {
	return New().Select(prompt, options, defaultIndex)
}
