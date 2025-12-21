package recipients

import (
	"bufio"
	"bytes"
	"fmt"
	"sort"
	"strings"
)

const (
	// RecipientsFile is the main recipients file name
	RecipientsFile = ".passbook-recipients"

	// Header is the file header
	Header = "# Passbook Recipients\n# Format: <age-public-key> # <email>\n"
)

// Recipients manages a list of age public keys
type Recipients struct {
	keys   []string          // Public keys in order
	emails map[string]string // Key -> email mapping
}

// New creates an empty Recipients
func New() *Recipients {
	return &Recipients{
		emails: make(map[string]string),
	}
}

// Parse parses a recipients file
func Parse(data []byte) (*Recipients, error) {
	r := &Recipients{
		emails: make(map[string]string),
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Skip comment-only lines
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Parse: "age1xxx... # email@domain.com"
		parts := strings.SplitN(line, "#", 2)
		key := strings.TrimSpace(parts[0])

		// Validate key format
		if !strings.HasPrefix(key, "age1") {
			continue // Skip invalid keys
		}

		r.keys = append(r.keys, key)

		if len(parts) > 1 {
			email := strings.TrimSpace(parts[1])
			r.emails[key] = email
		}
	}

	return r, scanner.Err()
}

// Marshal serializes recipients to file format
func (r *Recipients) Marshal() []byte {
	var buf bytes.Buffer
	buf.WriteString(Header)
	buf.WriteString("\n")

	for _, key := range r.keys {
		if email, ok := r.emails[key]; ok {
			buf.WriteString(fmt.Sprintf("%s # %s\n", key, email))
		} else {
			buf.WriteString(key + "\n")
		}
	}

	return buf.Bytes()
}

// Add adds a recipient
func (r *Recipients) Add(key, email string) bool {
	// Check for duplicates
	for _, k := range r.keys {
		if k == key {
			// Update email if provided
			if email != "" {
				r.emails[key] = email
			}
			return false // Already exists
		}
	}

	r.keys = append(r.keys, key)
	if email != "" {
		r.emails[key] = email
	}
	return true
}

// Remove removes a recipient
func (r *Recipients) Remove(key string) bool {
	for i, k := range r.keys {
		if k == key {
			r.keys = append(r.keys[:i], r.keys[i+1:]...)
			delete(r.emails, key)
			return true
		}
	}
	return false
}

// RemoveByEmail removes a recipient by email
func (r *Recipients) RemoveByEmail(email string) bool {
	// Find key by email
	var keyToRemove string
	for key, e := range r.emails {
		if strings.EqualFold(e, email) {
			keyToRemove = key
			break
		}
	}

	if keyToRemove == "" {
		return false
	}

	return r.Remove(keyToRemove)
}

// Has checks if a key is in the recipients
func (r *Recipients) Has(key string) bool {
	for _, k := range r.keys {
		if k == key {
			return true
		}
	}
	return false
}

// HasEmail checks if an email is in the recipients
func (r *Recipients) HasEmail(email string) bool {
	for _, e := range r.emails {
		if strings.EqualFold(e, email) {
			return true
		}
	}
	return false
}

// Keys returns all public keys
func (r *Recipients) Keys() []string {
	result := make([]string, len(r.keys))
	copy(result, r.keys)
	return result
}

// Count returns the number of recipients
func (r *Recipients) Count() int {
	return len(r.keys)
}

// GetEmail returns the email for a key
func (r *Recipients) GetEmail(key string) (string, bool) {
	email, ok := r.emails[key]
	return email, ok
}

// GetKey returns the key for an email
func (r *Recipients) GetKey(email string) (string, bool) {
	for key, e := range r.emails {
		if strings.EqualFold(e, email) {
			return key, true
		}
	}
	return "", false
}

// Merge merges another Recipients into this one
func (r *Recipients) Merge(other *Recipients) int {
	count := 0
	for _, key := range other.keys {
		email, _ := other.GetEmail(key)
		if r.Add(key, email) {
			count++
		}
	}
	return count
}

// Sort sorts recipients by email (keys without email come last)
func (r *Recipients) Sort() {
	sort.SliceStable(r.keys, func(i, j int) bool {
		emailI, okI := r.emails[r.keys[i]]
		emailJ, okJ := r.emails[r.keys[j]]

		if okI && okJ {
			return strings.ToLower(emailI) < strings.ToLower(emailJ)
		}
		if okI {
			return true
		}
		if okJ {
			return false
		}
		return r.keys[i] < r.keys[j]
	})
}

// Clone creates a copy of the recipients
func (r *Recipients) Clone() *Recipients {
	clone := &Recipients{
		keys:   make([]string, len(r.keys)),
		emails: make(map[string]string, len(r.emails)),
	}
	copy(clone.keys, r.keys)
	for k, v := range r.emails {
		clone.emails[k] = v
	}
	return clone
}

// Filter returns a new Recipients with only keys that pass the filter
func (r *Recipients) Filter(fn func(key, email string) bool) *Recipients {
	filtered := New()
	for _, key := range r.keys {
		email, _ := r.emails[key]
		if fn(key, email) {
			filtered.Add(key, email)
		}
	}
	return filtered
}

// Entries returns key-email pairs
func (r *Recipients) Entries() []Entry {
	entries := make([]Entry, len(r.keys))
	for i, key := range r.keys {
		entries[i] = Entry{
			Key:   key,
			Email: r.emails[key],
		}
	}
	return entries
}

// Entry represents a key-email pair
type Entry struct {
	Key   string
	Email string
}
