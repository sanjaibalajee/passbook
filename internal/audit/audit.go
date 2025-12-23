package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// EventType represents the type of audit event
type EventType string

const (
	// User events
	EventUserAdded    EventType = "user.added"
	EventUserRemoved  EventType = "user.removed"
	EventUserVerified EventType = "user.verified"
	EventRoleGranted  EventType = "role.granted"
	EventRoleRevoked  EventType = "role.revoked"

	// Credential events
	EventCredentialCreated EventType = "credential.created"
	EventCredentialUpdated EventType = "credential.updated"
	EventCredentialDeleted EventType = "credential.deleted"
	EventCredentialAccess  EventType = "credential.accessed"

	// Environment events
	EventEnvCreated EventType = "env.created"
	EventEnvUpdated EventType = "env.updated"
	EventEnvDeleted EventType = "env.deleted"
	EventEnvAccess  EventType = "env.accessed"

	// Project events
	EventProjectCreated EventType = "project.created"
	EventProjectDeleted EventType = "project.deleted"

	// Security events
	EventReEncrypt    EventType = "security.reencrypt"
	EventKeyRotated   EventType = "security.key_rotated"
	EventLoginSuccess EventType = "auth.login"
	EventLoginFailed  EventType = "auth.login_failed"
	EventLogout       EventType = "auth.logout"
)

// Event represents an audit log entry
type Event struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Type      EventType         `json:"type"`
	Actor     string            `json:"actor"`        // Email of who performed the action
	Target    string            `json:"target"`       // What was affected (user email, credential path, etc.)
	Details   map[string]string `json:"details"`      // Additional context
	IP        string            `json:"ip,omitempty"` // Client IP if available
}

// Logger handles audit logging
type Logger struct {
	storePath string
	logFile   string
	actor     string // Current user's email
}

// NewLogger creates a new audit logger
func NewLogger(storePath, actor string) *Logger {
	return &Logger{
		storePath: storePath,
		logFile:   filepath.Join(storePath, ".passbook-audit.log"),
		actor:     actor,
	}
}

// Log records an audit event
func (l *Logger) Log(eventType EventType, target string, details map[string]string) error {
	event := Event{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		Actor:     l.actor,
		Target:    target,
		Details:   details,
	}

	return l.writeEvent(event)
}

// LogWithDetails is a convenience method for logging with key-value pairs
func (l *Logger) LogWithDetails(eventType EventType, target string, kvPairs ...string) error {
	details := make(map[string]string)
	for i := 0; i < len(kvPairs)-1; i += 2 {
		details[kvPairs[i]] = kvPairs[i+1]
	}
	return l.Log(eventType, target, details)
}

// writeEvent appends an event to the audit log
func (l *Logger) writeEvent(event Event) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(l.logFile), 0700); err != nil {
		return fmt.Errorf("failed to create audit log directory: %w", err)
	}

	// Open file in append mode
	f, err := os.OpenFile(l.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}
	defer f.Close()

	// Write JSON line
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

// GetEvents retrieves audit events, optionally filtered
func (l *Logger) GetEvents(filter *EventFilter) ([]Event, error) {
	data, err := os.ReadFile(l.logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []Event{}, nil
		}
		return nil, fmt.Errorf("failed to read audit log: %w", err)
	}

	var events []Event
	lines := splitLines(data)

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			continue // Skip malformed lines
		}

		if filter == nil || filter.Matches(event) {
			events = append(events, event)
		}
	}

	return events, nil
}

// EventFilter filters audit events
type EventFilter struct {
	Types     []EventType
	Actor     string
	Target    string
	StartTime time.Time
	EndTime   time.Time
	Limit     int
}

// Matches checks if an event matches the filter
func (f *EventFilter) Matches(event Event) bool {
	if len(f.Types) > 0 {
		found := false
		for _, t := range f.Types {
			if event.Type == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if f.Actor != "" && event.Actor != f.Actor {
		return false
	}

	if f.Target != "" && event.Target != f.Target {
		return false
	}

	if !f.StartTime.IsZero() && event.Timestamp.Before(f.StartTime) {
		return false
	}

	if !f.EndTime.IsZero() && event.Timestamp.After(f.EndTime) {
		return false
	}

	return true
}

// splitLines splits byte data into lines
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// FormatEvent formats an event for display
func FormatEvent(e Event) string {
	details := ""
	for k, v := range e.Details {
		if details != "" {
			details += ", "
		}
		details += fmt.Sprintf("%s=%s", k, v)
	}

	if details != "" {
		return fmt.Sprintf("[%s] %s: %s -> %s (%s)",
			e.Timestamp.Format("2006-01-02 15:04:05"),
			e.Type, e.Actor, e.Target, details)
	}

	return fmt.Sprintf("[%s] %s: %s -> %s",
		e.Timestamp.Format("2006-01-02 15:04:05"),
		e.Type, e.Actor, e.Target)
}
