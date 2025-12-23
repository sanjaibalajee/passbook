package action

import (
	"fmt"
	"time"

	"github.com/urfave/cli/v2"

	"passbook/internal/audit"
)

// AuditLog shows audit log entries
func (a *Action) AuditLog(c *cli.Context) error {
	// Get current user for actor context
	currentUser, err := a.getCurrentUser()
	actorEmail := ""
	if err == nil {
		actorEmail = currentUser.Email
	}

	logger := audit.NewLogger(a.cfg.StorePath, actorEmail)

	// Build filter
	filter := &audit.EventFilter{}

	if actor := c.String("actor"); actor != "" {
		filter.Actor = actor
	}

	if target := c.String("target"); target != "" {
		filter.Target = target
	}

	if eventType := c.String("type"); eventType != "" {
		filter.Types = []audit.EventType{audit.EventType(eventType)}
	}

	if since := c.String("since"); since != "" {
		if d, err := time.ParseDuration(since); err == nil {
			filter.StartTime = time.Now().Add(-d)
		} else if t, err := time.Parse("2006-01-02", since); err == nil {
			filter.StartTime = t
		}
	}

	if limit := c.Int("limit"); limit > 0 {
		filter.Limit = limit
	} else {
		filter.Limit = 50 // Default
	}

	events, err := logger.GetEvents(filter)
	if err != nil {
		return fmt.Errorf("failed to read audit log: %w", err)
	}

	if len(events) == 0 {
		fmt.Println("No audit events found.")
		return nil
	}

	fmt.Println("Audit Log")
	fmt.Println("=========")
	fmt.Println()

	// Show most recent first, but respect limit
	start := 0
	if len(events) > filter.Limit {
		start = len(events) - filter.Limit
	}

	for i := len(events) - 1; i >= start; i-- {
		fmt.Println(audit.FormatEvent(events[i]))
	}

	if len(events) > filter.Limit {
		fmt.Printf("\n(Showing %d of %d events. Use --limit to see more)\n", filter.Limit, len(events))
	}

	return nil
}

// AuditStats shows audit statistics
func (a *Action) AuditStats(c *cli.Context) error {
	currentUser, err := a.getCurrentUser()
	actorEmail := ""
	if err == nil {
		actorEmail = currentUser.Email
	}

	logger := audit.NewLogger(a.cfg.StorePath, actorEmail)

	events, err := logger.GetEvents(nil)
	if err != nil {
		return fmt.Errorf("failed to read audit log: %w", err)
	}

	if len(events) == 0 {
		fmt.Println("No audit events found.")
		return nil
	}

	// Calculate stats
	eventCounts := make(map[audit.EventType]int)
	actorCounts := make(map[string]int)
	var earliest, latest time.Time

	for _, e := range events {
		eventCounts[e.Type]++
		actorCounts[e.Actor]++

		if earliest.IsZero() || e.Timestamp.Before(earliest) {
			earliest = e.Timestamp
		}
		if latest.IsZero() || e.Timestamp.After(latest) {
			latest = e.Timestamp
		}
	}

	fmt.Println("Audit Statistics")
	fmt.Println("================")
	fmt.Println()
	fmt.Printf("Total events: %d\n", len(events))
	fmt.Printf("Time range:   %s to %s\n",
		earliest.Format("2006-01-02 15:04"),
		latest.Format("2006-01-02 15:04"))
	fmt.Println()

	fmt.Println("Events by type:")
	for eventType, count := range eventCounts {
		fmt.Printf("  %-25s %d\n", eventType, count)
	}
	fmt.Println()

	fmt.Println("Events by actor:")
	for actor, count := range actorCounts {
		fmt.Printf("  %-30s %d\n", actor, count)
	}

	return nil
}

// getAuditLogger creates an audit logger for the current user
func (a *Action) getAuditLogger() *audit.Logger {
	currentUser, err := a.getCurrentUser()
	actorEmail := "unknown"
	if err == nil {
		actorEmail = currentUser.Email
	}
	return audit.NewLogger(a.cfg.StorePath, actorEmail)
}

// logAudit is a helper to log audit events
func (a *Action) logAudit(eventType audit.EventType, target string, details ...string) {
	logger := a.getAuditLogger()
	if err := logger.LogWithDetails(eventType, target, details...); err != nil {
		// Log errors silently - don't fail operations due to audit logging
		fmt.Printf("Warning: failed to log audit event: %v\n", err)
	}
}
