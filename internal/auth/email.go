package auth

import (
	"fmt"
	"net/smtp"

	"passbook/internal/config"
)

// EmailSender defines the interface for sending emails
type EmailSender interface {
	SendVerificationCode(to, code string) error
}

// NewEmailSender creates an EmailSender based on config
func NewEmailSender(cfg *config.Config) (EmailSender, error) {
	switch cfg.Email.Provider {
	case "smtp":
		// Only use SMTP if properly configured
		if cfg.Email.SMTP.Host != "" && cfg.Email.SMTP.Port > 0 {
			return NewSMTPSender(cfg.Email.SMTP), nil
		}
		// Fall back to console if SMTP not configured
		fmt.Println("(SMTP not configured, using console mode)")
		return &ConsoleSender{}, nil
	case "console":
		return &ConsoleSender{}, nil
	case "":
		// Default to console output for development
		return &ConsoleSender{}, nil
	default:
		return nil, fmt.Errorf("unknown email provider: %s", cfg.Email.Provider)
	}
}

// SMTPSender sends emails via SMTP
type SMTPSender struct {
	host     string
	port     int
	username string
	password string
	from     string
}

// NewSMTPSender creates a new SMTP sender
func NewSMTPSender(cfg config.SMTPConfig) *SMTPSender {
	from := cfg.Username
	if from == "" {
		from = "noreply@passbook.local"
	}

	return &SMTPSender{
		host:     cfg.Host,
		port:     cfg.Port,
		username: cfg.Username,
		password: cfg.Password,
		from:     from,
	}
}

// SendVerificationCode sends a verification code email
func (s *SMTPSender) SendVerificationCode(to, code string) error {
	subject := "Passbook Login Verification Code"
	body := fmt.Sprintf(`Your Passbook verification code is:

    %s

This code expires in 15 minutes.

If you didn't request this, you can safely ignore this email.
`, code)

	return s.send(to, subject, body)
}

// send sends an email via SMTP
func (s *SMTPSender) send(to, subject, body string) error {
	// Build message
	msg := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"\r\n"+
		"%s", s.from, to, subject, body)

	// Connect and authenticate
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	auth := smtp.PlainAuth("", s.username, s.password, s.host)

	return smtp.SendMail(addr, auth, s.from, []string{to}, []byte(msg))
}

// ConsoleSender outputs emails to console (for development)
type ConsoleSender struct{}

// SendVerificationCode prints the verification code to console
func (s *ConsoleSender) SendVerificationCode(to, code string) error {
	fmt.Println()
	fmt.Println("============================================")
	fmt.Printf("  VERIFICATION CODE for %s\n", to)
	fmt.Println("============================================")
	fmt.Printf("\n  Your code: %s\n\n", code)
	fmt.Println("  (In production, this would be emailed)")
	fmt.Println("============================================")
	fmt.Println()
	return nil
}
