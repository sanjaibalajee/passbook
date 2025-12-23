package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// GitHub OAuth endpoints
	githubDeviceCodeURL  = "https://github.com/login/device/code"
	githubAccessTokenURL = "https://github.com/login/oauth/access_token"
	githubUserURL        = "https://api.github.com/user"
	githubUserEmailsURL  = "https://api.github.com/user/emails"

	// Scopes needed for email verification
	// read:user - to get user profile
	// user:email - to get user's email addresses
	githubScopes = "read:user user:email"

	// Polling interval for device flow
	defaultPollInterval = 5 * time.Second
)

// GitHubClientID is the OAuth App client ID
// Set at build time with: go build -ldflags "-X passbook/internal/auth.GitHubClientID=YOUR_ID"
// Or override at runtime with PASSBOOK_GITHUB_CLIENT_ID environment variable
var GitHubClientID = ""

var (
	// ErrAuthPending is returned when authorization is still pending
	ErrAuthPending = errors.New("authorization pending")
	// ErrSlowDown is returned when polling too fast
	ErrSlowDown = errors.New("slow down")
	// ErrExpiredToken is returned when device code expires
	ErrExpiredToken = errors.New("device code expired")
	// ErrAccessDenied is returned when user denies access
	ErrAccessDenied = errors.New("access denied by user")
	// ErrEmailNotVerified is returned when GitHub email is not verified
	ErrEmailNotVerified = errors.New("github email not verified")
	// ErrEmailDomainMismatch is returned when email domain doesn't match
	ErrEmailDomainMismatch = errors.New("email domain not allowed")
	// ErrNoValidEmail is returned when no valid email found
	ErrNoValidEmail = errors.New("no valid email found in github account")
)

// GitHubAuth handles GitHub OAuth authentication
type GitHubAuth struct {
	clientID      string
	configDir     string
	allowedDomain string
}

// DeviceCodeResponse from GitHub
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// AccessTokenResponse from GitHub
type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// GitHubUser represents GitHub user info
type GitHubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// GitHubEmail represents a GitHub email
type GitHubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// GitHubSession stores the authenticated session
type GitHubSession struct {
	AccessToken     string    `yaml:"access_token"`
	GitHubID        int64     `yaml:"github_id"`
	GitHubLogin     string    `yaml:"github_login"`
	Email           string    `yaml:"email"`
	Name            string    `yaml:"name"`
	AuthenticatedAt time.Time `yaml:"authenticated_at"`
	ExpiresAt       time.Time `yaml:"expires_at,omitempty"`
}

// NewGitHubAuth creates a new GitHub auth handler
func NewGitHubAuth(configDir, allowedDomain string) *GitHubAuth {
	// Priority: env var > build-time > error
	clientID := os.Getenv("PASSBOOK_GITHUB_CLIENT_ID")
	if clientID == "" {
		clientID = GitHubClientID
	}

	return &GitHubAuth{
		clientID:      clientID,
		configDir:     configDir,
		allowedDomain: allowedDomain,
	}
}

// StartDeviceFlow initiates the GitHub device authorization flow
func (g *GitHubAuth) StartDeviceFlow() (*DeviceCodeResponse, error) {
	if g.clientID == "" {
		return nil, fmt.Errorf("GitHub OAuth not configured. Set PASSBOOK_GITHUB_CLIENT_ID environment variable or build with -ldflags \"-X passbook/internal/auth.GitHubClientID=YOUR_ID\"")
	}

	data := url.Values{}
	data.Set("client_id", g.clientID)
	data.Set("scope", githubScopes)

	req, err := http.NewRequest("POST", githubDeviceCodeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request device code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var deviceResp DeviceCodeResponse
	if err := json.Unmarshal(body, &deviceResp); err != nil {
		return nil, fmt.Errorf("failed to parse device code response: %w", err)
	}

	if deviceResp.DeviceCode == "" {
		return nil, fmt.Errorf("invalid device code response: %s", string(body))
	}

	return &deviceResp, nil
}

// PollForToken polls GitHub for the access token after user authorizes
func (g *GitHubAuth) PollForToken(deviceCode string, interval int) (*AccessTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", g.clientID)
	data.Set("device_code", deviceCode)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	req, err := http.NewRequest("POST", githubAccessTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to poll for token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp AccessTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Check for errors
	switch tokenResp.Error {
	case "":
		// Success
		return &tokenResp, nil
	case "authorization_pending":
		return nil, ErrAuthPending
	case "slow_down":
		return nil, ErrSlowDown
	case "expired_token":
		return nil, ErrExpiredToken
	case "access_denied":
		return nil, ErrAccessDenied
	default:
		return nil, fmt.Errorf("github oauth error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}
}

// GetUser fetches the authenticated user's info
func (g *GitHubAuth) GetUser(accessToken string) (*GitHubUser, error) {
	req, err := http.NewRequest("GET", githubUserURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github API error: %s", string(body))
	}

	var user GitHubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserEmails fetches the user's email addresses
func (g *GitHubAuth) GetUserEmails(accessToken string) ([]GitHubEmail, error) {
	req, err := http.NewRequest("GET", githubUserEmailsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user emails: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github API error: %s", string(body))
	}

	var emails []GitHubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return nil, err
	}

	return emails, nil
}

// GetVerifiedEmail gets the user's primary verified email that matches allowed domain
func (g *GitHubAuth) GetVerifiedEmail(accessToken string) (string, error) {
	emails, err := g.GetUserEmails(accessToken)
	if err != nil {
		return "", err
	}

	// First, try to find primary verified email matching domain
	for _, email := range emails {
		if email.Verified && email.Primary {
			if g.isAllowedDomain(email.Email) {
				return email.Email, nil
			}
		}
	}

	// If no primary matches, try any verified email matching domain
	for _, email := range emails {
		if email.Verified {
			if g.isAllowedDomain(email.Email) {
				return email.Email, nil
			}
		}
	}

	// Check if there are any verified emails at all
	var hasVerified bool
	for _, email := range emails {
		if email.Verified {
			hasVerified = true
			break
		}
	}

	if !hasVerified {
		return "", ErrEmailNotVerified
	}

	// If we have verified emails but none match domain
	if g.allowedDomain != "" {
		return "", ErrEmailDomainMismatch
	}

	return "", ErrNoValidEmail
}

// isAllowedDomain checks if email matches allowed domain
func (g *GitHubAuth) isAllowedDomain(email string) bool {
	if g.allowedDomain == "" {
		return true // No domain restriction
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	return strings.EqualFold(parts[1], g.allowedDomain)
}

// Authenticate performs the full GitHub authentication flow
func (g *GitHubAuth) Authenticate() (*GitHubSession, error) {
	// Check for existing valid session
	session, err := g.LoadSession()
	if err == nil && session != nil {
		// Verify session is still valid by making an API call
		user, err := g.GetUser(session.AccessToken)
		if err == nil && user != nil {
			return session, nil
		}
		// Session invalid, continue with new auth
	}

	// Start device flow
	deviceResp, err := g.StartDeviceFlow()
	if err != nil {
		return nil, fmt.Errorf("failed to start device flow: %w", err)
	}

	// Display instructions to user
	fmt.Println()
	fmt.Println("GitHub Authentication")
	fmt.Println("=====================")
	fmt.Println()
	fmt.Printf("1. Open this URL in your browser:\n")
	fmt.Printf("   \033[36m%s\033[0m\n", deviceResp.VerificationURI)
	fmt.Println()
	fmt.Printf("2. Enter this code:\n")
	fmt.Printf("   \033[1;33m%s\033[0m\n", deviceResp.UserCode)
	fmt.Println()
	fmt.Println("Waiting for authorization...")
	fmt.Println()

	// Poll for token
	pollInterval := time.Duration(deviceResp.Interval) * time.Second
	if pollInterval < defaultPollInterval {
		pollInterval = defaultPollInterval
	}

	deadline := time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second)

	var accessToken string
	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)

		tokenResp, err := g.PollForToken(deviceResp.DeviceCode, deviceResp.Interval)
		if err == ErrAuthPending {
			continue
		}
		if err == ErrSlowDown {
			pollInterval += 5 * time.Second
			continue
		}
		if err != nil {
			return nil, err
		}

		accessToken = tokenResp.AccessToken
		break
	}

	if accessToken == "" {
		return nil, ErrExpiredToken
	}

	fmt.Println("\033[32m✓ Authorization successful!\033[0m")
	fmt.Println()

	// Get user info
	user, err := g.GetUser(accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Get verified email
	email, err := g.GetVerifiedEmail(accessToken)
	if err != nil {
		return nil, err
	}

	// Create session
	session = &GitHubSession{
		AccessToken:     accessToken,
		GitHubID:        user.ID,
		GitHubLogin:     user.Login,
		Email:           email,
		Name:            user.Name,
		AuthenticatedAt: time.Now(),
	}

	// Save session
	if err := g.SaveSession(session); err != nil {
		return nil, fmt.Errorf("failed to save session: %w", err)
	}

	return session, nil
}

// SaveSession saves the GitHub session to disk
func (g *GitHubAuth) SaveSession(session *GitHubSession) error {
	if err := os.MkdirAll(g.configDir, 0700); err != nil {
		return err
	}

	sessionPath := filepath.Join(g.configDir, "github-session.yaml")

	data, err := yaml.Marshal(session)
	if err != nil {
		return err
	}

	return os.WriteFile(sessionPath, data, 0600)
}

// LoadSession loads the GitHub session from disk
func (g *GitHubAuth) LoadSession() (*GitHubSession, error) {
	sessionPath := filepath.Join(g.configDir, "github-session.yaml")

	data, err := os.ReadFile(sessionPath)
	if err != nil {
		return nil, err
	}

	var session GitHubSession
	if err := yaml.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

// ClearSession removes the saved session
func (g *GitHubAuth) ClearSession() error {
	sessionPath := filepath.Join(g.configDir, "github-session.yaml")
	err := os.Remove(sessionPath)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// IsAuthenticated checks if user is authenticated
func (g *GitHubAuth) IsAuthenticated() bool {
	session, err := g.LoadSession()
	if err != nil || session == nil {
		return false
	}

	// Verify token is still valid
	_, err = g.GetUser(session.AccessToken)
	return err == nil
}

// VerifyEmail performs GitHub auth and returns the verified email
// This is the main function to use for verifying a user's email
func VerifyEmailWithGitHub(configDir, allowedDomain string) (string, error) {
	auth := NewGitHubAuth(configDir, allowedDomain)
	session, err := auth.Authenticate()
	if err != nil {
		return "", err
	}
	return session.Email, nil
}

// PrettyPrint formats the session info for display
func (s *GitHubSession) PrettyPrint() string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("GitHub User: %s (@%s)\n", s.Name, s.GitHubLogin))
	buf.WriteString(fmt.Sprintf("Email:       %s\n", s.Email))
	buf.WriteString(fmt.Sprintf("GitHub ID:   %d\n", s.GitHubID))
	buf.WriteString(fmt.Sprintf("Auth Time:   %s\n", s.AuthenticatedAt.Format(time.RFC3339)))
	return buf.String()
}
