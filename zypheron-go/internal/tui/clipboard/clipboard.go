// Package clipboard provides secure clipboard integration for Zypheron TUI.
// Features configurable security controls including confirmation dialogs,
// content filtering for sensitive data, and optional audit logging.
package clipboard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Config holds clipboard security settings.
// All settings are configurable to allow users to balance security vs convenience.
type Config struct {
	// RequireConfirmation prompts user before copying sensitive data.
	// When true, displays a confirmation dialog before copying.
	// Default: true for security-conscious environments.
	RequireConfirmation bool

	// EnableFiltering masks or blocks sensitive patterns (IPs, credentials, API keys).
	// When true, detected sensitive data is redacted before copying.
	// Default: true to prevent accidental exposure.
	EnableFiltering bool

	// EnableAuditLog writes all clipboard operations to ~/.zypheron/logs/clipboard.log.
	// Useful for compliance and security auditing.
	// Default: false (opt-in for privacy).
	EnableAuditLog bool

	// AllowedPatterns specifies regex patterns that are always allowed.
	// Items matching these patterns bypass filtering.
	AllowedPatterns []string

	// BlockedPatterns specifies regex patterns that are always blocked.
	// Items matching these patterns are never copied.
	BlockedPatterns []string
}

// DefaultConfig returns a Config with sensible security defaults.
// Confirmation is enabled, filtering is enabled, audit logging is disabled.
func DefaultConfig() Config {
	return Config{
		RequireConfirmation: true,
		EnableFiltering:     true,
		EnableAuditLog:      false,
		AllowedPatterns:     []string{},
		BlockedPatterns:     []string{},
	}
}

// ConvenienceConfig returns a Config optimized for convenience.
// Reduces prompts while maintaining basic filtering.
func ConvenienceConfig() Config {
	return Config{
		RequireConfirmation: false,
		EnableFiltering:     true,
		EnableAuditLog:      false,
		AllowedPatterns:     []string{},
		BlockedPatterns:     []string{},
	}
}

// StrictConfig returns a Config with maximum security.
// All protections enabled including audit logging.
func StrictConfig() Config {
	return Config{
		RequireConfirmation: true,
		EnableFiltering:     true,
		EnableAuditLog:      true,
		AllowedPatterns:     []string{},
		BlockedPatterns:     []string{},
	}
}

// SensitiveType categorizes detected sensitive content.
type SensitiveType int

const (
	TypeNone SensitiveType = iota
	TypeIPAddress
	TypePrivateIP
	TypeAPIKey
	TypePassword
	TypeSSHKey
	TypeAWSCredential
	TypeJWT
	TypeEmail
	TypeCreditCard
)

// String returns a human-readable name for the sensitive type.
func (t SensitiveType) String() string {
	switch t {
	case TypeIPAddress:
		return "IP Address"
	case TypePrivateIP:
		return "Private IP"
	case TypeAPIKey:
		return "API Key"
	case TypePassword:
		return "Password"
	case TypeSSHKey:
		return "SSH Key"
	case TypeAWSCredential:
		return "AWS Credential"
	case TypeJWT:
		return "JWT Token"
	case TypeEmail:
		return "Email Address"
	case TypeCreditCard:
		return "Credit Card"
	default:
		return "None"
	}
}

// Detection represents a detected sensitive content pattern.
type Detection struct {
	Type     SensitiveType
	Match    string // The actual matched content
	Position int    // Start position in original text
	Redacted string // Redacted version of the match
}

// CopyResult represents the result of a clipboard copy operation.
type CopyResult struct {
	Success    bool
	Original   string       // Original text before filtering
	Filtered   string       // Text after filtering (if enabled)
	Detections []Detection  // List of detected sensitive content
	Blocked    bool         // Whether the operation was blocked
	Reason     string       // Reason for blocking (if blocked)
	Timestamp  time.Time    // When the operation occurred
}

// Clipboard provides secure clipboard operations.
// Thread-safe and configurable through Config.
type Clipboard struct {
	config  Config
	mu      sync.RWMutex
	logFile *os.File

	// Compiled regex patterns for efficiency
	patterns map[SensitiveType]*regexp.Regexp
}

// New creates a new Clipboard with the specified configuration.
func New(cfg Config) (*Clipboard, error) {
	c := &Clipboard{
		config:   cfg,
		patterns: make(map[SensitiveType]*regexp.Regexp),
	}

	// Compile detection patterns
	if err := c.compilePatterns(); err != nil {
		return nil, fmt.Errorf("failed to compile patterns: %w", err)
	}

	// Initialize audit log if enabled
	if cfg.EnableAuditLog {
		if err := c.initAuditLog(); err != nil {
			// Log error but don't fail - clipboard can work without logging
			fmt.Fprintf(os.Stderr, "Warning: Failed to initialize audit log: %v\n", err)
		}
	}

	return c, nil
}

// compilePatterns compiles all regex patterns for sensitive content detection.
func (c *Clipboard) compilePatterns() error {
	patterns := map[SensitiveType]string{
		// IPv4 addresses (more permissive to catch all formats)
		TypeIPAddress: `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,

		// Private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
		TypePrivateIP: `\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b`,

		// API keys (common formats: long alphanumeric strings, often with prefixes)
		TypeAPIKey: `(?i)(?:api[_-]?key|apikey|api_secret|secret[_-]?key)[:\s=]+["']?([a-zA-Z0-9_\-]{20,})["']?`,

		// Password patterns (key=value or json format)
		TypePassword: `(?i)(?:password|passwd|pwd|secret)[:\s=]+["']?([^\s"']{4,})["']?`,

		// SSH private key markers
		TypeSSHKey: `-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`,

		// AWS access keys (AKIA followed by 16 chars)
		TypeAWSCredential: `(?:AKIA|ABIA|ACCA)[A-Z0-9]{16}`,

		// JWT tokens (three base64 segments separated by dots)
		TypeJWT: `eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`,

		// Email addresses
		TypeEmail: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,

		// Credit card numbers (basic pattern - 13-19 digits, possibly grouped)
		TypeCreditCard: `\b(?:\d{4}[\s-]?){3}\d{1,7}\b`,
	}

	for t, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("failed to compile pattern for %s: %w", t.String(), err)
		}
		c.patterns[t] = re
	}

	return nil
}

// initAuditLog initializes the audit log file.
func (c *Clipboard) initAuditLog() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	logDir := filepath.Join(homeDir, ".zypheron", "logs")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	logPath := filepath.Join(logDir, "clipboard.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	c.logFile = f
	return nil
}

// Close releases resources used by the Clipboard.
func (c *Clipboard) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.logFile != nil {
		return c.logFile.Close()
	}
	return nil
}

// Detect scans text for sensitive content patterns.
// Returns all detections found in the text.
func (c *Clipboard) Detect(text string) []Detection {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var detections []Detection

	for t, pattern := range c.patterns {
		matches := pattern.FindAllStringIndex(text, -1)
		for _, match := range matches {
			content := text[match[0]:match[1]]
			detection := Detection{
				Type:     t,
				Match:    content,
				Position: match[0],
				Redacted: c.redact(content, t),
			}
			detections = append(detections, detection)
		}
	}

	return detections
}

// redact masks sensitive content based on its type.
func (c *Clipboard) redact(content string, t SensitiveType) string {
	// Keep first and last few chars for context, mask the middle
	switch t {
	case TypeIPAddress, TypePrivateIP:
		// Show network portion, mask host: 192.168.xxx.xxx
		parts := strings.Split(content, ".")
		if len(parts) == 4 {
			return parts[0] + "." + parts[1] + ".xxx.xxx"
		}
		return "xxx.xxx.xxx.xxx"

	case TypeAPIKey, TypePassword, TypeAWSCredential:
		// Show first 4 and last 2 chars: abcd...xy
		if len(content) > 8 {
			return content[:4] + "..." + content[len(content)-2:]
		}
		return "****"

	case TypeSSHKey:
		return "[SSH PRIVATE KEY REDACTED]"

	case TypeJWT:
		// Show header, mask payload and signature
		parts := strings.Split(content, ".")
		if len(parts) == 3 {
			return parts[0] + ".[PAYLOAD].[SIGNATURE]"
		}
		return "[JWT REDACTED]"

	case TypeEmail:
		// Show domain: ***@example.com
		atIdx := strings.LastIndex(content, "@")
		if atIdx > 0 {
			return "***" + content[atIdx:]
		}
		return "***@***"

	case TypeCreditCard:
		// Show last 4 digits: ****-****-****-1234
		digits := regexp.MustCompile(`\d`).FindAllString(content, -1)
		if len(digits) >= 4 {
			return "****-****-****-" + strings.Join(digits[len(digits)-4:], "")
		}
		return "****-****-****-****"

	default:
		return "[REDACTED]"
	}
}

// Filter applies redaction to all detected sensitive content in text.
func (c *Clipboard) Filter(text string) (string, []Detection) {
	detections := c.Detect(text)
	if len(detections) == 0 {
		return text, nil
	}

	filtered := text
	// Process in reverse order to maintain correct positions
	for i := len(detections) - 1; i >= 0; i-- {
		d := detections[i]
		filtered = filtered[:d.Position] + d.Redacted + filtered[d.Position+len(d.Match):]
	}

	return filtered, detections
}

// ShouldBlock checks if text contains patterns that should always be blocked.
func (c *Clipboard) ShouldBlock(text string) (bool, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check blocked patterns from config
	for _, pattern := range c.config.BlockedPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(text) {
			return true, fmt.Sprintf("Matches blocked pattern: %s", pattern)
		}
	}

	// Always block SSH private keys
	if c.patterns[TypeSSHKey].MatchString(text) {
		return true, "Contains SSH private key - copying is blocked for security"
	}

	return false, ""
}

// Copy prepares text for clipboard copying with security checks.
// Does NOT actually copy to clipboard - returns result for caller to handle.
//
// The caller is responsible for:
// 1. Showing confirmation dialog if result.RequiresConfirmation
// 2. Actually writing to system clipboard if result.Success
// 3. Handling blocked operations
//
// This design keeps the clipboard module focused on security logic
// and allows the TUI to handle user interaction.
func (c *Clipboard) Copy(text string) CopyResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	result := CopyResult{
		Original:  text,
		Filtered:  text,
		Timestamp: time.Now(),
	}

	// Check if should be blocked entirely
	if blocked, reason := c.ShouldBlock(text); blocked {
		result.Blocked = true
		result.Reason = reason
		c.logOperation(result)
		return result
	}

	// Detect and optionally filter sensitive content
	if c.config.EnableFiltering {
		filtered, detections := c.Filter(text)
		result.Filtered = filtered
		result.Detections = detections
	} else {
		result.Detections = c.Detect(text)
	}

	result.Success = true
	c.logOperation(result)
	return result
}

// NeedsConfirmation returns whether the given result requires user confirmation.
func (c *Clipboard) NeedsConfirmation(result CopyResult) bool {
	return c.config.RequireConfirmation && len(result.Detections) > 0
}

// logOperation writes clipboard operation to audit log if enabled.
func (c *Clipboard) logOperation(result CopyResult) {
	if !c.config.EnableAuditLog || c.logFile == nil {
		return
	}

	var detectionTypes []string
	for _, d := range result.Detections {
		detectionTypes = append(detectionTypes, d.Type.String())
	}

	status := "SUCCESS"
	if result.Blocked {
		status = "BLOCKED"
	}

	entry := fmt.Sprintf("[%s] %s | Detections: %s | Reason: %s | Length: %d chars\n",
		result.Timestamp.Format(time.RFC3339),
		status,
		strings.Join(detectionTypes, ", "),
		result.Reason,
		len(result.Original),
	)

	// Write is thread-safe because we're under the mutex
	_, _ = c.logFile.WriteString(entry)
}

// UpdateConfig updates the clipboard configuration.
// Thread-safe operation.
func (c *Clipboard) UpdateConfig(cfg Config) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = cfg
}

// GetConfig returns a copy of the current configuration.
func (c *Clipboard) GetConfig() Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config
}

// FormatDetectionsMessage creates a user-friendly message about detected content.
// Used for confirmation dialogs.
func FormatDetectionsMessage(detections []Detection) string {
	if len(detections) == 0 {
		return ""
	}

	counts := make(map[SensitiveType]int)
	for _, d := range detections {
		counts[d.Type]++
	}

	var parts []string
	for t, count := range counts {
		if count == 1 {
			parts = append(parts, t.String())
		} else {
			parts = append(parts, fmt.Sprintf("%d %ss", count, t.String()))
		}
	}

	return "Detected sensitive content: " + strings.Join(parts, ", ")
}
