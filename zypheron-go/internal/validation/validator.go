package validation

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// AllowedTools is a whitelist of permitted security tools
var AllowedTools = map[string]bool{
	"nmap":         true,
	"nikto":        true,
	"nuclei":       true,
	"masscan":      true,
	"sqlmap":       true,
	"hydra":        true,
	"metasploit":   true,
	"gobuster":     true,
	"ffuf":         true,
	"subfinder":    true,
	"amass":        true,
	"theharvester": true,
	"aircrack-ng":  true,
	"john":         true,
	"hashcat":      true,
}

// ValidateToolName validates that a tool name is in the allowlist
func ValidateToolName(tool string) error {
	if tool == "" {
		return fmt.Errorf("tool name cannot be empty")
	}

	tool = strings.ToLower(strings.TrimSpace(tool))

	if !AllowedTools[tool] {
		return fmt.Errorf("tool '%s' is not allowed", tool)
	}

	return nil
}

// ValidateTarget validates IP addresses, domains, and CIDR ranges
func ValidateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	target = strings.TrimSpace(target)

	// Check for shell metacharacters
	if containsShellMetachars(target) {
		return fmt.Errorf("target contains invalid characters")
	}

	// Check if it's a CIDR range
	if strings.Contains(target, "/") {
		_, _, err := net.ParseCIDR(target)
		if err != nil {
			return fmt.Errorf("invalid CIDR range: %w", err)
		}
		return nil
	}

	// Check if it's an IP address
	if net.ParseIP(target) != nil {
		return nil
	}

	// Check if it's a valid domain/hostname (including URLs)
	if isValidDomainOrURL(target) {
		return nil
	}

	return fmt.Errorf("invalid target format (must be IP, domain, URL, or CIDR)")
}

// ValidatePorts validates port numbers and port ranges
func ValidatePorts(ports string) error {
	if ports == "" {
		return fmt.Errorf("ports cannot be empty")
	}

	ports = strings.TrimSpace(ports)

	// Check for shell metacharacters
	if containsShellMetachars(ports) {
		return fmt.Errorf("ports contain invalid characters")
	}

	// Split by comma for multiple port specifications
	portSpecs := strings.Split(ports, ",")

	for _, spec := range portSpecs {
		spec = strings.TrimSpace(spec)

		// Check if it's a range (e.g., "1-1000")
		if strings.Contains(spec, "-") {
			parts := strings.Split(spec, "-")
			if len(parts) != 2 {
				return fmt.Errorf("invalid port range format: %s", spec)
			}

			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil || start < 1 || start > 65535 {
				return fmt.Errorf("invalid start port in range: %s", parts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil || end < 1 || end > 65535 {
				return fmt.Errorf("invalid end port in range: %s", parts[1])
			}

			if start > end {
				return fmt.Errorf("start port cannot be greater than end port: %s", spec)
			}
		} else {
			// Single port
			port, err := strconv.Atoi(spec)
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("invalid port number: %s", spec)
			}
		}
	}

	return nil
}

// SanitizeInput removes or escapes potentially dangerous characters
func SanitizeInput(input string) string {
	// Remove shell metacharacters
	dangerous := []string{";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r", "\\"}

	result := input
	for _, char := range dangerous {
		result = strings.ReplaceAll(result, char, "")
	}

	return strings.TrimSpace(result)
}

// containsShellMetachars checks for dangerous shell metacharacters
func containsShellMetachars(input string) bool {
	dangerous := []string{";", "&", "|", "`", "$", "(", ")", "\n", "\r", "\\", "!", "~"}

	for _, char := range dangerous {
		if strings.Contains(input, char) {
			return true
		}
	}

	return false
}

// isValidDomainOrURL validates domain names and URLs
func isValidDomainOrURL(input string) bool {
	// Remove protocol if present
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "ftp://")

	// Remove path if present
	if idx := strings.Index(input, "/"); idx != -1 {
		input = input[:idx]
	}

	// Remove port if present
	if idx := strings.Index(input, ":"); idx != -1 {
		input = input[:idx]
	}

	// Domain/hostname pattern
	// Allows alphanumeric, hyphens, dots, and underscores
	pattern := `^[a-zA-Z0-9]([a-zA-Z0-9\-\.\_]*[a-zA-Z0-9])?$`
	matched, _ := regexp.MatchString(pattern, input)

	return matched && len(input) > 0 && len(input) <= 253
}

// ValidateFilePath validates file paths for report output
func ValidateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed")
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("null bytes not allowed in file path")
	}

	return nil
}
