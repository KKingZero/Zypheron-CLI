package validation

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
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
		return fmt.Errorf("target cannot be empty.\n  Provide a target in one of these formats:\n    - Domain: example.com\n    - IPv4: 192.168.1.1\n    - IPv6: ::1\n    - CIDR: 192.168.1.0/24\n  Example: zypheron scan example.com")
	}

	// Enforce maximum length to prevent DoS
	if len(target) > 512 {
		return fmt.Errorf("target '%s' is too long (maximum 512 characters, got %d).\n  Try using a shorter hostname or IP address", target, len(target))
	}

	target = strings.TrimSpace(target)

	// Check for shell metacharacters
	if containsShellMetachars(target) {
		return fmt.Errorf("target '%s' contains invalid shell metacharacters.\n  Targets can only contain alphanumeric characters, dots, hyphens, colons, and slashes.\n  Invalid characters: ; & | ` $ ( ) < > etc.\n  Example of valid targets: example.com, 192.168.1.1, https://api.example.com", target)
	}

	// Check if it's a URL first (before CIDR check, since URLs contain /)
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "ftp://") {
		if isValidDomainOrURL(target) {
			return nil
		}
		return fmt.Errorf("invalid URL format '%s'.\n  URLs must have a valid domain.\n  Example: https://example.com", target)
	}

	// Check if it's a CIDR range (only if not a URL)
	if strings.Contains(target, "/") {
		_, _, err := net.ParseCIDR(target)
		if err != nil {
			return fmt.Errorf("invalid CIDR range '%s': %w.\n  CIDR ranges must be in format: IP/MASK\n  Examples:\n    - IPv4: 192.168.1.0/24\n    - IPv6: 2001:db8::/32", target, err)
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

	return fmt.Errorf("invalid target format '%s'.\n  Target must be one of:\n    - Domain name: example.com, subdomain.example.com\n    - IPv4 address: 192.168.1.1\n    - IPv6 address: 2001:db8::1 or ::1\n    - CIDR range: 192.168.1.0/24\n    - URL: https://example.com or http://api.example.com\n  Example: zypheron scan example.com", target)
}

// ValidatePorts validates port numbers and port ranges
func ValidatePorts(ports string) error {
	if ports == "" {
		return fmt.Errorf("ports cannot be empty.\n  Specify ports in one of these formats:\n    - Single port: 80\n    - Multiple ports: 80,443,8080\n    - Port range: 1-1000\n    - Combined: 80,443,8000-9000\n  Example: zypheron scan example.com --ports 80,443")
	}

	// Enforce maximum length to prevent DoS
	if len(ports) > 256 {
		return fmt.Errorf("ports specification '%s' is too long (maximum 256 characters, got %d).\n  Try using port ranges instead of listing individual ports.\n  Example: 1-1000 instead of 1,2,3,...,1000", ports, len(ports))
	}

	ports = strings.TrimSpace(ports)

	// Check for shell metacharacters
	if containsShellMetachars(ports) {
		return fmt.Errorf("ports '%s' contain invalid characters.\n  Ports can only contain digits, commas, and hyphens.\n  Examples:\n    - Valid: 80,443,8000-9000\n    - Invalid: 80;443 (no semicolons), 80|443 (no pipes)", ports)
	}

	// Split by comma for multiple port specifications
	portSpecs := strings.Split(ports, ",")

	for _, spec := range portSpecs {
		spec = strings.TrimSpace(spec)

		// Check if it's a range (e.g., "1-1000")
		if strings.Contains(spec, "-") {
			parts := strings.Split(spec, "-")
			if len(parts) != 2 {
				return fmt.Errorf("invalid port range format '%s'.\n  Port ranges must have exactly one hyphen: START-END\n  Example: 8000-9000", spec)
			}

			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil || start < 1 || start > 65535 {
				return fmt.Errorf("invalid start port '%s' in range.\n  Port numbers must be between 1 and 65535.\n  You provided: %s", parts[0], spec)
			}

			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil || end < 1 || end > 65535 {
				return fmt.Errorf("invalid end port '%s' in range.\n  Port numbers must be between 1 and 65535.\n  You provided: %s", parts[1], spec)
			}

			if start > end {
				return fmt.Errorf("start port %d cannot be greater than end port %d.\n  Port ranges must be in format: LOWER-HIGHER\n  Example: 8000-9000 (not 9000-8000)", start, end)
			}
		} else {
			// Single port
			port, err := strconv.Atoi(spec)
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("invalid port number '%s'.\n  Port numbers must be integers between 1 and 65535.\n  Examples: 80, 443, 8080", spec)
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
	// Comprehensive list of dangerous shell metacharacters
	dangerous := []string{
		";", "&", "|", "`", "$", "(", ")", "<", ">",
		"\n", "\r", "\t", "\\", "!", "~", "{", "}",
		"[", "]", "*", "?", "#", "%", "^",
	}

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
		return fmt.Errorf("file path cannot be empty.\n  Specify where to save the output file.\n  Example: zypheron scan example.com --output /tmp/scan-report.txt")
	}

	// Enforce maximum length to prevent DoS
	if len(path) > 4096 {
		return fmt.Errorf("file path '%s' is too long (maximum 4096 characters, got %d).\n  Use a shorter file path.", path, len(path))
	}

	// Decode URL encoding to catch obfuscated traversal attempts
	decodedPath, err := url.PathUnescape(path)
	if err != nil {
		return fmt.Errorf("invalid path encoding in '%s': %w.\n  File paths should not contain URL-encoded characters.\n  Use a simple path like: /tmp/report.txt", path, err)
	}

	// Check for path traversal in both original and decoded paths
	if strings.Contains(path, "..") || strings.Contains(decodedPath, "..") {
		return fmt.Errorf("path traversal (..) is not allowed in file path '%s'.\n  This is a security restriction.\n  Use absolute paths instead.\n  Example: /tmp/report.txt (not ../report.txt)", path)
	}

	// Check for null bytes (can truncate paths in some C implementations)
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("null bytes are not allowed in file path '%s'.\n  This is a security restriction.\n  Use a clean file path without special characters.", path)
	}

	// Resolve to absolute path and ensure it doesn't escape
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path for '%s': %w.\n  Make sure the path is valid and the parent directory exists.\n  Example: /home/user/reports/scan.txt", path, err)
	}

	// Additional security: prevent absolute paths that might escape to sensitive directories
	// This is a basic check - adjust based on your security requirements
	sensitivePatterns := []string{"/etc/", "/proc/", "/sys/", "/dev/"}
	absPathLower := strings.ToLower(absPath)
	for _, pattern := range sensitivePatterns {
		if strings.HasPrefix(absPathLower, pattern) {
			return fmt.Errorf("access to sensitive system directory '%s' is not allowed.\n  For security reasons, reports cannot be saved to system directories.\n  Use a user directory instead.\n  Example: /home/user/reports/scan.txt or /tmp/scan.txt", pattern)
		}
	}

	return nil
}
