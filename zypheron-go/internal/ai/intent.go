package ai

import (
	"regexp"
	"strings"
)

// Intent represents a parsed user intent
type Intent struct {
	Target         string   // Domain, IP, URL, or file path
	Tools          []string // List of tools to execute
	AnalysisType   string   // Type of analysis requested (architecture, vulnerabilities, etc.)
	Context        string   // Additional context from user query
	RequiresParsing bool    // Whether to use AI for complex parsing
}

// ToolMapping maps natural language keywords to tool commands
var ToolMapping = map[string]string{
	"osint":           "osint",
	"recon":           "recon",
	"reconnaissance":  "recon",
	"scan":            "scan",
	"scanning":        "scan",
	"forensics":       "forensics",
	"forensic":        "forensics",
	"api":             "api-pentest",
	"api test":        "api-pentest",
	"api testing":     "api-pentest",
	"reverse":         "reverse-eng",
	"reverse engineering": "reverse-eng",
	"reverse-eng":      "reverse-eng",
	"fuzz":            "fuzz",
	"fuzzing":         "fuzz",
	"secrets":         "secrets",
	"secret":          "secrets",
	"deps":            "deps",
	"dependencies":    "deps",
	"authenticated":   "authenticated-scan",
	"authenticated scan": "authenticated-scan",
	"pwn":             "pwn",
	"exploitation":    "pwn",
}

// AnalysisKeywords maps keywords to analysis types
var AnalysisKeywords = map[string]string{
	"architecture":    "architecture",
	"arch":           "architecture",
	"structure":      "architecture",
	"maintainer":     "maintainer",
	"maintainers":    "maintainer",
	"owner":          "maintainer",
	"owners":         "maintainer",
	"vulnerability":  "vulnerabilities",
	"vulnerabilities": "vulnerabilities",
	"vuln":           "vulnerabilities",
	"vulns":          "vulnerabilities",
	"security":       "vulnerabilities",
	"exploit":        "vulnerabilities",
	"who":            "maintainer",
	"how":            "architecture",
	"what":           "architecture",
}

// ParseIntent parses natural language to extract intent
// Returns an Intent struct with target, tools, and analysis requirements
func ParseIntent(query string) *Intent {
	query = strings.ToLower(query)
	intent := &Intent{
		Tools:          []string{},
		RequiresParsing: false,
	}

	// Extract target (domain, IP, URL, or file path)
	intent.Target = extractTarget(query)

	// Extract tools
	intent.Tools = extractTools(query)

	// Extract analysis type
	intent.AnalysisType = extractAnalysisType(query)

	// Store context
	intent.Context = query

	// If we couldn't parse well with simple patterns, mark for AI parsing
	if intent.Target == "" || len(intent.Tools) == 0 {
		intent.RequiresParsing = true
	}

	return intent
}

// extractTarget extracts target from query
func extractTarget(query string) string {
	// Patterns for different target types
	patterns := []*regexp.Regexp{
		// URLs
		regexp.MustCompile(`https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
		// Domains
		regexp.MustCompile(`([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})`),
		// IP addresses
		regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`),
		// File paths (Unix/Windows)
		regexp.MustCompile(`(/[^\s]+|([A-Za-z]:)?[\\/][^\s]+)`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(query)
		if len(matches) > 1 && matches[1] != "" {
			// Filter out common false positives
			target := matches[1]
			if !isFalsePositive(target) {
				return target
			}
		}
	}

	return ""
}

// extractTools extracts tool names from query
func extractTools(query string) []string {
	var tools []string
	seen := make(map[string]bool)

	// Check for tool keywords
	for keyword, tool := range ToolMapping {
		if strings.Contains(query, keyword) {
			if !seen[tool] {
				tools = append(tools, tool)
				seen[tool] = true
			}
		}
	}

	return tools
}

// extractAnalysisType extracts the type of analysis requested
func extractAnalysisType(query string) string {
	for keyword, analysisType := range AnalysisKeywords {
		if strings.Contains(query, keyword) {
			return analysisType
		}
	}

	// Default to general analysis
	return "general"
}

// isFalsePositive checks if a potential target is a false positive
func isFalsePositive(target string) bool {
	falsePositives := []string{
		"example.com",
		"localhost",
		"127.0.0.1",
		"0.0.0.0",
	}

	targetLower := strings.ToLower(target)
	for _, fp := range falsePositives {
		if targetLower == fp {
			return true
		}
	}

	return false
}

// ShouldExecuteTools checks if the query requests tool execution
func ShouldExecuteTools(query string) bool {
	queryLower := strings.ToLower(query)
	
	// Keywords that suggest tool execution
	executionKeywords := []string{
		"do", "perform", "run", "execute", "scan", "osint", "recon",
		"test", "check", "analyze", "fuzz", "forensics", "api",
	}

	for _, keyword := range executionKeywords {
		if strings.Contains(queryLower, keyword) {
			return true
		}
	}

	return false
}

