package tui

import (
	"strings"
)

// IntentType represents the classified intent of user input
type IntentType int

const (
	IntentChat     IntentType = iota // General question/conversation
	IntentScan                       // Execute a scan
	IntentFollowUp                   // Reference previous results
	IntentCommand                    // Execute a specific command
	IntentClarify                    // User needs clarification
)

// String returns a string representation of the intent type
func (i IntentType) String() string {
	switch i {
	case IntentChat:
		return "chat"
	case IntentScan:
		return "scan"
	case IntentFollowUp:
		return "followup"
	case IntentCommand:
		return "command"
	case IntentClarify:
		return "clarify"
	default:
		return "unknown"
	}
}

// ParsedIntent represents the result of intent classification
type ParsedIntent struct {
	Type        IntentType
	Target      string
	Tool        string
	Query       string
	NeedsTarget bool
	Confidence  float64
	References  []string // References to previous findings
}

// ClassifyIntent uses rule-based classification to determine user intent
func ClassifyIntent(input string, hasRecentFindings bool) ParsedIntent {
	lower := strings.ToLower(input)
	trimmed := strings.TrimSpace(input)

	// Obvious slash commands - always command
	if strings.HasPrefix(trimmed, "/") {
		return ParsedIntent{Type: IntentCommand, Query: input, Confidence: 1.0}
	}

	// Very short inputs with "?" - likely clarification needed
	if strings.HasSuffix(trimmed, "?") && len(trimmed) < 15 {
		return ParsedIntent{Type: IntentClarify, Query: input, Confidence: 0.8}
	}

	// Clear scan keywords with explicit tool names + target pattern
	explicitToolKeywords := []string{
		"nmap", "nikto", "nuclei", "httpx", "katana", "gau", "waybackurls", "assetfinder",
		"feroxbuster", "dirsearch", "wfuzz", "kiterunner", "newman", "schemathesis",
		"jwt-tool", "gobuster", "ffuf", "sqlmap", "hydra", "amass", "subfinder", "masscan",
		"whatweb", "wpscan",
	}
	for _, tool := range explicitToolKeywords {
		if strings.Contains(lower, tool) && containsTargetPattern(input) {
			target := extractTarget(input)
			return ParsedIntent{
				Type:        IntentScan,
				Target:      target,
				Tool:        tool,
				Query:       input,
				NeedsTarget: target == "",
				Confidence:  0.95,
			}
		}
	}

	// Clear action keywords with target
	actionKeywords := []string{
		"scan ", "pentest ", "attack ", "enumerate ", "recon ",
		"bruteforce ", "fuzz ", "exploit ", "probe ", "discover ",
		"crawl ", "fingerprint ", "sweep ", "audit ",
	}
	for _, kw := range actionKeywords {
		if strings.Contains(lower, kw) && containsTargetPattern(input) {
			target := extractTarget(input)
			return ParsedIntent{
				Type:        IntentScan,
				Target:      target,
				Query:       input,
				NeedsTarget: target == "",
				Confidence:  0.85,
			}
		}
	}

	// Scan keywords without a target pattern
	scanKeywords := []string{
		"scan", "pentest", "enumerate", "recon", "attack",
		"find vulnerabilities", "check security",
		"bruteforce", "fuzz", "exploit", "probe", "discover",
		"crawl", "fingerprint", "sweep", "audit",
	}
	for _, kw := range scanKeywords {
		if strings.Contains(lower, kw) {
			target := extractTarget(input)
			return ParsedIntent{
				Type:        IntentScan,
				Target:      target,
				Query:       input,
				NeedsTarget: target == "",
				Confidence:  0.7,
			}
		}
	}

	// Follow-up indicators (only relevant if we have findings)
	if hasRecentFindings {
		followUpPatterns := []string{
			"that vulnerability", "this finding", "the scan", "those results",
			"port 80", "port 443", "the server", "apache", "nginx",
			"exploit it", "attack path", "what about", "tell me more",
			"how do i", "can you explain",
			"what next", "how to exploit", "next steps", "deeper scan",
			"more info on", "escalate", "cve-", "port ",
			"service ", "open port",
		}
		for _, pattern := range followUpPatterns {
			if strings.Contains(lower, pattern) {
				return ParsedIntent{Type: IntentFollowUp, Query: input, Confidence: 0.7}
			}
		}
	}

	// Default to chat
	return ParsedIntent{Type: IntentChat, Query: input, Confidence: 0.5}
}

// containsTargetPattern checks if the input contains something that looks like a target
func containsTargetPattern(s string) bool {
	// Check for IP, domain, or URL patterns
	hasIP := strings.ContainsAny(s, "0123456789") && strings.Contains(s, ".")
	hasDomain := strings.Contains(s, ".com") || strings.Contains(s, ".net") ||
		strings.Contains(s, ".org") || strings.Contains(s, ".io") ||
		strings.Contains(s, ".local") || strings.Contains(s, ".dev")
	hasURL := strings.Contains(s, "http://") || strings.Contains(s, "https://")

	return hasIP || hasDomain || hasURL
}
