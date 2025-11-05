package api

import "time"

// APIVulnerability represents an API-specific vulnerability
type APIVulnerability struct {
	VulnID         string
	APIType        string // rest, graphql, soap
	OWASPCategory  string // API1, API2, etc.
	Title          string
	Description    string
	Severity       string // critical, high, medium, low
	Endpoint       string
	Method         string
	Parameter      string
	ProofOfConcept string
	RequestExample string
	ResponseExample string
	Evidence       []string
	Impact         string
	Remediation    string
	DiscoveredAt   time.Time
}

// GetSeverityColor returns a color code for severity
func (v *APIVulnerability) GetSeverityColor() string {
	switch v.Severity {
	case "critical":
		return "red"
	case "high":
		return "yellow"
	case "medium":
		return "cyan"
	default:
		return "white"
	}
}

// OWASPAPICategories represents OWASP API Security Top 10 categories
var OWASPAPICategories = map[string]string{
	"API1": "Broken Object Level Authorization",
	"API2": "Broken Authentication",
	"API3": "Broken Object Property Level Authorization",
	"API4": "Unrestricted Resource Consumption",
	"API5": "Broken Function Level Authorization",
	"API6": "Unrestricted Access to Sensitive Business Flows",
	"API7": "Server Side Request Forgery (SSRF)",
	"API8": "Security Misconfiguration",
	"API9": "Improper Inventory Management",
	"API10": "Unsafe Consumption of APIs",
}

