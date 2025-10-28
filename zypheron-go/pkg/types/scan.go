package types

import "time"

// ScanResult represents the result of a security scan
type ScanResult struct {
	ID              string            `json:"id"`
	Timestamp       time.Time         `json:"timestamp"`
	Target          string            `json:"target"`
	Tool            string            `json:"tool"`
	Ports           string            `json:"ports"`
	Output          string            `json:"output"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities"`
	AIAnalysis      string            `json:"ai_analysis,omitempty"`
	Duration        float64           `json:"duration"`
	Success         bool              `json:"success"`
	ErrorMessage    string            `json:"error_message,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// Vulnerability represents a discovered security vulnerability
type Vulnerability struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Severity         string   `json:"severity"`
	CVSSScore        *float64 `json:"cvss_score,omitempty"`
	CVEID            *string  `json:"cve_id,omitempty"`
	Port             *int     `json:"port,omitempty"`
	Host             *string  `json:"host,omitempty"`
	Remediation      *string  `json:"remediation,omitempty"`
	ExploitAvailable bool     `json:"exploit_available"`
	References       []string `json:"references,omitempty"`
}

// ScanSummary represents a brief summary of a scan
type ScanSummary struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	Target        string    `json:"target"`
	Tool          string    `json:"tool"`
	Success       bool      `json:"success"`
	VulnCount     int       `json:"vuln_count"`
	CriticalCount int       `json:"critical_count"`
	HighCount     int       `json:"high_count"`
}
