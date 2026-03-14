// +build ignore

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/reports"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/session"
)

func main() {
	// Create a sample session with realistic data
	sess := session.NewSession("192.168.1.100", session.ScanTypeNmap)

	// Add findings
	sess.AddFinding(session.Finding{
		Type:        "port",
		Title:       "Open Port 22 (SSH)",
		Description: "SSH service is accessible",
		Severity:    "info",
		Details: map[string]interface{}{
			"protocol": "tcp",
			"state":    "open",
		},
	})

	sess.AddFinding(session.Finding{
		Type:        "port",
		Title:       "Open Port 80 (HTTP)",
		Description: "HTTP service is running",
		Severity:    "info",
		Details: map[string]interface{}{
			"protocol": "tcp",
			"state":    "open",
			"banner":   "Apache/2.4.41 (Ubuntu)",
		},
	})

	sess.AddFinding(session.Finding{
		Type:        "service",
		Title:       "Apache Web Server Detected",
		Description: "Apache 2.4.41 running on Ubuntu",
		Severity:    "info",
	})

	// Add vulnerabilities
	sess.AddVulnerability(session.Vulnerability{
		CVEID:            "CVE-2023-1234",
		Title:            "SQL Injection in Login Form",
		Description:      "The application login form is vulnerable to SQL injection attacks, allowing attackers to bypass authentication",
		Severity:         "critical",
		CVSSScore:        9.8,
		Port:             80,
		Service:          "http",
		ExploitAvailable: true,
		Remediation:      "Implement parameterized queries and input validation. Update to latest framework version.",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
			"https://example.com/security-advisory",
		},
	})

	sess.AddVulnerability(session.Vulnerability{
		CVEID:            "CVE-2023-5678",
		Title:            "Cross-Site Scripting (XSS)",
		Description:      "Reflected XSS vulnerability in search parameter allows execution of arbitrary JavaScript",
		Severity:         "high",
		CVSSScore:        7.4,
		Port:             80,
		Service:          "http",
		ExploitAvailable: false,
		Remediation:      "Sanitize all user input and implement Content Security Policy headers",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2023-5678",
		},
	})

	sess.AddVulnerability(session.Vulnerability{
		Title:            "Directory Listing Enabled",
		Description:      "Web server allows directory browsing, potentially exposing sensitive files",
		Severity:         "medium",
		CVSSScore:        5.3,
		Port:             80,
		Service:          "http",
		ExploitAvailable: false,
		Remediation:      "Disable directory listing in Apache configuration (Options -Indexes)",
	})

	sess.AddVulnerability(session.Vulnerability{
		Title:            "Outdated SSL/TLS Configuration",
		Description:      "Server supports deprecated TLS 1.0 protocol",
		Severity:         "low",
		CVSSScore:        3.7,
		Port:             443,
		Service:          "https",
		ExploitAvailable: false,
		Remediation:      "Disable TLS 1.0 and enable only TLS 1.2 and 1.3",
	})

	// Set raw output
	sess.AppendRawOutput(`Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.100
Host is up (0.0012s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Welcome to Example.com

Service detection performed. Please report any incorrect results at https://nmap.org/submit/
Nmap done: 1 IP address (1 host up) scanned in 8.42 seconds
`)

	// Set AI analysis
	sess.SetAIAnalysis("The target appears to be a standard Ubuntu web server running Apache. Critical SQL injection vulnerability was detected in the login form, requiring immediate attention. The server also has several configuration issues including directory listing and outdated TLS protocols.")

	// Set summary
	sess.SetSummary("Scan completed successfully. Discovered 2 open ports, 3 services, and 4 vulnerabilities (1 critical, 1 high, 1 medium, 1 low).")

	// Add notes
	sess.Notes = "Initial reconnaissance scan. Follow-up required for SQL injection vulnerability testing."

	// Mark session as complete
	sess.Complete()

	// Generate report
	tmpDir := os.TempDir()
	outputPath := filepath.Join(tmpDir, "zypheron_sample_report.json")

	err := reports.ExportJSON(sess, outputPath)
	if err != nil {
		log.Fatalf("Failed to export report: %v", err)
	}

	// Read and display the report
	data, err := os.ReadFile(outputPath)
	if err != nil {
		log.Fatalf("Failed to read report: %v", err)
	}

	fmt.Println("Sample JSON Report:")
	fmt.Println("==================")
	fmt.Println(string(data))
	fmt.Println()
	fmt.Printf("Report saved to: %s\n", outputPath)
}
