package api

import (
	"fmt"
	"net/http"
	"time"
)

// APIScanner represents an API security scanner
type APIScanner struct {
	BaseURL      string
	Client       *http.Client
	Vulnerabilities []APIVulnerability
	Endpoints    []APIEndpoint
}

// NewAPIScanner creates a new API scanner
func NewAPIScanner(baseURL string, timeout time.Duration) *APIScanner {
	return &APIScanner{
		BaseURL: baseURL,
		Client: &http.Client{
			Timeout: timeout,
		},
		Vulnerabilities: []APIVulnerability{},
		Endpoints:       []APIEndpoint{},
	}
}

// Discover discovers API endpoints
func (s *APIScanner) Discover() error {
	endpoints, err := DiscoverEndpoints(s.BaseURL, s.Client.Timeout)
	if err != nil {
		return fmt.Errorf("endpoint discovery failed: %w", err)
	}

	s.Endpoints = endpoints
	return nil
}

// Scan performs a comprehensive API security scan
func (s *APIScanner) Scan() error {
	// Discover endpoints
	if err := s.Discover(); err != nil {
		return err
	}

	// Test each discovered endpoint
	for _, endpoint := range s.Endpoints {
		if !endpoint.IsBackend {
			continue
		}

		// Test rate limiting
		vuln, err := TestRateLimiting(s.Client, endpoint.URL, "GET", 100)
		if err == nil && vuln != nil {
			s.Vulnerabilities = append(s.Vulnerabilities, *vuln)
		}
	}

	return nil
}

// GetReport generates a security report
func (s *APIScanner) GetReport() map[string]interface{} {
	bySeverity := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	byOWASP := map[string]int{}

	for _, vuln := range s.Vulnerabilities {
		bySeverity[vuln.Severity]++
		byOWASP[vuln.OWASPCategory]++
	}

	return map[string]interface{}{
		"total_vulnerabilities": len(s.Vulnerabilities),
		"endpoints_tested":      len(s.Endpoints),
		"by_severity":           bySeverity,
		"by_owasp_category":    byOWASP,
		"critical_count":        bySeverity["critical"],
		"vulnerabilities":       s.Vulnerabilities,
	}
}

