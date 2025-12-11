package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// TestBOLA tests for Broken Object Level Authorization
func TestBOLA(client *http.Client, endpointTemplate string, objectIDs []string, expectedAccessible []string) ([]APIVulnerability, error) {
	var vulns []APIVulnerability

	for _, objID := range objectIDs {
		endpoint := strings.Replace(endpointTemplate, "{id}", objID, -1)
		
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// If we get 200 for an object we shouldn't access, it's BOLA
		if resp.StatusCode == 200 {
			shouldAccess := false
			for _, expected := range expectedAccessible {
				if expected == objID {
					shouldAccess = true
					break
				}
			}

			if !shouldAccess {
				vuln := APIVulnerability{
					VulnID:        fmt.Sprintf("bola_%d", len(vulns)),
					APIType:       "rest",
					OWASPCategory: "API1:2023 Broken Object Level Authorization",
					Title:         "BOLA - Unauthorized Object Access",
					Description:   fmt.Sprintf("User can access object %s without proper authorization", objID),
					Severity:      "critical",
					Endpoint:      endpoint,
					Method:        "GET",
					Parameter:     "id",
					ProofOfConcept: fmt.Sprintf("GET %s returns 200 for unauthorized object", endpoint),
					Impact:        "Unauthorized access to other users' data",
					Remediation:   "Implement object-level authorization checks",
					Evidence:      []string{fmt.Sprintf("Accessed unauthorized object ID: %s", objID)},
					DiscoveredAt:  time.Now(),
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns, nil
}

// TestBFLA tests for Broken Function Level Authorization
func TestBFLA(client *http.Client, adminEndpoints []struct {
	URL    string
	Method string
}) ([]APIVulnerability, error) {
	var vulns []APIVulnerability

	for _, endpointData := range adminEndpoints {
		req, err := http.NewRequest(endpointData.Method, endpointData.URL, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Low privilege user should get 403, not 200
		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			vuln := APIVulnerability{
				VulnID:        fmt.Sprintf("bfla_%d", len(vulns)),
				APIType:       "rest",
				OWASPCategory: "API5:2023 Broken Function Level Authorization",
				Title:         "BFLA - Unauthorized Admin Function Access",
				Description:   fmt.Sprintf("Low privilege user can access admin function: %s %s", endpointData.Method, endpointData.URL),
				Severity:      "critical",
				Endpoint:      endpointData.URL,
				Method:        endpointData.Method,
				ProofOfConcept: fmt.Sprintf("%s %s accessible to regular user", endpointData.Method, endpointData.URL),
				Impact:        "Privilege escalation to admin functions",
				Remediation:   "Implement function-level authorization checks",
				Evidence:      []string{fmt.Sprintf("Response: %d", resp.StatusCode)},
				DiscoveredAt:  time.Now(),
			}
			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}

// TestRateLimiting tests for lack of rate limiting
func TestRateLimiting(client *http.Client, endpoint string, method string, requestsCount int) (*APIVulnerability, error) {
	successCount := 0
	startTime := time.Now()

	for i := 0; i < requestsCount; i++ {
		req, err := http.NewRequest(method, endpoint, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			successCount++
		} else if resp.StatusCode == 429 {
			// Rate limiting is working
			return nil, nil
		}
	}

	elapsed := time.Since(startTime)
	requestsPerSecond := float64(requestsCount) / elapsed.Seconds()

	// If we completed all requests without rate limiting
	if successCount >= requestsCount*9/10 {
		vuln := &APIVulnerability{
			VulnID:        "rate_limit",
			APIType:       "rest",
			OWASPCategory: "API4:2023 Unrestricted Resource Consumption",
			Title:         "Missing Rate Limiting",
			Description:   fmt.Sprintf("No rate limiting on %s", endpoint),
			Severity:      "medium",
			Endpoint:      endpoint,
			Method:        method,
			ProofOfConcept: fmt.Sprintf("Sent %d requests in %.1fs (%.0f req/s)", requestsCount, elapsed.Seconds(), requestsPerSecond),
			Impact:        "API abuse, DoS potential, resource exhaustion",
			Remediation:   "Implement rate limiting (e.g., 100 requests per minute per user)",
			Evidence:      []string{fmt.Sprintf("Successful requests: %d/%d", successCount, requestsCount)},
			DiscoveredAt:  time.Now(),
		}
		return vuln, nil
	}

	return nil, nil
}

