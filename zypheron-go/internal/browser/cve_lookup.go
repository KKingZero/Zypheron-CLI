package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// CVEResult represents a CVE lookup result
type CVEResult struct {
	CVEID       string   `json:"cve_id"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`    // CRITICAL, HIGH, MEDIUM, LOW
	CVSSScore   float64  `json:"cvss_score"`  // 0.0 - 10.0
	Published   string   `json:"published"`   // Date published
	References  []string `json:"references"`  // URLs for more info
	Exploits    []string `json:"exploits"`    // Known exploit URLs
	Affected    []string `json:"affected"`    // Affected products/versions
	Source      string   `json:"source"`      // Where we found this info
}

// CVELookupResult represents the overall lookup result
type CVELookupResult struct {
	Query       string       `json:"query"`        // Original search query
	CVEs        []*CVEResult `json:"cves"`         // Found CVEs
	SearchedSources []string `json:"searched_sources"`
	MatchSource string       `json:"match_source"` // First source with results
	Error       string       `json:"error,omitempty"`
}

// CVESource represents a CVE data source
type CVESource struct {
	Name     string
	SearchFn func(ctx context.Context, query string) ([]*CVEResult, error)
}

// CVELookup provides CVE lookup functionality across multiple sources
type CVELookup struct {
	agent   *GeminiBrowserAgent
	sources []CVESource
	timeout time.Duration
}

// NewCVELookup creates a new CVE lookup instance
func NewCVELookup(agent *GeminiBrowserAgent) *CVELookup {
	lookup := &CVELookup{
		agent:   agent,
		timeout: 30 * time.Second,
	}

	// Define sources in order of preference
	lookup.sources = []CVESource{
		{Name: "NVD", SearchFn: lookup.searchNVD},
		{Name: "Exploit-DB", SearchFn: lookup.searchExploitDB},
		{Name: "CVEDetails", SearchFn: lookup.searchCVEDetails},
		{Name: "GitHub Security", SearchFn: lookup.searchGitHubSecurity},
	}

	return lookup
}

// LookupByProduct searches for CVEs affecting a product/version
// Example: "Apache 2.4.49", "OpenSSH 8.2", "nginx 1.18.0"
func (c *CVELookup) LookupByProduct(product string) (*CVELookupResult, error) {
	result := &CVELookupResult{
		Query:           product,
		CVEs:            []*CVEResult{},
		SearchedSources: []string{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	// Try each source until we find results
	for _, source := range c.sources {
		result.SearchedSources = append(result.SearchedSources, source.Name)

		cves, err := source.SearchFn(ctx, product)
		if err != nil {
			continue // Try next source
		}

		if len(cves) > 0 {
			result.CVEs = cves
			result.MatchSource = source.Name
			return result, nil
		}
	}

	return result, nil // No CVEs found but not an error
}

// LookupByCVEID looks up a specific CVE by ID
// Example: "CVE-2021-44228"
func (c *CVELookup) LookupByCVEID(cveID string) (*CVEResult, error) {
	// Normalize CVE ID format
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if !strings.HasPrefix(cveID, "CVE-") {
		cveID = "CVE-" + cveID
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	// Try NVD first for direct CVE lookup
	result, err := c.lookupCVEFromNVD(ctx, cveID)
	if err == nil && result != nil {
		return result, nil
	}

	// Fallback to search
	results, err := c.LookupByProduct(cveID)
	if err != nil {
		return nil, err
	}

	if len(results.CVEs) > 0 {
		return results.CVEs[0], nil
	}

	return nil, fmt.Errorf("CVE %s not found", cveID)
}

// searchNVD searches the National Vulnerability Database
func (c *CVELookup) searchNVD(ctx context.Context, query string) ([]*CVEResult, error) {
	// Use NVD's search API (public, no auth required for basic search)
	searchURL := fmt.Sprintf("https://nvd.nist.gov/vuln/search/results?query=%s&form_type=Basic&results_type=overview",
		url.QueryEscape(query))

	if c.agent == nil {
		return c.searchNVDAPI(ctx, query)
	}

	// Navigate and extract results
	if err := chromedp.Run(c.agent.ctx, chromedp.Navigate(searchURL)); err != nil {
		return nil, fmt.Errorf("failed to navigate to NVD: %w", err)
	}

	// Wait for results
	if err := chromedp.Run(c.agent.ctx, chromedp.Sleep(2*time.Second)); err != nil {
		return nil, err
	}

	// Get page content
	var htmlContent string
	if err := chromedp.Run(c.agent.ctx, chromedp.OuterHTML("html", &htmlContent)); err != nil {
		return nil, err
	}

	return parseNVDResults(htmlContent)
}

// searchNVDAPI uses NVD's REST API (preferred when no browser needed)
func (c *CVELookup) searchNVDAPI(ctx context.Context, query string) ([]*CVEResult, error) {
	// NVD 2.0 API
	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s",
		url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Zypheron-Security-Scanner/1.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	var nvdResp NVDAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, err
	}

	var results []*CVEResult
	for _, vuln := range nvdResp.Vulnerabilities {
		cve := vuln.CVE
		result := &CVEResult{
			CVEID:       cve.ID,
			Description: extractDescription(cve.Descriptions),
			Severity:    extractSeverity(cve.Metrics),
			CVSSScore:   extractCVSSScore(cve.Metrics),
			Published:   cve.Published,
			References:  extractReferences(cve.References),
			Source:      "NVD",
		}
		results = append(results, result)
	}

	return results, nil
}

// lookupCVEFromNVD looks up a specific CVE ID from NVD
func (c *CVELookup) lookupCVEFromNVD(ctx context.Context, cveID string) (*CVEResult, error) {
	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Zypheron-Security-Scanner/1.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	var nvdResp NVDAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, err
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, nil
	}

	cve := nvdResp.Vulnerabilities[0].CVE
	return &CVEResult{
		CVEID:       cve.ID,
		Description: extractDescription(cve.Descriptions),
		Severity:    extractSeverity(cve.Metrics),
		CVSSScore:   extractCVSSScore(cve.Metrics),
		Published:   cve.Published,
		References:  extractReferences(cve.References),
		Source:      "NVD",
	}, nil
}

// searchExploitDB searches Exploit-DB for exploits
func (c *CVELookup) searchExploitDB(ctx context.Context, query string) ([]*CVEResult, error) {
	searchURL := fmt.Sprintf("https://www.exploit-db.com/search?q=%s", url.QueryEscape(query))

	if c.agent == nil {
		return nil, fmt.Errorf("browser agent required for Exploit-DB")
	}

	if err := chromedp.Run(c.agent.ctx, chromedp.Navigate(searchURL)); err != nil {
		return nil, err
	}

	if err := chromedp.Run(c.agent.ctx, chromedp.Sleep(3*time.Second)); err != nil {
		return nil, err
	}

	var htmlContent string
	if err := chromedp.Run(c.agent.ctx, chromedp.OuterHTML("html", &htmlContent)); err != nil {
		return nil, err
	}

	return parseExploitDBResults(htmlContent)
}

// searchCVEDetails searches CVEDetails.com
func (c *CVELookup) searchCVEDetails(ctx context.Context, query string) ([]*CVEResult, error) {
	searchURL := fmt.Sprintf("https://www.cvedetails.com/google-search-results.php?q=%s", url.QueryEscape(query))

	if c.agent == nil {
		return nil, fmt.Errorf("browser agent required for CVEDetails")
	}

	if err := chromedp.Run(c.agent.ctx, chromedp.Navigate(searchURL)); err != nil {
		return nil, err
	}

	if err := chromedp.Run(c.agent.ctx, chromedp.Sleep(2*time.Second)); err != nil {
		return nil, err
	}

	var htmlContent string
	if err := chromedp.Run(c.agent.ctx, chromedp.OuterHTML("html", &htmlContent)); err != nil {
		return nil, err
	}

	return parseCVEDetailsResults(htmlContent)
}

// searchGitHubSecurity searches GitHub Security Advisories
func (c *CVELookup) searchGitHubSecurity(ctx context.Context, query string) ([]*CVEResult, error) {
	searchURL := fmt.Sprintf("https://github.com/advisories?query=%s", url.QueryEscape(query))

	if c.agent == nil {
		return nil, fmt.Errorf("browser agent required for GitHub Security")
	}

	if err := chromedp.Run(c.agent.ctx, chromedp.Navigate(searchURL)); err != nil {
		return nil, err
	}

	if err := chromedp.Run(c.agent.ctx, chromedp.Sleep(2*time.Second)); err != nil {
		return nil, err
	}

	var htmlContent string
	if err := chromedp.Run(c.agent.ctx, chromedp.OuterHTML("html", &htmlContent)); err != nil {
		return nil, err
	}

	return parseGitHubSecurityResults(htmlContent)
}

// NVD API Response structures
type NVDAPIResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE NVDCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type NVDCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CvssMetricV31 []struct {
			CvssData struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
		CvssMetricV2 []struct {
			CvssData struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"cvssData"`
			BaseSeverity string `json:"baseSeverity"`
		} `json:"cvssMetricV2"`
	} `json:"metrics"`
	References []struct {
		URL    string   `json:"url"`
		Source string   `json:"source"`
		Tags   []string `json:"tags"`
	} `json:"references"`
}

// Helper functions
func extractDescription(descriptions []struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}) string {
	for _, d := range descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(descriptions) > 0 {
		return descriptions[0].Value
	}
	return ""
}

func extractSeverity(metrics struct {
	CvssMetricV31 []struct {
		CvssData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV31"`
	CvssMetricV2 []struct {
		CvssData struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"cvssData"`
		BaseSeverity string `json:"baseSeverity"`
	} `json:"cvssMetricV2"`
}) string {
	if len(metrics.CvssMetricV31) > 0 {
		return metrics.CvssMetricV31[0].CvssData.BaseSeverity
	}
	if len(metrics.CvssMetricV2) > 0 {
		return metrics.CvssMetricV2[0].BaseSeverity
	}
	return "UNKNOWN"
}

func extractCVSSScore(metrics struct {
	CvssMetricV31 []struct {
		CvssData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV31"`
	CvssMetricV2 []struct {
		CvssData struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"cvssData"`
		BaseSeverity string `json:"baseSeverity"`
	} `json:"cvssMetricV2"`
}) float64 {
	if len(metrics.CvssMetricV31) > 0 {
		return metrics.CvssMetricV31[0].CvssData.BaseScore
	}
	if len(metrics.CvssMetricV2) > 0 {
		return metrics.CvssMetricV2[0].CvssData.BaseScore
	}
	return 0.0
}

func extractReferences(refs []struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}) []string {
	var urls []string
	for _, ref := range refs {
		urls = append(urls, ref.URL)
	}
	return urls
}

// parseNVDResults parses HTML results from NVD search page
func parseNVDResults(html string) ([]*CVEResult, error) {
	var results []*CVEResult

	// Find CVE IDs in the page
	cvePattern := regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	matches := cvePattern.FindAllString(html, -1)

	seen := make(map[string]bool)
	for _, cveID := range matches {
		if seen[cveID] {
			continue
		}
		seen[cveID] = true

		results = append(results, &CVEResult{
			CVEID:  cveID,
			Source: "NVD",
		})

		if len(results) >= 10 {
			break
		}
	}

	return results, nil
}

// parseExploitDBResults parses HTML results from Exploit-DB
func parseExploitDBResults(html string) ([]*CVEResult, error) {
	var results []*CVEResult

	// Find CVE IDs and exploit titles
	cvePattern := regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	exploitPattern := regexp.MustCompile(`/exploits/(\d+)`)

	cveMatches := cvePattern.FindAllString(html, -1)
	exploitMatches := exploitPattern.FindAllStringSubmatch(html, -1)

	seen := make(map[string]bool)
	for _, cveID := range cveMatches {
		if seen[cveID] {
			continue
		}
		seen[cveID] = true

		result := &CVEResult{
			CVEID:  cveID,
			Source: "Exploit-DB",
		}

		// Add exploit links if found
		for _, match := range exploitMatches {
			if len(match) >= 2 {
				result.Exploits = append(result.Exploits,
					fmt.Sprintf("https://www.exploit-db.com/exploits/%s", match[1]))
			}
		}

		results = append(results, result)

		if len(results) >= 10 {
			break
		}
	}

	return results, nil
}

// parseCVEDetailsResults parses HTML results from CVEDetails
func parseCVEDetailsResults(html string) ([]*CVEResult, error) {
	var results []*CVEResult

	cvePattern := regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	matches := cvePattern.FindAllString(html, -1)

	seen := make(map[string]bool)
	for _, cveID := range matches {
		if seen[cveID] {
			continue
		}
		seen[cveID] = true

		results = append(results, &CVEResult{
			CVEID:  cveID,
			Source: "CVEDetails",
		})

		if len(results) >= 10 {
			break
		}
	}

	return results, nil
}

// parseGitHubSecurityResults parses HTML results from GitHub Security Advisories
func parseGitHubSecurityResults(html string) ([]*CVEResult, error) {
	var results []*CVEResult

	// GitHub advisories have GHSA IDs and sometimes CVE IDs
	cvePattern := regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	ghsaPattern := regexp.MustCompile(`GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}`)

	cveMatches := cvePattern.FindAllString(html, -1)
	ghsaMatches := ghsaPattern.FindAllString(html, -1)

	seen := make(map[string]bool)

	// Add CVE results
	for _, cveID := range cveMatches {
		if seen[cveID] {
			continue
		}
		seen[cveID] = true

		results = append(results, &CVEResult{
			CVEID:  cveID,
			Source: "GitHub Security",
		})
	}

	// Add GHSA results (some may not have CVE IDs)
	for _, ghsaID := range ghsaMatches {
		if seen[ghsaID] {
			continue
		}
		seen[ghsaID] = true

		results = append(results, &CVEResult{
			CVEID:      ghsaID,
			Source:     "GitHub Security",
			References: []string{fmt.Sprintf("https://github.com/advisories/%s", ghsaID)},
		})
	}

	if len(results) > 10 {
		results = results[:10]
	}

	return results, nil
}

// ExtractServiceVersion extracts product/version from nmap service detection
// Example: "Apache httpd 2.4.49" -> "Apache 2.4.49"
func ExtractServiceVersion(serviceInfo string) string {
	// Common patterns for service versions
	patterns := []struct {
		regex   *regexp.Regexp
		format  func([]string) string
	}{
		// Apache httpd 2.4.49
		{regexp.MustCompile(`(?i)(apache)\s+(?:httpd\s+)?(\d+\.\d+\.?\d*)`), func(m []string) string { return m[1] + " " + m[2] }},
		// nginx/1.18.0
		{regexp.MustCompile(`(?i)(nginx)[/\s]+(\d+\.\d+\.?\d*)`), func(m []string) string { return m[1] + " " + m[2] }},
		// OpenSSH_8.2p1
		{regexp.MustCompile(`(?i)(openssh)[_\s]+(\d+\.\d+\.?\d*)`), func(m []string) string { return m[1] + " " + m[2] }},
		// MySQL 5.7.32
		{regexp.MustCompile(`(?i)(mysql)[/\s]+(\d+\.\d+\.?\d*)`), func(m []string) string { return m[1] + " " + m[2] }},
		// PostgreSQL 12.4
		{regexp.MustCompile(`(?i)(postgres(?:ql)?)[/\s]+(\d+\.?\d*\.?\d*)`), func(m []string) string { return "PostgreSQL " + m[2] }},
		// Microsoft IIS httpd 10.0
		{regexp.MustCompile(`(?i)microsoft\s+(iis)[/\s]+(?:httpd\s+)?(\d+\.?\d*)`), func(m []string) string { return "IIS " + m[2] }},
		// vsftpd 3.0.3
		{regexp.MustCompile(`(?i)(vsftpd)[/\s]+(\d+\.\d+\.?\d*)`), func(m []string) string { return m[1] + " " + m[2] }},
		// ProFTPD 1.3.5
		{regexp.MustCompile(`(?i)(proftpd)[/\s]+(\d+\.\d+\.?\d*)`), func(m []string) string { return m[1] + " " + m[2] }},
		// Generic: product version pattern
		{regexp.MustCompile(`([a-zA-Z][\w-]+)[/\s]+(\d+\.\d+\.?\d*)`), func(m []string) string { return m[1] + " " + m[2] }},
	}

	for _, p := range patterns {
		if matches := p.regex.FindStringSubmatch(serviceInfo); matches != nil {
			return p.format(matches)
		}
	}

	return serviceInfo
}
