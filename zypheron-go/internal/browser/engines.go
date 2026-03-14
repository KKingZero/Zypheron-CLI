package browser

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"
)

// SearchEngine defines the interface for search engines
type SearchEngine interface {
	// Search performs a search query and returns results
	Search(query string, maxResults int) ([]SearchResult, error)
	// Name returns the engine name
	Name() string
	// RequiresAPIKey returns true if the engine requires an API key
	RequiresAPIKey() bool
	// IsAvailable checks if the engine is available (has API key if required)
	IsAvailable() bool
}

// EngineType represents the type of search engine
type EngineType string

const (
	EngineGoogle     EngineType = "google"
	EngineBing       EngineType = "bing"
	EngineDuckDuckGo EngineType = "duckduckgo"
	EngineShodan     EngineType = "shodan"
	EngineCensys     EngineType = "censys"
)

// GetEngine returns a search engine instance by type
func GetEngine(engineType EngineType) (SearchEngine, error) {
	switch engineType {
	case EngineShodan:
		return NewShodanEngine()
	case EngineCensys:
		return NewCensysEngine()
	default:
		return nil, fmt.Errorf("unsupported engine type: %s", engineType)
	}
}

// GetAvailableEngines returns all engines that are available (have API keys)
func GetAvailableEngines(requestedEngines []string) ([]SearchEngine, []string) {
	var available []SearchEngine
	var skipped []string

	for _, name := range requestedEngines {
		engineType := EngineType(strings.ToLower(name))

		switch engineType {
		case EngineGoogle, EngineBing, EngineDuckDuckGo:
			// Browser-based engines are always "available" - handled by existing BrowserAgent
			continue
		case EngineShodan, EngineCensys:
			engine, err := GetEngine(engineType)
			if err != nil {
				skipped = append(skipped, fmt.Sprintf("%s: %v", name, err))
				continue
			}
			if !engine.IsAvailable() {
				skipped = append(skipped, fmt.Sprintf("%s: API key not configured (use 'zypheron config set-key %s')", name, name))
				continue
			}
			available = append(available, engine)
		default:
			skipped = append(skipped, fmt.Sprintf("%s: unknown engine", name))
		}
	}

	return available, skipped
}

// =============================================================================
// Shodan Engine
// =============================================================================

const (
	shodanAPIBase = "https://api.shodan.io"
)

// ShodanEngine implements SearchEngine for Shodan
type ShodanEngine struct {
	apiKey     string
	httpClient *http.Client
}

// NewShodanEngine creates a new Shodan search engine
func NewShodanEngine() (*ShodanEngine, error) {
	apiKey, err := config.GetAPIKey(config.ProviderShodan)
	if err != nil {
		return &ShodanEngine{}, nil // Return empty engine, IsAvailable will return false
	}

	return &ShodanEngine{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

func (e *ShodanEngine) Name() string {
	return "shodan"
}

func (e *ShodanEngine) RequiresAPIKey() bool {
	return true
}

func (e *ShodanEngine) IsAvailable() bool {
	return e.apiKey != ""
}

// ShodanSearchResult represents a Shodan search result
type ShodanSearchResult struct {
	Matches []struct {
		IP        string   `json:"ip_str"`
		Port      int      `json:"port"`
		Hostnames []string `json:"hostnames"`
		Product   string   `json:"product"`
		Version   string   `json:"version"`
		OS        string   `json:"os"`
		Data      string   `json:"data"`
		Org       string   `json:"org"`
		ISP       string   `json:"isp"`
		Location  struct {
			City        string  `json:"city"`
			Country     string  `json:"country_name"`
			CountryCode string  `json:"country_code"`
			Latitude    float64 `json:"latitude"`
			Longitude   float64 `json:"longitude"`
		} `json:"location"`
		Vulns []string `json:"vulns"`
	} `json:"matches"`
	Total int `json:"total"`
}

func (e *ShodanEngine) Search(query string, maxResults int) ([]SearchResult, error) {
	if !e.IsAvailable() {
		return nil, fmt.Errorf("Shodan API key not configured")
	}

	// Build URL
	endpoint := fmt.Sprintf("%s/shodan/host/search", shodanAPIBase)
	params := url.Values{}
	params.Set("key", e.apiKey)
	params.Set("query", query)
	if maxResults > 0 && maxResults < 100 {
		params.Set("page", "1")
	}

	fullURL := endpoint + "?" + params.Encode()

	// Make request
	resp, err := e.httpClient.Get(fullURL)
	if err != nil {
		return nil, fmt.Errorf("shodan request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("shodan: invalid API key")
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("shodan: %s - %s", resp.Status, string(body))
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read shodan response: %w", err)
	}

	var shodanResult ShodanSearchResult
	if err := json.Unmarshal(body, &shodanResult); err != nil {
		return nil, fmt.Errorf("failed to parse shodan response: %w", err)
	}

	// Convert to SearchResult
	var results []SearchResult
	for i, match := range shodanResult.Matches {
		if maxResults > 0 && i >= maxResults {
			break
		}

		title := fmt.Sprintf("%s:%d", match.IP, match.Port)
		if match.Product != "" {
			title = fmt.Sprintf("%s - %s", title, match.Product)
			if match.Version != "" {
				title = fmt.Sprintf("%s %s", title, match.Version)
			}
		}

		hostname := match.IP
		if len(match.Hostnames) > 0 {
			hostname = match.Hostnames[0]
		}

		description := fmt.Sprintf("Org: %s | ISP: %s", match.Org, match.ISP)
		if match.Location.Country != "" {
			description += fmt.Sprintf(" | Location: %s, %s", match.Location.City, match.Location.Country)
		}
		if match.OS != "" {
			description += fmt.Sprintf(" | OS: %s", match.OS)
		}
		if len(match.Vulns) > 0 {
			description += fmt.Sprintf(" | Vulns: %s", strings.Join(match.Vulns[:min(3, len(match.Vulns))], ", "))
		}

		results = append(results, SearchResult{
			Title:       title,
			URL:         fmt.Sprintf("https://www.shodan.io/host/%s", match.IP),
			Description: description,
			Source:      "shodan",
			Metadata: map[string]string{
				"ip":       match.IP,
				"port":     fmt.Sprintf("%d", match.Port),
				"hostname": hostname,
				"org":      match.Org,
			},
		})
	}

	return results, nil
}

// =============================================================================
// Censys Engine
// =============================================================================

const (
	censysAPIBase = "https://search.censys.io/api/v2"
)

// CensysEngine implements SearchEngine for Censys
type CensysEngine struct {
	apiID      string
	apiSecret  string
	httpClient *http.Client
}

// NewCensysEngine creates a new Censys search engine
func NewCensysEngine() (*CensysEngine, error) {
	apiID, err := config.GetAPIKey(config.ProviderCensys)
	if err != nil {
		return &CensysEngine{}, nil
	}

	apiSecret, err := config.GetAPIKey(config.ProviderCensysSecret)
	if err != nil {
		return &CensysEngine{}, nil
	}

	return &CensysEngine{
		apiID:     apiID,
		apiSecret: apiSecret,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

func (e *CensysEngine) Name() string {
	return "censys"
}

func (e *CensysEngine) RequiresAPIKey() bool {
	return true
}

func (e *CensysEngine) IsAvailable() bool {
	return e.apiID != "" && e.apiSecret != ""
}

// CensysSearchRequest represents the Censys search API request
type CensysSearchRequest struct {
	Query   string `json:"q"`
	PerPage int    `json:"per_page"`
}

// CensysSearchResult represents the Censys search API response
type CensysSearchResult struct {
	Result struct {
		Hits []struct {
			IP             string   `json:"ip"`
			Services       []CensysService `json:"services"`
			AutonomousSystem struct {
				ASN         int    `json:"asn"`
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"autonomous_system"`
			Location struct {
				Country   string `json:"country"`
				City      string `json:"city"`
				Continent string `json:"continent"`
			} `json:"location"`
			OperatingSystem struct {
				Product string `json:"product"`
				Version string `json:"version"`
			} `json:"operating_system"`
			DNS struct {
				Names []string `json:"names"`
			} `json:"dns"`
		} `json:"hits"`
		Total int `json:"total"`
	} `json:"result"`
	Status string `json:"status"`
}

// CensysService represents a service in Censys results
type CensysService struct {
	Port        int    `json:"port"`
	ServiceName string `json:"service_name"`
	Transport   string `json:"transport_protocol"`
}

func (e *CensysEngine) Search(query string, maxResults int) ([]SearchResult, error) {
	if !e.IsAvailable() {
		return nil, fmt.Errorf("Censys API credentials not configured")
	}

	// Build request
	endpoint := fmt.Sprintf("%s/hosts/search", censysAPIBase)

	perPage := 25
	if maxResults > 0 && maxResults < 100 {
		perPage = maxResults
	}

	reqBody := CensysSearchRequest{
		Query:   query,
		PerPage: perPage,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create censys request: %w", err)
	}

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to create censys request: %w", err)
	}

	req.SetBasicAuth(e.apiID, e.apiSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Make request
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("censys request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("censys: invalid API credentials")
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("censys: %s - %s", resp.Status, string(body))
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read censys response: %w", err)
	}

	var censysResult CensysSearchResult
	if err := json.Unmarshal(body, &censysResult); err != nil {
		return nil, fmt.Errorf("failed to parse censys response: %w", err)
	}

	// Convert to SearchResult
	var results []SearchResult
	for i, hit := range censysResult.Result.Hits {
		if maxResults > 0 && i >= maxResults {
			break
		}

		// Build title from services
		var ports []string
		var services []string
		for _, svc := range hit.Services {
			ports = append(ports, fmt.Sprintf("%d", svc.Port))
			if svc.ServiceName != "" {
				services = append(services, svc.ServiceName)
			}
		}

		title := hit.IP
		if len(services) > 0 {
			title = fmt.Sprintf("%s - %s", hit.IP, strings.Join(services[:min(3, len(services))], ", "))
		}

		hostname := hit.IP
		if len(hit.DNS.Names) > 0 {
			hostname = hit.DNS.Names[0]
		}

		description := fmt.Sprintf("Ports: %s", strings.Join(ports, ", "))
		if hit.AutonomousSystem.Name != "" {
			description += fmt.Sprintf(" | AS%d %s", hit.AutonomousSystem.ASN, hit.AutonomousSystem.Name)
		}
		if hit.Location.Country != "" {
			loc := hit.Location.Country
			if hit.Location.City != "" {
				loc = hit.Location.City + ", " + hit.Location.Country
			}
			description += fmt.Sprintf(" | Location: %s", loc)
		}
		if hit.OperatingSystem.Product != "" {
			description += fmt.Sprintf(" | OS: %s", hit.OperatingSystem.Product)
		}

		results = append(results, SearchResult{
			Title:       title,
			URL:         fmt.Sprintf("https://search.censys.io/hosts/%s", hit.IP),
			Description: description,
			Source:      "censys",
			Metadata: map[string]string{
				"ip":       hit.IP,
				"hostname": hostname,
				"ports":    strings.Join(ports, ","),
				"asn":      fmt.Sprintf("%d", hit.AutonomousSystem.ASN),
			},
		})
	}

	return results, nil
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
