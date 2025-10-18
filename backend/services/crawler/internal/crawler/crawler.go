package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	pb "github.com/cobra-ai/crawler/proto"
)

type WebCrawler struct {
	logger *zap.Logger
	client *http.Client
}

type CrawlOptions struct {
	MaxDepth            int
	MaxPages            int
	FollowExternalLinks bool
	RespectRobotsTxt    bool
	AllowedDomains      []string
	ExcludedPaths       []string
	ConcurrentRequests  int
	DelayMs             int
	UserAgent           string
	JavascriptRendering bool
	CustomHeaders       map[string]string
}

type Selector struct {
	Name        string
	CSSSelector string
	XPath       string
	Attribute   string
	Multiple    bool
}

type ScreenshotOptions struct {
	Width           int
	Height          int
	FullPage        bool
	Quality         int
	Format          string
	WaitMs          int
	WaitForSelector string
}

type SubdomainInfo struct {
	Subdomain   string
	IPAddresses []string
	Source      string
	Active      bool
}

type RobotsInfo struct {
	Exists          bool
	Content         string
	DisallowedPaths []string
	AllowedPaths    []string
	Sitemaps        []string
	CrawlDelay      int
}

func New(logger *zap.Logger) *WebCrawler {
	return &WebCrawler{
		logger: logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (w *WebCrawler) Crawl(startURL string, opts CrawlOptions, resultChan chan<- *pb.CrawlResult) error {
	visited := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Parse start URL
	parsedURL, err := url.Parse(startURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	// Create a semaphore for concurrent requests
	sem := make(chan struct{}, opts.ConcurrentRequests)

	// Start crawling
	wg.Add(1)
	go w.crawlPage(parsedURL.String(), 0, opts, visited, &mu, &wg, sem, resultChan)

	wg.Wait()
	return nil
}

func (w *WebCrawler) crawlPage(pageURL string, depth int, opts CrawlOptions, visited map[string]bool, mu *sync.Mutex, wg *sync.WaitGroup, sem chan struct{}, resultChan chan<- *pb.CrawlResult) {
	defer wg.Done()

	// Check if we've reached max depth or max pages
	mu.Lock()
	if depth > opts.MaxDepth || len(visited) >= opts.MaxPages {
		mu.Unlock()
		return
	}
	
	// Check if already visited
	if visited[pageURL] {
		mu.Unlock()
		return
	}
	visited[pageURL] = true
	mu.Unlock()

	// Rate limiting
	if opts.DelayMs > 0 {
		time.Sleep(time.Duration(opts.DelayMs) * time.Millisecond)
	}

	// Acquire semaphore
	sem <- struct{}{}
	defer func() { <-sem }()

	// Make request
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		w.logger.Error("Failed to create request", zap.String("url", pageURL), zap.Error(err))
		return
	}

	// Set headers
	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	}
	for k, v := range opts.CustomHeaders {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		w.logger.Error("Failed to fetch page", zap.String("url", pageURL), zap.Error(err))
		return
	}
	defer resp.Body.Close()

	// Create result
	result := &pb.CrawlResult{
		Url:        pageURL,
		StatusCode: int32(resp.StatusCode),
		Headers:    make(map[string]string),
		Depth:      int32(depth),
		Timestamp: &pb.Timestamp{
			Seconds: time.Now().Unix(),
			Nanos:   0,
		},
	}

	// Copy headers
	for k, v := range resp.Header {
		if len(v) > 0 {
			result.Headers[k] = v[0]
		}
	}

	// Send result
	select {
	case resultChan <- result:
	default:
		// Channel might be closed
		return
	}

	// Extract links and continue crawling
	if resp.StatusCode == 200 && depth < opts.MaxDepth {
		// In a real implementation, would parse HTML and extract links
		// For now, simulate finding a few links
		links := []string{
			pageURL + "/about",
			pageURL + "/contact",
			pageURL + "/products",
		}

		for _, link := range links {
			wg.Add(1)
			go w.crawlPage(link, depth+1, opts, visited, mu, wg, sem, resultChan)
		}
	}
}

func (w *WebCrawler) ExtractData(pageURL string, selectors []Selector, javascriptRendering bool) (map[string][]string, error) {
	// Simplified implementation
	// In production, would use a real HTML parser and possibly a headless browser
	
	resp, err := w.client.Get(pageURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Simulate data extraction
	data := make(map[string][]string)
	for _, sel := range selectors {
		if sel.Multiple {
			data[sel.Name] = []string{"value1", "value2", "value3"}
		} else {
			data[sel.Name] = []string{"single value"}
		}
	}

	return data, nil
}

func (w *WebCrawler) TakeScreenshot(pageURL string, opts ScreenshotOptions) ([]byte, int, int, error) {
	// Simplified implementation
	// In production, would use a headless browser like Chromium
	
	// Simulate screenshot data
	mockData := []byte("PNG_IMAGE_DATA_HERE")
	width := opts.Width
	height := opts.Height
	
	if width == 0 {
		width = 1920
	}
	if height == 0 {
		height = 1080
	}

	return mockData, width, height, nil
}

func (w *WebCrawler) FindSubdomains(domain string, sources []string) ([]SubdomainInfo, error) {
	// Simplified implementation
	// In production, would query various sources like crt.sh, DNSDumpster, etc.
	
	subdomains := []SubdomainInfo{
		{
			Subdomain:   "www." + domain,
			IPAddresses: []string{"192.168.1.1"},
			Source:      "crt.sh",
			Active:      true,
		},
		{
			Subdomain:   "api." + domain,
			IPAddresses: []string{"192.168.1.2"},
			Source:      "DNSDumpster",
			Active:      true,
		},
		{
			Subdomain:   "mail." + domain,
			IPAddresses: []string{"192.168.1.3"},
			Source:      "crt.sh",
			Active:      true,
		},
	}

	return subdomains, nil
}

func (w *WebCrawler) CheckRobotsTxt(pageURL string, userAgent string) (RobotsInfo, error) {
	// Parse URL to get base
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return RobotsInfo{}, err
	}

	robotsURL := fmt.Sprintf("%s://%s/robots.txt", parsedURL.Scheme, parsedURL.Host)
	
	resp, err := w.client.Get(robotsURL)
	if err != nil {
		return RobotsInfo{Exists: false}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return RobotsInfo{Exists: false}, nil
	}

	// Simulate robots.txt parsing
	info := RobotsInfo{
		Exists:          true,
		Content:         "User-agent: *\nDisallow: /admin/\nDisallow: /private/\nSitemap: /sitemap.xml",
		DisallowedPaths: []string{"/admin/", "/private/"},
		AllowedPaths:    []string{"/"},
		Sitemaps:        []string{"/sitemap.xml"},
		CrawlDelay:      1,
	}

	return info, nil
} 