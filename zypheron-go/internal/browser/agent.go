package browser

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// BrowserAgent represents a browser automation agent
type BrowserAgent interface {
	Navigate(url string) error
	Search(query string, engine string) ([]SearchResult, error)
	ExtractResults() ([]SearchResult, error)
	Close() error
}

// SearchResult represents a search engine result
type SearchResult struct {
	Title       string
	URL         string
	Description string
	Rank        int
}

// GeminiBrowserAgent implements browser automation using chromedp
type GeminiBrowserAgent struct {
	ctx     context.Context
	cancel  context.CancelFunc
	results []SearchResult
}

// NewGeminiBrowserAgent creates a new browser agent with chromedp
func NewGeminiBrowserAgent() (*GeminiBrowserAgent, error) {
	// Check if Chromium is installed before attempting to use chromedp
	installed, _, instructions := CheckChromiumInstalled()
	if !installed {
		return nil, fmt.Errorf("chromium not found: %s", strings.Join(instructions, "; "))
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
	)

	// SECURITY: Only disable sandbox in Docker/CI environments or if explicitly requested
	// Disabling sandbox is a security risk and should only be done in controlled environments
	if os.Getenv("ZYPHERON_UNSAFE_BROWSER") == "true" || os.Getenv("CI") != "" || isRunningInDocker() {
		opts = append(opts, chromedp.Flag("no-sandbox", true))
		fmt.Println("⚠️  WARNING: Browser sandbox is DISABLED. This is a security risk!")
		fmt.Println("   Only use this in trusted/isolated environments (Docker, CI, etc.)")
	}

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel2 := chromedp.NewContext(allocCtx, chromedp.WithLogf(func(format string, v ...interface{}) {
		// Suppress chromedp logs
	}))

	// Set timeout
	ctx, cancel3 := context.WithTimeout(ctx, 30*time.Second)

	// Combine cancels
	cancelFunc := func() {
		cancel3()
		cancel2()
		cancel()
	}

	return &GeminiBrowserAgent{
		ctx:     ctx,
		cancel:  cancelFunc,
		results: []SearchResult{},
	}, nil
}

// Navigate navigates to a URL
func (a *GeminiBrowserAgent) Navigate(targetURL string) error {
	return chromedp.Run(a.ctx, chromedp.Navigate(targetURL))
}

// Search performs a search query on Google or Bing
func (a *GeminiBrowserAgent) Search(query string, engine string) ([]SearchResult, error) {
	var searchURL string

	// Build search URL based on engine
	if engine == "bing" {
		searchURL = fmt.Sprintf("https://www.bing.com/search?q=%s", url.QueryEscape(query))
	} else {
		// Default to Google
		searchURL = fmt.Sprintf("https://www.google.com/search?q=%s", url.QueryEscape(query))
	}

	// Navigate to search page
	if err := chromedp.Run(a.ctx, chromedp.Navigate(searchURL)); err != nil {
		return nil, fmt.Errorf("failed to navigate to search page: %w", err)
	}

	// Wait for results to load
	if err := chromedp.Run(a.ctx, chromedp.Sleep(2*time.Second)); err != nil {
		return nil, fmt.Errorf("failed to wait for page load: %w", err)
	}

	// Extract search results
	results, err := a.extractSearchResults(engine)
	if err != nil {
		return nil, fmt.Errorf("failed to extract results: %w", err)
	}

	a.results = results
	return results, nil
}

// extractSearchResults extracts search results from the current page
func (a *GeminiBrowserAgent) extractSearchResults(engine string) ([]SearchResult, error) {
	// Get page HTML
	var htmlContent string
	if err := chromedp.Run(a.ctx, chromedp.OuterHTML("html", &htmlContent)); err != nil {
		return nil, fmt.Errorf("failed to get page HTML: %w", err)
	}

	// Parse results based on engine
	if engine == "bing" {
		return parseBingResults(htmlContent)
	}
	return parseGoogleResults(htmlContent)
}

// ExtractResults extracts results from current page
func (a *GeminiBrowserAgent) ExtractResults() ([]SearchResult, error) {
	return a.results, nil
}

// Close closes the browser agent
func (a *GeminiBrowserAgent) Close() error {
	if a.cancel != nil {
		a.cancel()
	}
	return nil
}

// isRunningInDocker checks if the process is running inside a Docker container
func isRunningInDocker() bool {
	// Check for .dockerenv file
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Check /proc/1/cgroup for docker or containerd
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") || strings.Contains(content, "containerd") {
			return true
		}
	}

	return false
}
