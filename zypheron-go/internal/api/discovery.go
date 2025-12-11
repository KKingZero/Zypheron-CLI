package api

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// APIEndpoint represents a discovered API endpoint
type APIEndpoint struct {
	URL         string
	Method      string
	StatusCode  int
	ContentType string
	IsSPA       bool
	IsBackend   bool
}

// DiscoverEndpoints discovers API endpoints from a base URL
func DiscoverEndpoints(baseURL string, timeout time.Duration) ([]APIEndpoint, error) {
	var endpoints []APIEndpoint

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Common API endpoint patterns
	patterns := []string{
		"/api/v1",
		"/api/v2",
		"/api",
		"/rest",
		"/graphql",
		"/v1",
		"/v2",
		"/swagger",
		"/openapi",
	}

	client := &http.Client{
		Timeout: timeout,
	}

	for _, pattern := range patterns {
		testURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, pattern)
		
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "Zypheron-API-Scanner/1.0")
		req.Header.Set("Accept", "application/json, application/graphql, */*")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		contentType := resp.Header.Get("Content-Type")
		isBackend := strings.Contains(contentType, "application/json") ||
			strings.Contains(contentType, "application/graphql") ||
			resp.StatusCode == 401 ||
			resp.StatusCode == 403 ||
			resp.StatusCode == 405

		endpoint := APIEndpoint{
			URL:         testURL,
			Method:      "GET",
			StatusCode:  resp.StatusCode,
			ContentType: contentType,
			IsBackend:   isBackend,
		}

		endpoints = append(endpoints, endpoint)
	}

	return endpoints, nil
}

// ExtractEndpointsFromHTML extracts potential API endpoints from HTML content
func ExtractEndpointsFromHTML(html, baseURL string) []string {
	var endpoints []string

	// Look for fetch/axios calls
	fetchPattern := regexp.MustCompile(`fetch\(['"]([^'"]+)['"]`)
	axiosPattern := regexp.MustCompile(`axios\.(?:get|post|put|delete)\(['"]([^'"]+)['"]`)

	matches := fetchPattern.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			endpoints = append(endpoints, match[1])
		}
	}

	matches = axiosPattern.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			endpoints = append(endpoints, match[1])
		}
	}

	// Look for absolute URLs
	urlPattern := regexp.MustCompile(`https?://[^\s"']+`)
	matches = urlPattern.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 0 && strings.Contains(match[0], "api") {
			endpoints = append(endpoints, match[0])
		}
	}

	return endpoints
}

// FetchText fetches text content from a URL
func FetchText(url string, timeout time.Duration) (string, error) {
	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Zypheron-API-Scanner/1.0")
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

