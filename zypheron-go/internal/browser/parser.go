package browser

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// parseGoogleResults parses Google search results from HTML
func parseGoogleResults(htmlContent string) ([]SearchResult, error) {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	var results []SearchResult
	rank := 1

	// Google search results are typically in divs with class "g"
	// We'll use a more flexible approach to find result containers
	var findResults func(*html.Node)
	findResults = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Look for div elements that might contain results
			if n.Data == "div" {
				// Check if this div contains a link and text that looks like a result
				var hasLink bool
				var linkURL, title, description string

				var extractContent func(*html.Node)
				extractContent = func(node *html.Node) {
					if node.Type == html.ElementNode && node.Data == "a" {
						for _, attr := range node.Attr {
							if attr.Key == "href" && strings.HasPrefix(attr.Val, "http") {
								hasLink = true
								linkURL = attr.Val
								// Extract title from link text
								if node.FirstChild != nil && node.FirstChild.Type == html.TextNode {
									title = strings.TrimSpace(node.FirstChild.Data)
								}
								// Also check for h3 inside the link
								for c := node.FirstChild; c != nil; c = c.NextSibling {
									if c.Type == html.ElementNode && c.Data == "h3" {
										if c.FirstChild != nil {
											title = strings.TrimSpace(c.FirstChild.Data)
										}
									}
								}
							}
						}
					}
					if node.Type == html.TextNode && title == "" {
						text := strings.TrimSpace(node.Data)
						if len(text) > 10 && len(text) < 200 {
							title = text
						}
					}
					for c := node.FirstChild; c != nil; c = c.NextSibling {
						extractContent(c)
					}
				}

				extractContent(n)

				if hasLink && title != "" {
					// Extract description from sibling text nodes
					var extractDesc func(*html.Node)
					extractDesc = func(node *html.Node) {
						if node.Type == html.TextNode {
							text := strings.TrimSpace(node.Data)
							if len(text) > 20 && len(text) < 300 {
								description = text
							}
						}
						for c := node.FirstChild; c != nil; c = c.NextSibling {
							extractDesc(c)
						}
					}
					extractDesc(n)

					if description == "" {
						description = "No description available"
					}

					// Clean URL (remove Google redirect)
					if strings.Contains(linkURL, "/url?q=") {
						if parsed, err := url.Parse(linkURL); err == nil {
							if q := parsed.Query().Get("q"); q != "" {
								linkURL = q
							}
						}
					}

					results = append(results, SearchResult{
						Title:       title,
						URL:         linkURL,
						Description: description,
						Rank:        rank,
					})
					rank++
					if rank > 10 { // Limit to top 10 results
						return
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			findResults(c)
		}
	}

	findResults(doc)

	// Fallback: Use regex if DOM parsing didn't work well
	if len(results) == 0 {
		return parseGoogleResultsRegex(htmlContent)
	}

	return results, nil
}

// parseGoogleResultsRegex uses regex as fallback for Google results
func parseGoogleResultsRegex(htmlContent string) ([]SearchResult, error) {
	var results []SearchResult

	// Pattern for Google search results
	// This is a simplified regex - real parsing would be more complex
	linkPattern := regexp.MustCompile(`<a[^>]+href="([^"]+)"[^>]*>([^<]+)</a>`)
	matches := linkPattern.FindAllStringSubmatch(htmlContent, -1)

	rank := 1
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) >= 3 {
			linkURL := match[1]
			title := strings.TrimSpace(match[2])

			// Filter out Google's own links
			if strings.Contains(linkURL, "google.com") || strings.Contains(linkURL, "javascript:") {
				continue
			}

			// Clean URL
			if strings.HasPrefix(linkURL, "/url?q=") {
				if parsed, err := url.Parse("https://google.com" + linkURL); err == nil {
					if q := parsed.Query().Get("q"); q != "" {
						linkURL = q
					}
				}
			}

			if strings.HasPrefix(linkURL, "http") && !seen[linkURL] && len(title) > 5 {
				seen[linkURL] = true
				results = append(results, SearchResult{
					Title:       title,
					URL:         linkURL,
					Description: "Description not available",
					Rank:        rank,
				})
				rank++
				if rank > 10 {
					break
				}
			}
		}
	}

	return results, nil
}

// parseBingResults parses Bing search results from HTML
func parseBingResults(htmlContent string) ([]SearchResult, error) {
	var results []SearchResult

	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	rank := 1

	// Bing results are typically in li elements with class "b_algo"
	var findResults func(*html.Node)
	findResults = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "li" {
			var linkURL, title, description string

			var extractContent func(*html.Node)
			extractContent = func(node *html.Node) {
				if node.Type == html.ElementNode && node.Data == "a" {
					for _, attr := range node.Attr {
						if attr.Key == "href" && strings.HasPrefix(attr.Val, "http") {
							linkURL = attr.Val
							// Get title from h2 or link text
							for c := node.FirstChild; c != nil; c = c.NextSibling {
								if c.Type == html.ElementNode && c.Data == "h2" {
									if c.FirstChild != nil {
										title = strings.TrimSpace(c.FirstChild.Data)
									}
								} else if c.Type == html.TextNode {
									text := strings.TrimSpace(c.Data)
									if len(text) > 5 {
										title = text
									}
								}
							}
						}
					}
				}
				if node.Type == html.ElementNode && node.Data == "p" {
					if node.FirstChild != nil && node.FirstChild.Type == html.TextNode {
						description = strings.TrimSpace(node.FirstChild.Data)
					}
				}
				for c := node.FirstChild; c != nil; c = c.NextSibling {
					extractContent(c)
				}
			}

			extractContent(n)

			if linkURL != "" && title != "" {
				if description == "" {
					description = "No description available"
				}

				results = append(results, SearchResult{
					Title:       title,
					URL:         linkURL,
					Description: description,
					Rank:        rank,
				})
				rank++
				if rank > 10 {
					return
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			findResults(c)
		}
	}

	findResults(doc)

	// Fallback to regex if DOM parsing didn't work
	if len(results) == 0 {
		return parseBingResultsRegex(htmlContent)
	}

	return results, nil
}

// parseBingResultsRegex uses regex as fallback for Bing results
func parseBingResultsRegex(htmlContent string) ([]SearchResult, error) {
	var results []SearchResult

	// Pattern for Bing search results
	linkPattern := regexp.MustCompile(`<a[^>]+href="([^"]+)"[^>]*>([^<]+)</a>`)
	matches := linkPattern.FindAllStringSubmatch(htmlContent, -1)

	rank := 1
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) >= 3 {
			linkURL := match[1]
			title := strings.TrimSpace(match[2])

			// Filter out Bing's own links
			if strings.Contains(linkURL, "bing.com") && !strings.Contains(linkURL, "www.bing.com/search") {
				continue
			}
			if strings.Contains(linkURL, "javascript:") {
				continue
			}

			if strings.HasPrefix(linkURL, "http") && !seen[linkURL] && len(title) > 5 {
				seen[linkURL] = true
				results = append(results, SearchResult{
					Title:       title,
					URL:         linkURL,
					Description: "Description not available",
					Rank:        rank,
				})
				rank++
				if rank > 10 {
					break
				}
			}
		}
	}

	return results, nil
}

