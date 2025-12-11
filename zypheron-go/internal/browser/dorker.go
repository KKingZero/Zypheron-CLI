package browser

import (
	"fmt"
	"strings"
)

// DorkQuery represents a dorking query
type DorkQuery struct {
	Query      string
	Engine     string
	MaxResults int
}

// Dorker performs Google/Bing dorking
type Dorker struct {
	agent BrowserAgent
}

// NewDorker creates a new dorker
func NewDorker(agent BrowserAgent) *Dorker {
	return &Dorker{
		agent: agent,
	}
}

// ExecuteDork executes a dork query
func (d *Dorker) ExecuteDork(query DorkQuery) ([]SearchResult, error) {
	// Build search query
	searchQuery := query.Query
	
	// Add common dorking operators if not present
	if !strings.Contains(searchQuery, "site:") && !strings.Contains(searchQuery, "inurl:") {
		// Could add AI-powered query enhancement here
	}
	
	// Perform search
	results, err := d.agent.Search(searchQuery, query.Engine)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}
	
	// Limit results
	if query.MaxResults > 0 && len(results) > query.MaxResults {
		results = results[:query.MaxResults]
	}
	
	return results, nil
}

// GenerateDorkQueries generates dork queries based on keywords
func GenerateDorkQueries(keywords []string, baseQueries []string) []string {
	var queries []string
	
	for _, keyword := range keywords {
		for _, baseQuery := range baseQueries {
			query := strings.Replace(baseQuery, "{keyword}", keyword, -1)
			queries = append(queries, query)
		}
	}
	
	return queries
}

// CommonDorkPatterns contains common Google dorking patterns
var CommonDorkPatterns = []string{
	"site:{keyword}",
	"inurl:{keyword}",
	"intitle:{keyword}",
	"filetype:pdf {keyword}",
	"intext:{keyword}",
}

