package crawler

import (
	"context"
	"time"
)

// Crawler interface for web crawling
type Crawler interface {
	Name() string
	Crawl(ctx context.Context, opts CrawlOptions) (*CrawlResult, error)
}

// CrawlOptions configures crawling behavior
type CrawlOptions struct {
	Target      string        // Starting URL
	Depth       int           // Crawl depth (1-10)
	Concurrency int           // Concurrent workers
	Timeout     time.Duration // Per-URL timeout
	UserAgent   string        // Custom user agent
	Filters     CrawlFilters  // Include/exclude patterns
}

// CrawlResult contains all discovered information
type CrawlResult struct {
	URLs            []string    `json:"urls"`
	Forms           []Form      `json:"forms"`
	JavaScripts     []JS        `json:"javascripts"`
	Parameters      []Parameter `json:"parameters"`
	GraphQLEndpoint string      `json:"graphql_endpoint,omitempty"`
	Emails          []string    `json:"emails"`
	Comments        []string    `json:"comments"`
	Technologies    []string    `json:"technologies"`
	CreatedAt       time.Time   `json:"created_at"`
}

// Form represents an HTML form
type Form struct {
	URL    string      `json:"url"`
	Method string      `json:"method"`
	Action string      `json:"action"`
	Inputs []FormInput `json:"inputs"`
}

// FormInput represents a form input field
type FormInput struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

// JS represents a JavaScript file
type JS struct {
	URL    string `json:"url"`
	Source string `json:"source,omitempty"`
	Hash   string `json:"hash,omitempty"`
}

// Parameter represents a URL parameter
type Parameter struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	URL    string `json:"url"`
	Source string `json:"source"` // "query", "form", "js", etc.
}

// CrawlFilters control what gets crawled
type CrawlFilters struct {
	AllowPatterns []string // Regex patterns to include
	DenyPatterns  []string // Regex patterns to exclude
	InternalOnly  bool     // Only crawl same domain
	MaxURLs       int      // Maximum URLs to crawl
}

// Note: Crawler will be used by multiple future modules:
// - Phase 2.7: URL Discovery (Archive aggregation + crawler)
// - Phase 3: JavaScript Recon (JS extraction using crawler)
// - Phase 3.5: Parameter Discovery (Parameter extraction using crawler)
// - Phase 3.7: GraphQL Detection (GraphQL discovery using crawler)
