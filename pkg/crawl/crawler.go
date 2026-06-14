package crawl

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// CrawlResult holds all discoveries from a crawl session.
type CrawlResult struct {
	URLs    []string   `json:"urls"`
	Params  []string   `json:"parameters"`
	APIs    []string   `json:"apis"`
	JSFiles []string   `json:"js_files"`
	Stats   CrawlStats `json:"stats"`
}

// CrawlStats contains counts and metadata.
type CrawlStats struct {
	TotalURLs    int `json:"total_urls"`
	TotalParams  int `json:"total_parameters"`
	TotalAPIs    int `json:"total_apis"`
	TotalJSFiles int `json:"total_js_files"`
	PagesCrawled int `json:"pages_crawled"`
	Errors       int `json:"errors"`
}

// pageTask represents a single URL to crawl.
type pageTask struct {
	url   string
	depth int
}

// pendingCounter tracks the number of outstanding crawl tasks.
type pendingCounter struct {
	mu    sync.Mutex
	count int
}

// Crawler performs concurrent web crawling.
type Crawler struct {
	client   *http.Client
	baseURL  *url.URL
	baseHost string
	maxDepth int
	retries  int

	// shared state
	mu           sync.Mutex
	visited      map[string]int // url -> depth visited
	params       map[string]bool
	apis         map[string]bool
	jsFiles      map[string]bool
	urls         []string
	pagesCrawled int
	crawlErrors  int
}

// NewCrawler creates a new crawler instance.
func NewCrawler(client *http.Client, targetURL string, maxDepth, retries int) (*Crawler, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Host == "" {
		return nil, fmt.Errorf("target URL must include a host")
	}

	return &Crawler{
		client:   client,
		baseURL:  u,
		baseHost: u.Host,
		maxDepth: maxDepth,
		retries:  retries,
		visited:  make(map[string]int),
		params:   make(map[string]bool),
		apis:     make(map[string]bool),
		jsFiles:  make(map[string]bool),
	}, nil
}

// Crawl starts crawling from the target URL using a worker pool.
func (c *Crawler) Crawl(ctx context.Context, concurrency int) (*CrawlResult, error) {
	startURL := c.baseURL.String()

	// Worker pool
	taskCh := make(chan pageTask, concurrency*2)
	doneCh := make(chan struct{})
	var wg sync.WaitGroup

	pending := &pendingCounter{}

	// Launch workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskCh {
				c.processPage(ctx, task, taskCh, pending)
			}
		}()
	}

	// Seed first task
	pending.mu.Lock()
	pending.count = 1
	pending.mu.Unlock()
	taskCh <- pageTask{url: startURL, depth: 0}

	// Monitor completion in background
	go func() {
		for {
			pending.mu.Lock()
			count := pending.count
			pending.mu.Unlock()

			if count == 0 {
				close(doneCh)
				return
			}

			select {
			case <-ctx.Done():
				close(doneCh)
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()

	// Wait for done or context cancellation
	select {
	case <-doneCh:
		close(taskCh)
	case <-ctx.Done():
		close(taskCh)
	}

	wg.Wait()
	return c.result(), nil
}

// processPage crawls a single page and enqueues new links.
func (c *Crawler) processPage(ctx context.Context, task pageTask, taskCh chan<- pageTask, pending *pendingCounter) {
	// Check depth
	if task.depth > c.maxDepth {
		return
	}

	// Check if already visited at same or lesser depth
	c.mu.Lock()
	if existingDepth, visited := c.visited[task.url]; visited && existingDepth <= task.depth {
		c.mu.Unlock()
		return
	}
	c.visited[task.url] = task.depth
	c.mu.Unlock()

	// Fetch the page
	body, err := c.fetch(ctx, task.url)
	if err != nil {
		c.mu.Lock()
		c.crawlErrors++
		c.mu.Unlock()
		return
	}

	c.mu.Lock()
	c.pagesCrawled++
	c.mu.Unlock()

	// Parse HTML and extract links
	links, forms, scripts, iframes := c.parseHTML(task.url, body)

	// Enqueue new tasks for discovered URLs (same-host only)
	discovered := append(links, forms...)
	discovered = append(discovered, iframes...)
	for _, link := range discovered {
		c.addURL(link)
		if task.depth < c.maxDepth {
			absURL := c.resolveURL(link)
			if absURL == "" || !c.isSameHost(absURL) {
				continue
			}
			c.mu.Lock()
			_, alreadyVisited := c.visited[absURL]
			c.mu.Unlock()
			if alreadyVisited {
				continue
			}

			pending.mu.Lock()
			pending.count++
			pending.mu.Unlock()

			select {
			case taskCh <- pageTask{url: absURL, depth: task.depth + 1}:
			case <-ctx.Done():
				pending.mu.Lock()
				pending.count--
				pending.mu.Unlock()
				return
			}
		}
	}

	// Collect JS files (can be external too)
	for _, src := range scripts {
		absSrc := c.resolveURL(src)
		if absSrc != "" {
			c.addJSFile(absSrc)
		}
	}
}

// fetch downloads a page with retries.
func (c *Crawler) fetch(ctx context.Context, rawURL string) ([]byte, error) {
	var lastErr error
	for i := 0; i <= c.retries; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(i) * 500 * time.Millisecond):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "GoSpyder/3.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")

		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		// Only process HTML responses
		contentType := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "text/html") &&
			!strings.HasPrefix(contentType, "application/xhtml+xml") {
			return nil, fmt.Errorf("non-HTML content: %s", contentType)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
		if err != nil {
			lastErr = err
			continue
		}

		return body, nil
	}

	return nil, fmt.Errorf("fetch failed after %d retries: %w", c.retries, lastErr)
}

// parseHTML extracts links, form actions, script src, and iframe src from HTML.
func (c *Crawler) parseHTML(baseURL string, body []byte) (links, forms, scripts, iframes []string) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				if href := getAttr(n, "href"); href != "" {
					if abs := c.resolveURL(href); abs != "" && c.isSameHost(abs) {
						links = append(links, abs)
					}
				}
			case "form":
				if action := getAttr(n, "action"); action != "" {
					if abs := c.resolveURL(action); abs != "" && c.isSameHost(abs) {
						forms = append(forms, abs)
					}
				}
			case "script":
				if src := getAttr(n, "src"); src != "" {
					if abs := c.resolveURL(src); abs != "" {
						scripts = append(scripts, abs)
					}
				}
			case "iframe":
				if src := getAttr(n, "src"); src != "" {
					if abs := c.resolveURL(src); abs != "" && c.isSameHost(abs) {
						iframes = append(iframes, abs)
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			f(child)
		}
	}
	f(doc)

	// Deduplicate results
	links = unique(links)
	forms = unique(forms)
	scripts = unique(scripts)
	iframes = unique(iframes)

	return
}

// resolveURL resolves a possibly-relative URL to absolute.
func (c *Crawler) resolveURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}

	// Skip anchors, javascript, mailto, etc.
	if strings.HasPrefix(rawURL, "#") ||
		strings.HasPrefix(rawURL, "javascript:") ||
		strings.HasPrefix(rawURL, "mailto:") ||
		strings.HasPrefix(rawURL, "tel:") ||
		strings.HasPrefix(rawURL, "data:") {
		return ""
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	// If already absolute, return as-is (strip fragment)
	if u.IsAbs() {
		u.Fragment = ""
		return u.String()
	}

	// Resolve relative URL
	base := *c.baseURL
	resolved := base.ResolveReference(u)
	resolved.Fragment = ""
	return resolved.String()
}

// isSameHost checks if a URL belongs to the same host as the target.
func (c *Crawler) isSameHost(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, c.baseHost)
}

// addURL records a discovered URL and checks for parameters and API patterns.
func (c *Crawler) addURL(rawURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Normalize: trim trailing slash
	normalized := strings.TrimSuffix(rawURL, "/")

	// Check if already recorded
	for _, existing := range c.urls {
		if existing == normalized {
			return
		}
	}

	c.urls = append(c.urls, normalized)

	// Check for parameters
	u, err := url.Parse(normalized)
	if err == nil && u.RawQuery != "" {
		paramKey := u.Path + "?" + u.RawQuery
		if !c.params[paramKey] {
			c.params[paramKey] = true
		}
	}

	// Check for API patterns
	if err == nil {
		detectAPI(u.Path, c.apis)
	}
}

// addJSFile records a discovered JavaScript file URL.
func (c *Crawler) addJSFile(rawURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Only add .js files
	if !strings.HasSuffix(rawURL, ".js") {
		return
	}

	if !c.jsFiles[rawURL] {
		c.jsFiles[rawURL] = true
	}
}

// detectAPI checks if a path matches known API patterns.
func detectAPI(pathStr string, results map[string]bool) {
	pathLower := strings.ToLower(pathStr)
	apiPatterns := []string{
		"/api/",
		"/graphql",
		"/v1/",
		"/v2/",
		"/rest/",
		"/swagger",
	}

	for _, pattern := range apiPatterns {
		if strings.Contains(pathLower, pattern) {
			results[pathStr] = true
			return
		}
	}
}

// result builds the final CrawlResult from discovered data.
func (c *Crawler) result() *CrawlResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	params := make([]string, 0, len(c.params))
	for p := range c.params {
		params = append(params, p)
	}

	apis := make([]string, 0, len(c.apis))
	for a := range c.apis {
		apis = append(apis, a)
	}

	jsFiles := make([]string, 0, len(c.jsFiles))
	for j := range c.jsFiles {
		jsFiles = append(jsFiles, j)
	}

	return &CrawlResult{
		URLs:    c.urls,
		Params:  params,
		APIs:    apis,
		JSFiles: jsFiles,
		Stats: CrawlStats{
			TotalURLs:    len(c.urls),
			TotalParams:  len(c.params),
			TotalAPIs:    len(c.apis),
			TotalJSFiles: len(c.jsFiles),
			PagesCrawled: c.pagesCrawled,
			Errors:       c.crawlErrors,
		},
	}
}

// getAttr safely retrieves an HTML attribute value.
func getAttr(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

// unique deduplicates a string slice.
func unique(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// Crawl is the top-level convenience function.
func Crawl(ctx context.Context, client *http.Client, targetURL string, maxDepth, concurrency, retries int) (*CrawlResult, error) {
	crawler, err := NewCrawler(client, targetURL, maxDepth, retries)
	if err != nil {
		return nil, err
	}
	return crawler.Crawl(ctx, concurrency)
}