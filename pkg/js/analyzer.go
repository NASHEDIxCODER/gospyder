package js

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxJSFileSize = 10 * 1024 * 1024 // 10MB

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// JSEndpoint represents an extracted API endpoint/path.
type JSEndpoint struct {
	Path     string `json:"path"`
	Source   string `json:"source"`  // the JS file URL where found
	Method   string `json:"method"`  // inferred HTTP method if known
	Context  string `json:"context"` // surrounding code snippet
}

// JSDomain represents an external domain found in JS.
type JSDomain struct {
	Domain string `json:"domain"`
	Source string `json:"source"`
	Type   string `json:"type"` // "url", "websocket", "fetch"
}

// JSSecret represents a detected secret with confidence.
type JSSecret struct {
	Type       string `json:"type"`
	Location   string `json:"location"`   // URL or file where found
	Preview    string `json:"preview"`    // short preview, not the full blob
	Confidence string `json:"confidence"` // LOW, MEDIUM, HIGH
	Raw        string `json:"-"`          // internal match, not exported to output
}

// JSFile describes a single discovered JS file.
type JSFile struct {
	URL      string `json:"url"`
	Size     int    `json:"size"`
	Analyzed bool   `json:"analyzed"`
}

// EndpointCategory groups endpoints by category.
type EndpointCategory string

const (
	CategoryAuth       EndpointCategory = "Authentication"
	CategoryAPI        EndpointCategory = "API"
	CategoryGraphQL    EndpointCategory = "GraphQL"
	CategoryUploads    EndpointCategory = "Uploads"
	CategoryAdmin      EndpointCategory = "Admin"
	CategoryUser       EndpointCategory = "User"
	CategoryOther      EndpointCategory = "Other"
)

// Result is the aggregated JS analysis result.
type Result struct {
	Files          []JSFile                 `json:"files"`
	Endpoints      []JSEndpoint             `json:"endpoints"`
	Domains        []JSDomain               `json:"domains"`
	Secrets        []JSSecret               `json:"secrets"`
	Stats          ResultStats              `json:"stats"`
	EndpointGroups map[EndpointCategory][]JSEndpoint `json:"endpoint_groups,omitempty"`
}

// ResultStats holds summary statistics.
type ResultStats struct {
	JSFiles    int `json:"js_files"`
	Endpoints  int `json:"endpoints"`
	Domains    int `json:"domains"`
	Secrets    int `json:"secrets"`
}

// Analyzer performs JavaScript discovery and analysis.
type Analyzer struct {
	client  *http.Client
	timeout time.Duration
	retries int
	threads int
}

// NewAnalyzer creates a new JS analyzer.
func NewAnalyzer(client *http.Client, timeout time.Duration, retries, threads int) *Analyzer {
	return &Analyzer{
		client:  client,
		timeout: timeout,
		retries: retries,
		threads: threads,
	}
}

// ---------------------------------------------------------------------------
// PHASE 1 + 2 - JavaScript Discovery & Download
// ---------------------------------------------------------------------------

// DiscoverAndAnalyze performs the full pipeline: discover JS files, download,
// extract endpoints, domains, and secrets.
func (a *Analyzer) DiscoverAndAnalyze(ctx context.Context, targetURL string) (*Result, error) {
	// PHASE 1: Extract JS URLs from the main page HTML
	jsURLs, err := a.extractJSFromPage(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JS from page: %w", err)
	}

	// Deduplicate
	seen := make(map[string]bool)
	unique := make([]string, 0, len(jsURLs))
	for _, u := range jsURLs {
		if !seen[u] {
			seen[u] = true
			unique = append(unique, u)
		}
	}
	jsURLs = unique

	if len(jsURLs) == 0 {
		return &Result{}, nil
	}

	// PHASE 2: Download JS files concurrently and analyze them
	files, contentMap := a.downloadJSFiles(ctx, jsURLs)

	// PHASE 3-5: Full analysis pipeline
	result := a.AnalyzeAll(files, contentMap)

	return result, nil
}

// extractJSFromPage fetches the HTML and finds all JavaScript references.
func (a *Analyzer) extractJSFromPage(ctx context.Context, pageURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "GoSpyder/3.0")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5MB limit
	if err != nil {
		return nil, err
	}

	html := string(body)
	baseURL, _ := url.Parse(pageURL)

	// Patterns to match JS references
	patterns := []*regexp.Regexp{
		// <script src="...">
		regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`),
		// <script type="module" src="...">
		regexp.MustCompile(`<script[^>]+type=["']module["'][^>]*src=["']([^"']+)["']`),
		// dynamic import("...")
		regexp.MustCompile(`import\(["']([^"']+)["']\)`),
		// import ... from "..."
		regexp.MustCompile(`(?:import|export)\s+(?:\{[^}]*\}\s+from\s+)?["']([^"']+(?:\.js|\.mjs|\.cjs))["']`),
		// new Worker("...")
		regexp.MustCompile(`new\s+(?:Worker|SharedWorker|ServiceWorker)\(["']([^"']+)["']`),
	}

	collected := make(map[string]bool)
	var results []string

	for _, re := range patterns {
		matches := re.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			jsURL := resolveURL(baseURL, m[1])
			if jsURL != "" && !collected[jsURL] {
				collected[jsURL] = true
				results = append(results, jsURL)
			}
		}
	}

	return results, nil
}

// resolveURL resolves a potentially relative URL against a base.
func resolveURL(base *url.URL, ref string) string {
	if strings.HasPrefix(ref, "data:") || strings.HasPrefix(ref, "blob:") {
		return ""
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	if refURL.IsAbs() {
		return ref
	}
	if base == nil {
		return ref
	}
	return base.ResolveReference(refURL).String()
}

// downloadJSFile downloads a single JS file and returns its content.
func (a *Analyzer) downloadJSFile(ctx context.Context, jsURL string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= a.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jsURL, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "GoSpyder/3.0")
		req.Header.Set("Accept", "application/javascript, */*")

		resp, err := a.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Check for non-200 status codes
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			lastErr = fmt.Errorf("unexpected status code %d", resp.StatusCode)
			continue
		}

		// Enforce max size
		limited := io.LimitReader(resp.Body, maxJSFileSize+1)
		data, err := io.ReadAll(limited)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		if len(data) > maxJSFileSize {
			return nil, fmt.Errorf("file too large (%d bytes)", len(data))
		}

		return data, nil
	}
	return nil, lastErr
}

// downloadJSFiles downloads multiple JS files concurrently using a worker pool.
// Returns the files metadata and a map of URL -> content for successful downloads.
func (a *Analyzer) downloadJSFiles(ctx context.Context, urls []string) ([]JSFile, map[string][]byte) {
	type job struct {
		url string
	}
	type result struct {
		url     string
		content []byte
		err     error
	}

	jobs := make(chan job, len(urls))
	results := make(chan result, len(urls))

	// Worker pool
	var wg sync.WaitGroup
	numWorkers := a.threads
	if numWorkers <= 0 {
		numWorkers = 10
	}
	if numWorkers > len(urls) {
		numWorkers = len(urls)
	}
	if numWorkers == 0 {
		numWorkers = 1
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				content, err := a.downloadJSFile(ctx, j.url)
				results <- result{url: j.url, content: content, err: err}
			}
		}()
	}

	// Send jobs
	for _, u := range urls {
		jobs <- job{url: u}
	}
	close(jobs)

	// Wait for all workers to finish
	wg.Wait()
	close(results)

	// Collect results
	files := make([]JSFile, 0, len(urls))
	contentMap := make(map[string][]byte)

	for r := range results {
		jsFile := JSFile{URL: r.url}
		if r.err == nil && len(r.content) > 0 {
			jsFile.Size = len(r.content)
			jsFile.Analyzed = true
			contentMap[r.url] = r.content
		} else {
			jsFile.Size = len(r.content)
		}
		files = append(files, jsFile)
	}

	return files, contentMap
}

// ---------------------------------------------------------------------------
// PHASE 3 - Endpoint Extraction Patterns
// ---------------------------------------------------------------------------

var endpointPatterns = []struct {
	re      *regexp.Regexp
	method  string
}{
	// fetch("/api/...") or fetch('...')
	{regexp.MustCompile(`fetch\(["']([^"']+)["']`), ""},
	// axios.get/post/put/delete(...)
	{regexp.MustCompile(`axios\.(?:get|post|put|patch|delete|head|options)\(["']([^"']+)["']`), ""},
	// XMLHttpRequest with .open("GET", "...")
	{regexp.MustCompile(`\.open\(["'](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["'],\s*["']([^"']+)["']`), ""},
	// jQuery.ajax / $.ajax / $.get / $.post
	{regexp.MustCompile(`\$\s*\.\s*(?:ajax|get|post|getJSON)\(["']([^"']+)["']`), ""},
	// $.ajax({url: "..."})
	{regexp.MustCompile(`url:\s*["']([^"']+)["']`), ""},
	// WebSocket construction
	{regexp.MustCompile(`new\s+WebSocket\(["']([^"']+)["']`), "WS"},
	// GraphQL endpoint patterns
	{regexp.MustCompile(`["'](/graphql[^"']*)["']`), "POST"},
	{regexp.MustCompile(`["'](/api[^"']*)["']`), ""},
	{regexp.MustCompile(`["'](/v[12][^"']*)["']`), ""},
	// Relative path patterns commonly used as endpoints
	{regexp.MustCompile(`["'](/(?:auth|login|register|admin|user|account|profile|logout|signup|signin|token|oauth|callback|webhook|health|status|metrics|config|settings|notification|search|upload|download|export|import|connect)[^"']*)["']`), ""},
}

// ExtractEndpoints extracts API endpoints from JS content.
func (a *Analyzer) ExtractEndpoints(content []byte, sourceURL string) []JSEndpoint {
	contentStr := string(content)
	seen := make(map[string]bool)
	var endpoints []JSEndpoint

	for _, p := range endpointPatterns {
		matches := p.re.FindAllStringSubmatch(contentStr, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			raw := m[1]
			// Skip obvious non-endpoints
			if skipNonEndpoint(raw) {
				continue
			}
			// Validate endpoint - reject invalid protocol-only patterns
			if isInvalidEndpoint(raw) {
				continue
			}
			// Normalize
			endpoint := normalizeEndpoint(raw)
			if endpoint == "" || seen[endpoint] {
				continue
			}
			seen[endpoint] = true

			// Extract context (surrounding ~60 chars)
			ctx := extractContext(contentStr, m[0])

			method := p.method
			if method == "" {
				method = inferMethod(raw)
			}

			endpoints = append(endpoints, JSEndpoint{
				Path:    endpoint,
				Source:  sourceURL,
				Method:  method,
				Context: ctx,
			})
		}
	}

	return endpoints
}

// isInvalidEndpoint rejects protocol-only or clearly invalid endpoint strings.
func isInvalidEndpoint(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	// Reject bare protocols that are not real endpoints
	if lower == "https:" || lower == "http:" || lower == "https://" || lower == "http://" {
		return true
	}
	if strings.HasPrefix(lower, "javascript:") {
		return true
	}
	if strings.HasPrefix(lower, "data:") && !strings.Contains(lower, "/api") && !strings.Contains(lower, "/graphql") {
		return true
	}
	return false
}

// normalizeEndpoint cleans and normalizes an endpoint path.
func normalizeEndpoint(raw string) string {
	// Remove quotes if any remain
	raw = strings.Trim(raw, "\"'`")
	// Ignore template literals that contain expressions
	if strings.Contains(raw, "${") && strings.Contains(raw, "}") {
		// Still capture the template prefix if useful
		parts := strings.Split(raw, "${")
		raw = parts[0]
		if raw == "" || raw == "/" {
			return ""
		}
	}
	// Ensure it starts with /
	if !strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") && !strings.HasPrefix(raw, "ws://") && !strings.HasPrefix(raw, "wss://") {
		raw = "/" + raw
	}
	// Remove query strings for dedup
	if idx := strings.Index(raw, "?"); idx >= 0 {
		raw = raw[:idx]
	}
	// Remove fragments
	if idx := strings.Index(raw, "#"); idx >= 0 {
		raw = raw[:idx]
	}
	// Remove trailing slash
	raw = strings.TrimRight(raw, "/")
	if raw == "" {
		return ""
	}
	return raw
}

// skipNonEndpoint returns true if the string is unlikely to be an endpoint.
func skipNonEndpoint(s string) bool {
	// Too short
	if len(s) < 3 {
		return true
	}
	// These are probably not endpoints
	nonEndpoints := []string{
		"javascript:", "data:", "blob:", "mailto:", "tel:",
		".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
		".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
		".mp4", ".mp3", ".avi", ".mov", ".webm",
	}
	lower := strings.ToLower(s)
	for _, ne := range nonEndpoints {
		if strings.Contains(lower, ne) {
			return true
		}
	}
	// Likely a relative JS file path
	if strings.HasSuffix(lower, ".js") && !strings.Contains(lower, "/api") && !strings.Contains(lower, "/graphql") {
		return true
	}
	return false
}

// inferMethod tries to infer HTTP method from endpoint name.
func inferMethod(path string) string {
	lower := strings.ToLower(path)
	switch {
	case containsAny(lower, "logout", "signout", "delete", "remove", "destroy"):
		return "DELETE"
	case containsAny(lower, "register", "signup", "create", "new", "upload"):
		return "POST"
	case containsAny(lower, "login", "signin", "auth", "token", "oauth", "callback"):
		return "POST"
	case containsAny(lower, "update", "edit", "modify", "patch", "settings", "profile"):
		return "PATCH"
	case containsAny(lower, "/api/", "/v1/", "/v2/", "/graphql"):
		return ""
	default:
		return "GET"
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func extractContext(content, match string) string {
	idx := strings.Index(content, match)
	if idx < 0 {
		return ""
	}
	start := idx - 40
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + 20
	if end > len(content) {
		end = len(content)
	}
	ctx := content[start:end]
	// Clean newlines/tabs for display
	ctx = strings.ReplaceAll(ctx, "\n", " ")
	ctx = strings.ReplaceAll(ctx, "\r", "")
	ctx = strings.ReplaceAll(ctx, "\t", " ")
	ctx = strings.TrimSpace(ctx)
	if len(ctx) > 80 {
		ctx = ctx[:80] + "..."
	}
	return ctx
}

// ---------------------------------------------------------------------------
// PHASE 4 - Domain Extraction & Validation
// ---------------------------------------------------------------------------

var (
	// Extract absolute URLs
	urlPattern = regexp.MustCompile(`https?://([a-zA-Z0-9.-]+)(?:/|:|"|'|\s|\)|,|$|])`)
	// Extract WebSocket URLs
	wsPattern = regexp.MustCompile(`wss?://([a-zA-Z0-9.-]+)(?:/|:|"|'|\s|\)|,|$|])`)
)

// isValidDomain checks whether a domain is a valid FQDN with at least one dot.
func isValidDomain(domain string) bool {
	// Must contain a dot
	if !strings.Contains(domain, ".") {
		return false
	}
	// Reject localhost and other non-FQDN patterns
	lower := strings.ToLower(domain)
	if lower == "localhost" || strings.HasPrefix(lower, "localhost.") {
		return false
	}
	// Validate hostname via net.LookupHost-compatible check
	// Use net.ParseIP or validate characters
	if net.ParseIP(domain) != nil {
		return true // IP addresses are valid
	}
	// Basic hostname validation
	if len(domain) > 253 {
		return false
	}
	for _, part := range strings.Split(domain, ".") {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		if part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

// ExtractDomains extracts external domains from JS content.
func (a *Analyzer) ExtractDomains(content []byte, sourceURL string) []JSDomain {
	contentStr := string(content)
	seen := make(map[string]bool)
	var domains []JSDomain

	// URL domains
	urlMatches := urlPattern.FindAllStringSubmatch(contentStr, -1)
	for _, m := range urlMatches {
		if len(m) < 2 {
			continue
		}
		domain := strings.ToLower(m[1])
		// Apply domain validation
		if !isValidDomain(domain) {
			continue
		}
		if seen[domain] {
			continue
		}
		seen[domain] = true

		// Determine type
		dType := "url"
		if strings.HasPrefix(m[0], "wss://") || strings.HasPrefix(m[0], "ws://") {
			dType = "websocket"
		}

		domains = append(domains, JSDomain{
			Domain: domain,
			Source: sourceURL,
			Type:   dType,
		})
	}

	// WS pattern (separate to catch any missed)
	wsMatches := wsPattern.FindAllStringSubmatch(contentStr, -1)
	for _, m := range wsMatches {
		if len(m) < 2 {
			continue
		}
		domain := strings.ToLower(m[1])
		if !isValidDomain(domain) {
			continue
		}
		if seen[domain] {
			continue
		}
		seen[domain] = true
		domains = append(domains, JSDomain{
			Domain: domain,
			Source: sourceURL,
			Type:   "websocket",
		})
	}

	return domains
}

// ---------------------------------------------------------------------------
// PHASE 5 - Secret Detection (Improved)
// ---------------------------------------------------------------------------

type secretPattern struct {
	name       string
	confidence string
	re         *regexp.Regexp
}

var secretPatterns = []secretPattern{
	// AWS Access Keys - AKIA... (HIGH confidence when matched with context)
	{
		name:       "AWS Access Key",
		confidence: "HIGH",
		re:         regexp.MustCompile(`(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})`),
	},
	// AWS Secret Key
	{
		name:       "AWS Secret Key",
		confidence: "HIGH",
		re:         regexp.MustCompile(`(?i)(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)["']?\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']`),
	},
	// Google API Key
	{
		name:       "Google API Key",
		confidence: "MEDIUM",
		re:         regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	},
	// Stripe Live Key
	{
		name:       "Stripe Live Key",
		confidence: "HIGH",
		re:         regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
	},
	// Stripe Test Key
	{
		name:       "Stripe Test Key",
		confidence: "MEDIUM",
		re:         regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24,}`),
	},
	// GitHub Token
	{
		name:       "GitHub Token",
		confidence: "HIGH",
		re:         regexp.MustCompile(`gh[ps]_[0-9a-zA-Z]{36,}`),
	},
	// GitHub OAuth
	{
		name:       "GitHub OAuth Token",
		confidence: "MEDIUM",
		re:         regexp.MustCompile(`(?i)(?:github_token|GITHUB_TOKEN)["']?\s*[:=]\s*["']([^"']{16,})["']`),
	},
	// JWT - looks for typical JWT patterns
	{
		name:       "JWT Secret/Token",
		confidence: "MEDIUM",
		re:         regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`),
	},
	// Firebase URL
	{
		name:       "Firebase URL",
		confidence: "MEDIUM",
		re:         regexp.MustCompile(`https?://[a-zA-Z0-9-]+\.firebaseio\.com`),
	},
}

// ExtractSecrets extracts potential secrets from JS content.
func (a *Analyzer) ExtractSecrets(content []byte, sourceURL string) []JSSecret {
	contentStr := string(content)
	seen := make(map[string]bool)
	var secrets []JSSecret

	for _, sp := range secretPatterns {
		matches := sp.re.FindAllStringSubmatch(contentStr, -1)
		if len(matches) == 0 {
			continue
		}
		for _, m := range matches {
			var matchStr string
			if len(m) > 1 {
				matchStr = m[0] // full match
			} else {
				matchStr = m[0]
			}

			if seen[matchStr] {
				continue
			}
			seen[matchStr] = true

			// Reject the pattern "secret":"protected" and other obvious non-secrets
			if strings.Contains(strings.ToLower(matchStr), `"protected"`) ||
				strings.Contains(strings.ToLower(matchStr), `"public"`) ||
				strings.HasPrefix(matchStr, `"`) && strings.Count(matchStr, `"`) >= 4 {
				continue
			}

			// Create preview (truncated)
			preview := matchStr
			if len(preview) > 40 {
				preview = preview[:20] + "..." + preview[len(preview)-17:]
			}

			secrets = append(secrets, JSSecret{
				Type:       sp.name,
				Location:   sourceURL,
				Preview:    preview,
				Confidence: sp.confidence,
				Raw:        matchStr,
			})
		}
	}

	return secrets
}

// ---------------------------------------------------------------------------
// Endpoint Categorization
// ---------------------------------------------------------------------------

// categorizeEndpoint groups an endpoint path into a category.
func categorizeEndpoint(path string) EndpointCategory {
	lower := strings.ToLower(path)
	switch {
	case containsAny(lower, "/auth", "/login", "/signin", "/signup", "/register",
		"/logout", "/signout", "/oauth", "/token", "/callback", "/sso"):
		return CategoryAuth
	case containsAny(lower, "/graphql"):
		return CategoryGraphQL
	case containsAny(lower, "/upload", "/file", "/media", "/asset", "/image"):
		return CategoryUploads
	case containsAny(lower, "/admin", "/manage", "/dashboard", "/control", "/moderate", "/moderation"):
		return CategoryAdmin
	case containsAny(lower, "/user", "/account", "/profile", "/member", "/customer", "/subscriber"):
		return CategoryUser
	case containsAny(lower, "/api", "/v1/", "/v2/", "/v3/", "/rest", "/service", "/endpoint", "/rpc"):
		return CategoryAPI
	default:
		return CategoryOther
	}
}

// categorizeEndpoints groups endpoints by category, with stable ordering.
func categorizeEndpoints(endpoints []JSEndpoint) map[EndpointCategory][]JSEndpoint {
	groups := make(map[EndpointCategory][]JSEndpoint)
	for _, ep := range endpoints {
		cat := categorizeEndpoint(ep.Path)
		groups[cat] = append(groups[cat], ep)
	}
	// Sort each category's endpoints by path for stability
	for cat := range groups {
		sort.Slice(groups[cat], func(i, j int) bool {
			return groups[cat][i].Path < groups[cat][j].Path
		})
	}
	return groups
}

// ---------------------------------------------------------------------------
// Sorting Helpers
// ---------------------------------------------------------------------------

// sortResult sorts all findings within a result for stable, deterministic output.
func sortResult(r *Result) {
	// Sort files by URL
	sort.Slice(r.Files, func(i, j int) bool {
		return r.Files[i].URL < r.Files[j].URL
	})
	// Sort endpoints by path (primary), then method (secondary), then source
	sort.Slice(r.Endpoints, func(i, j int) bool {
		if r.Endpoints[i].Path != r.Endpoints[j].Path {
			return r.Endpoints[i].Path < r.Endpoints[j].Path
		}
		if r.Endpoints[i].Method != r.Endpoints[j].Method {
			return r.Endpoints[i].Method < r.Endpoints[j].Method
		}
		return r.Endpoints[i].Source < r.Endpoints[j].Source
	})
	// Sort domains by domain
	sort.Slice(r.Domains, func(i, j int) bool {
		return r.Domains[i].Domain < r.Domains[j].Domain
	})
	// Sort secrets by type, then confidence
	sort.Slice(r.Secrets, func(i, j int) bool {
		if r.Secrets[i].Type != r.Secrets[j].Type {
			return r.Secrets[i].Type < r.Secrets[j].Type
		}
		return r.Secrets[i].Confidence > r.Secrets[j].Confidence
	})
}

// ---------------------------------------------------------------------------
// Full Analysis Pipeline
// ---------------------------------------------------------------------------

// AnalyzeAll applies endpoint, domain, and secret extraction to downloaded content.
func (a *Analyzer) AnalyzeAll(files []JSFile, contentMap map[string][]byte) *Result {
	result := &Result{}
	endpointSeen := make(map[string]bool) // global dedup key: path|method
	domainSeen := make(map[string]bool)
	secretSeen := make(map[string]bool)

	for _, f := range files {
		if !f.Analyzed {
			result.Files = append(result.Files, f)
			continue
		}
		result.Files = append(result.Files, f)

		content, ok := contentMap[f.URL]
		if !ok || len(content) == 0 {
			continue
		}

		// Extract endpoints
		endpoints := a.ExtractEndpoints(content, f.URL)
		for _, e := range endpoints {
			// Global deduplication: path + method (not per-source)
			key := e.Path + "|" + e.Method
			if !endpointSeen[key] {
				endpointSeen[key] = true
				result.Endpoints = append(result.Endpoints, e)
			}
		}

		// Extract domains
		domains := a.ExtractDomains(content, f.URL)
		for _, d := range domains {
			if !domainSeen[d.Domain] {
				domainSeen[d.Domain] = true
				result.Domains = append(result.Domains, d)
			}
		}

		// Extract secrets
		secrets := a.ExtractSecrets(content, f.URL)
		for _, s := range secrets {
			if !secretSeen[s.Type+s.Preview+s.Location] {
				secretSeen[s.Type+s.Preview+s.Location] = true
				result.Secrets = append(result.Secrets, s)
			}
		}
	}

	// Sort everything for stable output
	sortResult(result)

	// Build endpoint groups (categorized)
	result.EndpointGroups = categorizeEndpoints(result.Endpoints)

	// Build statistics
	result.Stats = ResultStats{
		JSFiles:   len(result.Files),
		Endpoints: len(result.Endpoints),
		Domains:   len(result.Domains),
		Secrets:   len(result.Secrets),
	}

	return result
}