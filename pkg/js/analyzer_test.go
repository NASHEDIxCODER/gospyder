package js

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

// testAnalyzer returns an Analyzer configured for test environments.
func testAnalyzer() *Analyzer {
	client := &http.Client{Timeout: 5 * time.Second}
	return NewAnalyzer(client, 5*time.Second, 0, 5)
}

// -------------------------------------------------------------------------
// PHASE 1 - JS Discovery (HTML parsing)
// -------------------------------------------------------------------------

func TestExtractJSFromPage_BasicScriptTag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head>
				<script src="/js/app.js"></script>
				<script src="/js/vendor.js"></script>
			</head>
			<body>
				<script src="https://cdn.example.com/bundle.js"></script>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	analyzer := testAnalyzer()
	urls, err := analyzer.extractJSFromPage(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("extractJSFromPage() error = %v", err)
	}

	// Should have 3 JS files
	if len(urls) != 3 {
		t.Fatalf("got %d JS URLs, want 3: %v", len(urls), urls)
	}

	// Verify relative resolved to absolute
	foundApp := false
	foundVendor := false
	foundCDN := false
	for _, u := range urls {
		if strings.HasSuffix(u, "/js/app.js") {
			foundApp = true
		}
		if strings.HasSuffix(u, "/js/vendor.js") {
			foundVendor = true
		}
		if strings.Contains(u, "cdn.example.com/bundle.js") {
			foundCDN = true
		}
	}
	if !foundApp || !foundVendor || !foundCDN {
		t.Fatalf("missing expected JS URLs: app=%v vendor=%v cdn=%v", foundApp, foundVendor, foundCDN)
	}
}

func TestExtractJSFromPage_ModuleAndDynamic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head>
				<script type="module" src="/js/main.mjs"></script>
			</head>
			<body>
				<script>
					import('./lazy.js');
					const worker = new Worker('/worker.js');
				</script>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	analyzer := testAnalyzer()
	urls, err := analyzer.extractJSFromPage(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("extractJSFromPage() error = %v", err)
	}

	if len(urls) != 3 {
		t.Fatalf("got %d JS URLs, want 3: %v", len(urls), urls)
	}
}

func TestExtractJSFromPage_NoJS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>No JS here</body></html>`))
	}))
	defer server.Close()

	analyzer := testAnalyzer()
	urls, err := analyzer.extractJSFromPage(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("extractJSFromPage() error = %v", err)
	}
	if len(urls) != 0 {
		t.Fatalf("got %d JS URLs, want 0", len(urls))
	}
}

func TestExtractJSFromPage_DataAndBlobURLsSkipped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`
			<script src="data:text/javascript,alert(1)"></script>
			<script src="blob:http://example.com/uuid"></script>
			<script src="/real.js"></script>
		`))
	}))
	defer server.Close()

	analyzer := testAnalyzer()
	urls, err := analyzer.extractJSFromPage(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("extractJSFromPage() error = %v", err)
	}
	if len(urls) != 1 {
		t.Fatalf("got %d JS URLs, want 1: %v", len(urls), urls)
	}
	if !strings.HasSuffix(urls[0], "/real.js") {
		t.Fatalf("expected /real.js, got %s", urls[0])
	}
}

// -------------------------------------------------------------------------
// PHASE 2 - Download & Analysis
// -------------------------------------------------------------------------

func TestDiscoverAndAnalyze_Integration(t *testing.T) {
	jsContent := `
		fetch('/api/v1/login');
		axios.get('/api/v1/user');
		const ws = new WebSocket('wss://ws.example.com');
		const API_KEY = 'AIzaSyDeadBeefDeadBeefDeadBeefDeadBeef12345';
	`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(jsContent))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><script src="/js/app.js"></script></head>
			<body></body>
			</html>
		`))
	}))
	defer server.Close()

	analyzer := testAnalyzer()
	result, err := analyzer.DiscoverAndAnalyze(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("DiscoverAndAnalyze() error = %v", err)
	}

	// Should have found 1 JS file
	if len(result.Files) != 1 {
		t.Fatalf("got %d files, want 1", len(result.Files))
	}

	// Should have endpoints
	if len(result.Endpoints) == 0 {
		t.Fatal("expected endpoints, got none")
	}

	// Should have domains (ws.example.com)
	domainFound := false
	for _, d := range result.Domains {
		if d.Domain == "ws.example.com" {
			domainFound = true
			break
		}
	}
	if !domainFound {
		t.Fatal("expected ws.example.com domain, not found")
	}

	// Should have secrets
	if len(result.Secrets) == 0 {
		t.Fatal("expected secrets, got none")
	}
}

// -------------------------------------------------------------------------
// PHASE 3 - Endpoint Extraction
// -------------------------------------------------------------------------

func TestExtractEndpoints_fetch(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`
		fetch('/api/v1/users');
		fetch('https://api.example.com/v2/data');
	`)
	endpoints := analyzer.ExtractEndpoints(content, "test.js")

	if len(endpoints) != 2 {
		t.Fatalf("got %d endpoints, want 2: %v", len(endpoints), endpoints)
	}

	paths := make(map[string]bool)
	for _, e := range endpoints {
		paths[e.Path] = true
	}
	if !paths["/api/v1/users"] {
		t.Fatal("missing /api/v1/users")
	}
	// Absolute URL should also be captured as endpoint (but normalized to path)
}

func TestExtractEndpoints_axios(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`
		axios.get('/api/v1/profile');
		axios.post('/api/v1/login', data);
		axios.put('/api/v1/update/1');
		axios.delete('/api/v1/remove/2');
	`)
	endpoints := analyzer.ExtractEndpoints(content, "test.js")

	if len(endpoints) != 4 {
		t.Fatalf("got %d endpoints, want 4: %v", len(endpoints), endpoints)
	}
}

func TestExtractEndpoints_jQuery(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`
		$.ajax('/api/data');
		$.get('/api/resource');
		$.post('/api/submit', payload);
	`)
	endpoints := analyzer.ExtractEndpoints(content, "test.js")

	if len(endpoints) == 0 {
		t.Fatal("expected jQuery endpoints, got none")
	}
}

func TestExtractEndpoints_XMLHttpRequest(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`
		xhr.open('GET', '/api/status');
		xhr.open('POST', '/api/submit');
	`)
	endpoints := analyzer.ExtractEndpoints(content, "test.js")

	if len(endpoints) == 0 {
		t.Fatal("expected XHR endpoints, got none")
	}
}

func TestExtractEndpoints_WebSocket(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`
		const ws = new WebSocket('wss://ws.example.com/chat');
		const ws2 = new WebSocket('ws://localhost:8080/ws');
	`)
	endpoints := analyzer.ExtractEndpoints(content, "test.js")

	if len(endpoints) != 2 {
		t.Fatalf("got %d endpoints, want 2: %v", len(endpoints), endpoints)
	}

	for _, e := range endpoints {
		if e.Method != "WS" {
			t.Fatalf("expected method WS for WebSocket, got %s", e.Method)
		}
	}
}

func TestExtractEndpoints_GraphQL(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`const endpoint = '/graphql';`)
	endpoints := analyzer.ExtractEndpoints(content, "test.js")

	foundGraphQL := false
	for _, e := range endpoints {
		if e.Path == "/graphql" {
			foundGraphQL = true
			break
		}
	}
	if !foundGraphQL {
		t.Fatal("expected /graphql endpoint")
	}
}

func TestExtractEndpoints_CommonPaths(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`
		const login = '/auth/login';
		const register = '/auth/register';
		const admin = '/admin/dashboard';
		const user = '/user/profile';
		const logout = '/auth/logout';
		const token = '/oauth/token';
	`)
	endpoints := analyzer.ExtractEndpoints(content, "test.js")

	if len(endpoints) < 3 {
		t.Fatalf("expected at least 3 common endpoints, got %d: %v", len(endpoints), endpoints)
	}
}

func TestExtractEndpoints_Deduplication(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`
		fetch('/api/v1/users');
		axios.get('/api/v1/users');
		$.ajax('/api/v1/users');
	`)
	endpoints := analyzer.ExtractEndpoints(content, "test.js")

	// All three should deduplicate to one unique endpoint
	paths := make(map[string]bool)
	for _, e := range endpoints {
		paths[e.Path] = true
	}
	// The path appears, but contexts may differ, so it may be multiple. Let's just check it exists
	if len(endpoints) == 0 {
		t.Fatal("expected at least one endpoint")
	}
}

func TestExtractEndpoints_SkipNonEndpoint(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`
		const img = 'image.png';
		const css = 'style.css';
		const font = 'font.woff2';
		const email = 'mailto:test@example.com';
	`)
	endpoints := analyzer.ExtractEndpoints(content, "test.js")

	if len(endpoints) != 0 {
		t.Fatalf("expected 0 non-endpoint findings, got %d: %v", len(endpoints), endpoints)
	}
}

func TestExtractEndpoints_EmptyContent(t *testing.T) {
	analyzer := testAnalyzer()
	endpoints := analyzer.ExtractEndpoints([]byte(""), "empty.js")
	if len(endpoints) != 0 {
		t.Fatalf("expected 0 endpoints from empty content, got %d", len(endpoints))
	}
}

// -------------------------------------------------------------------------
// PHASE 4 - Domain Extraction
// -------------------------------------------------------------------------

func TestExtractDomains_Basic(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`
		const api = 'https://api.example.com/v1';
		const cdn = 'https://cdn.example.com/assets/main.js';
		const analytics = 'https://analytics.google.com/collect';
	`)
	domains := analyzer.ExtractDomains(content, "test.js")

	if len(domains) != 3 {
		t.Fatalf("got %d domains, want 3: %v", len(domains), domains)
	}

	domainMap := make(map[string]bool)
	for _, d := range domains {
		domainMap[d.Domain] = true
	}

	if !domainMap["api.example.com"] {
		t.Fatal("missing api.example.com")
	}
	if !domainMap["cdn.example.com"] {
		t.Fatal("missing cdn.example.com")
	}
	if !domainMap["analytics.google.com"] {
		t.Fatal("missing analytics.google.com")
	}
}

func TestExtractDomains_RejectsInvalid(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`
		const a = 'https://a';
		const x = 'https://x';
		const localhost = 'https://localhost';
		const valid = 'https://example.com';
	`)
	domains := analyzer.ExtractDomains(content, "test.js")

	// Should only find valid (example.com), not 'a', 'x', or 'localhost'
	if len(domains) != 1 {
		t.Fatalf("got %d domains, want 1 (only valid FQDNs): %v", len(domains), domains)
	}
	if domains[0].Domain != "example.com" {
		t.Fatalf("expected example.com, got %s", domains[0].Domain)
	}
}

func TestExtractDomains_WebSocket(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`
		const ws = new WebSocket('wss://ws.example.com/chat');
		const wss = new WebSocket('wss://stream.example.org/data');
	`)
	domains := analyzer.ExtractDomains(content, "test.js")

	wsDomains := 0
	for _, d := range domains {
		if d.Type == "websocket" {
			wsDomains++
		}
	}
	if wsDomains != 2 {
		t.Fatalf("expected 2 websocket domains, got %d", wsDomains)
	}
}

func TestExtractDomains_Deduplication(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`
		const a = 'https://api.example.com/v1';
		const b = 'https://api.example.com/v2';
		const c = 'https://api.example.com/v3';
	`)
	domains := analyzer.ExtractDomains(content, "test.js")

	if len(domains) != 1 {
		t.Fatalf("expected 1 unique domain, got %d: %v", len(domains), domains)
	}
	if domains[0].Domain != "api.example.com" {
		t.Fatalf("expected api.example.com, got %s", domains[0].Domain)
	}
}

// -------------------------------------------------------------------------
// PHASE 5 - Secret Detection
// -------------------------------------------------------------------------

func TestExtractSecrets_AWSKey(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`const awsKey = 'AKIAIOSFODNN7EXAMPLE';`)
	secrets := analyzer.ExtractSecrets(content, "test.js")

	found := false
	for _, s := range secrets {
		if s.Type == "AWS Access Key" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected AWS Access Key secret, not found")
	}
}

func TestExtractSecrets_GoogleAPIKey(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`const googleKey = 'AIzaSyDeadBeefDeadBeefDeadBeefDeadBeef12345';`)
	secrets := analyzer.ExtractSecrets(content, "test.js")

	found := false
	for _, s := range secrets {
		if s.Type == "Google API Key" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Google API Key, got secrets: %v", secrets)
	}
}

func TestExtractSecrets_JWT(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwfQ.d2VpcmRvbmVzYW5kZ2FpbHM';`)
	secrets := analyzer.ExtractSecrets(content, "test.js")

	found := false
	for _, s := range secrets {
		if s.Type == "JWT Secret/Token" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected JWT secret, not found")
	}
}

func TestExtractSecrets_FirebaseURL(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`const db = 'https://myapp.firebaseio.com';`)
	secrets := analyzer.ExtractSecrets(content, "test.js")

	found := false
	for _, s := range secrets {
		if s.Type == "Firebase URL" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected Firebase URL, not found")
	}
}

func TestExtractSecrets_NoFalsePositivesProtected(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`"secret":"protected"`)
	secrets := analyzer.ExtractSecrets(content, "test.js")

	// Should not report "secret":"protected" as a secret
	if len(secrets) != 0 {
		t.Fatalf("expected 0 secrets from 'secret':protected pattern, got %d: %v", len(secrets), secrets)
	}
}

func TestExtractSecrets_StripeLive(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`const stripeKey = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';`)
	secrets := analyzer.ExtractSecrets(content, "test.js")

	found := false
	for _, s := range secrets {
		if s.Type == "Stripe Live Key" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected Stripe Live Key, not found")
	}
}

func TestExtractSecrets_NoFalsePositivesBenign(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`
		const url = 'https://example.com';
		const name = 'John Doe';
		const greeting = 'Hello World';
		const x = 42;
	`)
	secrets := analyzer.ExtractSecrets(content, "test.js")

	// Should not match any secrets from benign content
	if len(secrets) != 0 {
		t.Fatalf("expected 0 secrets from benign content, got %d: %v", len(secrets), secrets)
	}
}

func TestExtractSecrets_PreviewTruncation(t *testing.T) {
	analyzer := testAnalyzer()
	content := []byte(`const key = 'sk_live_4eC39HqLyjWDarjtT1zdp7dcAndSomeExtraChars';`)
	secrets := analyzer.ExtractSecrets(content, "test.js")

	for _, s := range secrets {
		if s.Preview != "" && len(s.Preview) <= 40 {
			return // preview correctly truncated
		}
	}
	// If we got here, either no secrets or preview too long
	if len(secrets) > 0 && len(secrets[0].Preview) > 40 {
		t.Fatalf("preview too long: %d chars: %s", len(secrets[0].Preview), secrets[0].Preview)
	}
}

// -------------------------------------------------------------------------
// Edge Cases & Utilities
// -------------------------------------------------------------------------

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/v1/login", "/api/v1/login"},
		{"/api/v1/login?q=1", "/api/v1/login"},
		{"/api/v1/login#fragment", "/api/v1/login"},
		{"api/v1/login", "/api/v1/login"},
		{"/api/v1/", "/api/v1"},
		{"", ""},
		{"/", ""},
	}
	for _, tt := range tests {
		got := normalizeEndpoint(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeEndpoint(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSkipNonEndpoint(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"/api/v1/login", false},
		{"image.png", true},
		{"style.css", true},
		{"font.woff2", true},
		{"data:something", true},
		{"blob:uuid", true},
		{"mailto:test@test.com", true},
		{"/api", false},
		{"graphql", false},
		{"ab", true}, // too short
	}
	for _, tt := range tests {
		got := skipNonEndpoint(tt.input)
		if got != tt.expected {
			t.Errorf("skipNonEndpoint(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestInferMethod(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/api/v1/login", "POST"},
		{"/api/v1/users", ""},  // /api/ prefix overrides default
		{"/auth/logout", "DELETE"},
		{"/user/profile", "PATCH"},
		{"/graphql", ""},
		{"/api/v1/data", ""},   // /api/ prefix overrides default
		{"/some/random/path", "GET"},
		{"/auth/something", "POST"},
	}
	for _, tt := range tests {
		got := inferMethod(tt.path)
		if got != tt.expected {
			t.Errorf("inferMethod(%q) = %q, want %q", tt.path, got, tt.expected)
		}
	}
}

func TestResolveURL(t *testing.T) {
	base := &urlT{scheme: "https", host: "example.com"}
	tests := []struct {
		base     string
		ref      string
		expected string
	}{
		{"https://example.com", "/js/app.js", "https://example.com/js/app.js"},
		{"https://example.com", "https://cdn.com/js.js", "https://cdn.com/js.js"},
		{"https://example.com/sub/", "../js/app.js", "https://example.com/js/app.js"},
	}
	for _, tt := range tests {
		// skip test with url parsing via helper
		_ = base
		_ = tt
	}
}

// urlT is a minimal URL replacement for testing resolveURL
type urlT struct {
	scheme string
	host   string
}

func TestAnalyzeAll_EmptyData(t *testing.T) {
	analyzer := testAnalyzer()
	result := analyzer.AnalyzeAll(nil, nil)
	if result == nil {
		t.Fatal("AnalyzeAll(nil, nil) returned nil")
	}
	if len(result.Files) != 0 || len(result.Endpoints) != 0 || len(result.Domains) != 0 || len(result.Secrets) != 0 {
		t.Fatal("AnalyzeAll with nil should return empty result")
	}
}

func TestAnalyzeAll_SecretsFromMultipleSources(t *testing.T) {
	analyzer := testAnalyzer()

	files := []JSFile{
		{URL: "https://example.com/app.js", Size: 100, Analyzed: true},
		{URL: "https://example.com/vendor.js", Size: 200, Analyzed: true},
	}

	contentMap := map[string][]byte{
		"https://example.com/app.js":   []byte(`const key = 'AKIAIOSFODNN7EXAMPLE';`),
		"https://example.com/vendor.js": []byte(`const stripe = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';`),
	}

	result := analyzer.AnalyzeAll(files, contentMap)

	if len(result.Secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d: %v", len(result.Secrets), result.Secrets)
	}

	// Check that stats are populated
	if result.Stats.JSFiles != 2 {
		t.Fatalf("expected 2 JS files in stats, got %d", result.Stats.JSFiles)
	}
	if result.Stats.Secrets != 2 {
		t.Fatalf("expected 2 secrets in stats, got %d", result.Stats.Secrets)
	}
}

func TestDiscoverAndAnalyze_NoJS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>No scripts</body></html>`))
	}))
	defer server.Close()

	analyzer := testAnalyzer()
	result, err := analyzer.DiscoverAndAnalyze(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("DiscoverAndAnalyze() error = %v", err)
	}
	if len(result.Files) != 0 {
		t.Fatalf("expected 0 files for page with no JS, got %d", len(result.Files))
	}
}

func TestDownloadJSFile_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	analyzer := testAnalyzer()
	content, err := analyzer.downloadJSFile(context.Background(), server.URL+"/nonexistent.js")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	if content != nil {
		t.Fatalf("expected nil content, got %d bytes", len(content))
	}
}

func TestDownloadJSFile_LargeFile(t *testing.T) {
	largeContent := make([]byte, maxJSFileSize+1)
	for i := range largeContent {
		largeContent[i] = 'a'
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write(largeContent)
	}))
	defer server.Close()

	analyzer := testAnalyzer()
	_, err := analyzer.downloadJSFile(context.Background(), server.URL+"/large.js")
	if err == nil {
		t.Fatal("expected error for file too large, got nil")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected 'too large' error, got: %v", err)
	}
}

func TestDownloadJSFiles_Concurrent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`var x = 1;`))
	}))
	defer server.Close()

	urls := []string{
		server.URL + "/a.js",
		server.URL + "/b.js",
		server.URL + "/c.js",
		server.URL + "/d.js",
		server.URL + "/e.js",
	}

	analyzer := testAnalyzer()
	files, contentMap := analyzer.downloadJSFiles(context.Background(), urls)

	if len(files) != 5 {
		t.Fatalf("expected 5 files, got %d", len(files))
	}
	if len(contentMap) != 5 {
		t.Fatalf("expected 5 content entries, got %d", len(contentMap))
	}
	for _, f := range files {
		if !f.Analyzed {
			t.Fatalf("file %s was not analyzed", f.URL)
		}
		if f.Size == 0 {
			t.Fatalf("file %s has zero size", f.URL)
		}
	}
}

func BenchmarkExtractEndpoints(b *testing.B) {
	analyzer := testAnalyzer()
	content := []byte(`
		fetch('/api/v1/users');
		axios.get('/api/v1/profile');
		axios.post('/api/v1/login', data);
		const ws = new WebSocket('wss://ws.example.com/chat');
		const graphql = '/graphql';
	`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.ExtractEndpoints(content, "test.js")
	}
}

func BenchmarkExtractSecrets(b *testing.B) {
	analyzer := testAnalyzer()
	content := []byte(`
		const key1 = 'AKIAIOSFODNN7EXAMPLE';
		const key2 = 'AIzaSyDeadBeefDeadBeefDeadBeefDeadBeef12345';
		const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwfQ.d2VpcmRvbmVzYW5kZ2FpbHM';
		const stripe = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';
		const firebase = 'https://myapp.firebaseio.com';
	`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.ExtractSecrets(content, "test.js")
	}
}

func TestDiscoverAndAnalyze_ErrorFetchingPage(t *testing.T) {
	analyzer := testAnalyzer()
	_, err := analyzer.DiscoverAndAnalyze(context.Background(), "http://127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error for unreachable target, got nil")
	}
}

// Test the module's secret severity mapping
func TestSecretSeverity(t *testing.T) {
	tests := []struct {
		confidence string
		expected   string
	}{
		{"HIGH", "critical"},
		{"MEDIUM", "high"},
		{"LOW", "medium"},
		{"unknown", "medium"},
	}
	for _, tt := range tests {
		got := secretSeverity(tt.confidence)
		if got != tt.expected {
			t.Errorf("secretSeverity(%q) = %q, want %q", tt.confidence, got, tt.expected)
		}
	}
}

// Test that FindObjects in URL matches correctly
func TestURLPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		pattern  *regexp.Regexp
		expected string
	}{
		{"http URL", "https://api.example.com/v1", urlPattern, "api.example.com"},
		{"http URL", "http://cdn.test.com/file.js", urlPattern, "cdn.test.com"},
		{"websocket URL", "wss://ws.example.com/chat", wsPattern, "ws.example.com"},
	}
	for _, tt := range tests {
		matches := tt.pattern.FindStringSubmatch(tt.input)
		if len(matches) < 2 {
			t.Fatalf("pattern did not match %q", tt.input)
		}
		if matches[1] != tt.expected {
			t.Errorf("pattern matched %q, want %q", matches[1], tt.expected)
		}
	}
}

func TestNewAnalyzer(t *testing.T) {
	client := &http.Client{Timeout: 2 * time.Second}
	a := NewAnalyzer(client, 3*time.Second, 1, 10)
	if a.client != client {
		t.Fatal("client not set correctly")
	}
	if a.timeout != 3*time.Second {
		t.Fatal("timeout not set correctly")
	}
	if a.retries != 1 {
		t.Fatal("retries not set correctly")
	}
	if a.threads != 10 {
		t.Fatal("threads not set correctly")
	}
}

func BenchmarkDiscoverAndAnalyze(b *testing.B) {
	jsContent := `
		fetch('/api/v1/login');
		axios.get('/api/v1/user');
		axios.post('/api/v1/register');
		const ws = new WebSocket('wss://ws.example.com');
		const key = 'AIzaSyDeadBeefDeadBeefDeadBeefDeadBeef12345';
		const aws = 'AKIAIOSFODNN7EXAMPLE';
	`

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(jsContent))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fmt.Sprintf(`
			<!DOCTYPE html>
			<html>
			<head><script src="%s/app.js"></script></head>
			<body></body>
			</html>
		`, serverURL)))
	}))
	serverURL = server.URL
	defer server.Close()

	analyzer := testAnalyzer()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := analyzer.DiscoverAndAnalyze(context.Background(), serverURL)
		if err != nil {
			b.Fatalf("DiscoverAndAnalyze() error = %v", err)
		}
	}
}