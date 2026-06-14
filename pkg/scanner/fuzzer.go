package scanner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/NASHEDIxCODER/gospyder/internal/logger"
	"github.com/google/uuid"
)

// BaselineResponse stores the baseline response for wildcard detection.
type BaselineResponse struct {
	StatusCode    int
	ContentLength int64
	Title         string
	Fingerprint   string
}

// FuzzResult stores a single fuzzed path result.
type FuzzResult struct {
	URL           string
	Path          string
	StatusCode    int
	ContentLength int64
	Title         string
	Fingerprint   string
	RedirectURL   string
}

// FuzzerConfig holds configuration for the fuzzer.
type FuzzerConfig struct {
	Logger            *logger.Logger
	TolerancePercent  float64 // content length tolerance percentage (0.0-1.0)
	MinToleranceBytes int64   // minimum absolute tolerance in bytes
	Debug             bool
	DetectSoft404     bool
	DetectCatchAll    bool
	DetectSPA         bool
}

// DefaultFuzzerConfig returns a sensible default configuration.
func DefaultFuzzerConfig() FuzzerConfig {
	return FuzzerConfig{
		TolerancePercent:  0.05,  // 5% content length tolerance
		MinToleranceBytes: 50,    // minimum 50 bytes absolute difference
		Debug:             false,
		DetectSoft404:     true,
		DetectCatchAll:    true,
		DetectSPA:         true,
	}
}

// Fuzzer performs directory fuzzing with wildcard detection and response fingerprinting.
type Fuzzer struct {
	config  FuzzerConfig
	client  *http.Client
	baseURL string

	// Track fingerprints to suppress duplicates
	fingerprints map[string]int // fingerprint -> count
	fpMu         sync.Mutex

	// Wildcard baseline
	baseline *BaselineResponse
}

// NewFuzzer creates a new Fuzzer with the given configuration.
func NewFuzzer(config FuzzerConfig) *Fuzzer {
	transport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		MaxIdleConnsPerHost:   100,
		DisableKeepAlives:     false,
		DisableCompression:    true,
	}

	return &Fuzzer{
		config:       config,
		fingerprints: make(map[string]int),
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// generateRandomPath creates a unique random path unlikely to exist on any server.
func generateRandomPath() string {
	id := uuid.New().String()
	return fmt.Sprintf("/gospyder-random-%s", id)
}

// fetchResponse fetches a URL and returns structured response data.
func (f *Fuzzer) fetchResponse(ctx context.Context, url string) (*FuzzResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "GoSpyder/3.0")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the full body to get content length and extract title
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	contentLength := int64(len(body))
	title := extractTitle(string(body))

	// Determine redirect URL if applicable
	redirectURL := ""
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			redirectURL = loc
		}
	}

	result := &FuzzResult{
		URL:           url,
		StatusCode:    resp.StatusCode,
		ContentLength: contentLength,
		Title:         title,
		RedirectURL:   redirectURL,
	}
	result.Fingerprint = fingerprint(result.StatusCode, result.Title, result.ContentLength)

	return result, nil
}

// fingerprint creates a hash from status code + title + content length rounded to nearest 100.
func fingerprint(statusCode int, title string, contentLength int64) string {
	// Round content length to nearest 100 to allow small variations
	roundedLength := (contentLength / 100) * 100
	data := fmt.Sprintf("%d|%s|%d", statusCode, title, roundedLength)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:16]) // Use first 16 bytes for compact fingerprint
}

// contentLengthSimilar checks if two content lengths are similar within tolerance.
func (f *Fuzzer) contentLengthSimilar(baselineLen, currentLen int64) bool {
	if baselineLen == currentLen {
		return true
	}

	// Absolute difference check
	diff := int64(math.Abs(float64(baselineLen - currentLen)))
	if diff <= f.config.MinToleranceBytes {
		return true
	}

	// Percentage difference check (relative to baseline)
	if baselineLen > 0 {
		percentDiff := float64(diff) / float64(baselineLen)
		if percentDiff <= f.config.TolerancePercent {
			return true
		}
	}

	return false
}

// isWildcardResponse checks if the response matches the wildcard baseline.
func (f *Fuzzer) isWildcardResponse(result *FuzzResult) bool {
	if f.baseline == nil {
		return false
	}

	// Same status code
	if result.StatusCode != f.baseline.StatusCode {
		return false
	}

	// Similar content length
	if !f.contentLengthSimilar(f.baseline.ContentLength, result.ContentLength) {
		return false
	}

	// Same title
	if result.Title != f.baseline.Title {
		return false
	}

	return true
}

// isDuplicate checks if we've already seen this fingerprint.
// maxDuplicates controls how many duplicates to allow before suppressing.
// maxDuplicates=0 means suppress all duplicates after the first occurrence.
func (f *Fuzzer) isDuplicate(fp string, maxDuplicates int) bool {
	f.fpMu.Lock()
	defer f.fpMu.Unlock()

	count := f.fingerprints[fp]
	f.fingerprints[fp] = count + 1

	// count is the number of times seen before this call.
	// count=0 means first occurrence - should not be suppressed.
	// count >= 1 means duplicate - suppress if count > maxDuplicates.
	return count > maxDuplicates
}

// isValidFinding checks if a response represents a meaningful finding.
func (f *Fuzzer) isValidFinding(result *FuzzResult) bool {
	// Authentication pages are always interesting
	if result.StatusCode == 401 || result.StatusCode == 403 {
		return true
	}

	// Meaningful redirects
	if result.StatusCode >= 300 && result.StatusCode < 400 {
		redirectURL := result.RedirectURL
		if redirectURL != "" && !isTrivialRedirect(redirectURL, f.baseURL) {
			return true
		}
		return false
	}

	// 2xx responses that passed baseline check are valid
	if result.StatusCode >= 200 && result.StatusCode < 300 {
		return true
	}

	// 405 Method Not Allowed is interesting
	if result.StatusCode == 405 {
		return true
	}

	return false
}

// isTrivialRedirect checks if a redirect goes to a trivial location (like root or same host).
func isTrivialRedirect(redirectURL, baseURL string) bool {
	if redirectURL == "/" || redirectURL == "" {
		return true
	}
	if strings.EqualFold(redirectURL, baseURL) ||
		strings.EqualFold(redirectURL, baseURL+"/") {
		return true
	}
	return false
}

// establishBaseline requests a random path and establishes the wildcard baseline.
func (f *Fuzzer) establishBaseline(ctx context.Context, baseURL string) error {
	randomPath := generateRandomPath()
	randomURL := fmt.Sprintf("%s%s", strings.TrimRight(baseURL, "/"), randomPath)

	f.config.Logger.Debug("Establishing baseline with random path: %s", randomURL)

	result, err := f.fetchResponse(ctx, randomURL)
	if err != nil {
		return fmt.Errorf("failed to establish baseline: %w", err)
	}

	f.baseline = &BaselineResponse{
		StatusCode:    result.StatusCode,
		ContentLength: result.ContentLength,
		Title:         result.Title,
		Fingerprint:   result.Fingerprint,
	}

	if f.config.Debug {
		f.config.Logger.Info("=== Baseline ===")
		f.config.Logger.Info("Status: %d", f.baseline.StatusCode)
		f.config.Logger.Info("Length: %d", f.baseline.ContentLength)
		f.config.Logger.Info("Title: %s", f.baseline.Title)
		f.config.Logger.Info("Fingerprint: %s", f.baseline.Fingerprint)
		f.config.Logger.Info("")
	}

	return nil
}

// Scan performs directory fuzzing with wildcard detection and response fingerprinting.
func (f *Fuzzer) Scan(ctx context.Context, baseURL, wordlist string, threads int) []string {
	var found []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	f.baseURL = baseURL

	// Reset state
	f.fingerprints = make(map[string]int)
	f.baseline = nil

	// Establish baseline first
	if err := f.establishBaseline(ctx, baseURL); err != nil {
		f.config.Logger.Debug("Failed to establish baseline: %v", err)
		// Continue without baseline filtering
	}

	file, err := os.Open(wordlist)
	if err != nil {
		return found
	}
	defer file.Close()

	sem := make(chan struct{}, threads)
	scanner := bufio.NewScanner(file)

	// Track stats
	keptCount := 0
	discardedCount := 0
	var statsMu sync.Mutex

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			if f.config.Debug {
				f.config.Logger.Info("=== Fuzzing Summary ===")
				f.config.Logger.Info("Findings Kept: %d", keptCount)
				f.config.Logger.Info("Findings Discarded: %d", discardedCount)
			}
			return found
		default:
		}

		path := strings.TrimSpace(scanner.Text())
		if path == "" || strings.HasPrefix(path, "#") {
			continue
		}

		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			url := fmt.Sprintf("%s/%s", strings.TrimRight(baseURL, "/"), p)

			result, err := f.fetchResponse(ctx, url)
			if err != nil {
				return
			}

			// Wildcard response detection
			if f.baseline != nil && f.isWildcardResponse(result) {
				statsMu.Lock()
				discardedCount++
				statsMu.Unlock()

				if f.config.Debug {
					f.config.Logger.Debug("DISCARDED (wildcard): %s [%d] len=%d title=%q",
						url, result.StatusCode, result.ContentLength, result.Title)
				}
				return
			}

			// Duplicate suppression via fingerprinting
			if f.isDuplicate(result.Fingerprint, 0) {
				statsMu.Lock()
				discardedCount++
				statsMu.Unlock()

				if f.config.Debug {
					f.config.Logger.Debug("DISCARDED (duplicate): %s [%d] fp=%s",
						url, result.StatusCode, result.Fingerprint)
				}
				return
			}

			// Check if this is a valid finding
			if !f.isValidFinding(result) {
				statsMu.Lock()
				discardedCount++
				statsMu.Unlock()
				return
			}

			// Valid finding
			statsMu.Lock()
			keptCount++
			statsMu.Unlock()

			mu.Lock()
			found = append(found,
				fmt.Sprintf("%s [%d]", url, result.StatusCode))
			mu.Unlock()

			if f.config.Debug {
				f.config.Logger.Debug("KEPT: %s [%d] len=%d title=%q fp=%s",
					url, result.StatusCode, result.ContentLength, result.Title, result.Fingerprint)
			}
		}(path)
	}

	wg.Wait()

	if f.config.Debug {
		f.config.Logger.Info("=== Fuzzing Summary ===")
		f.config.Logger.Info("Findings Kept: %d", keptCount)
		f.config.Logger.Info("Findings Discarded: %d", discardedCount)
	}

	return found
}