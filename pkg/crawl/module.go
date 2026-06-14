package crawl

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/NASHEDIxCODER/gospyder/internal/registry"
)

// ModuleAdapter wraps the crawler as a registry.Module.
type ModuleAdapter struct{}

// NewCrawlModule creates a new crawl module.
func NewCrawlModule() registry.Module {
	return &ModuleAdapter{}
}

func (m *ModuleAdapter) Name() string {
	return "crawl"
}

func (m *ModuleAdapter) Description() string {
	return "Web crawling for URL discovery, parameter extraction, API detection, and JS file collection"
}

func (m *ModuleAdapter) Run(ctx context.Context, opts registry.Options) (*registry.Result, error) {
	target, ok := opts.Flags["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("target flag required (usage: gospyder crawl <url>)")
	}

	timeout := time.Duration(opts.Config.Timeout) * time.Second
	if opts.Config.Timeout <= 0 {
		timeout = 10 * time.Second
	}

	threads := opts.Config.Threads
	if threads <= 0 {
		threads = 20
	}

	// Use Crawler config from global settings
	maxDepth := opts.Config.Crawler.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 3
	}

	concurrency := opts.Config.Crawler.Concurrency
	if concurrency <= 0 {
		concurrency = threads
	}

	retries := opts.Config.Retries
	if retries <= 0 {
		retries = 1
	}

	opts.Logger.Info("Starting crawl for %s (depth=%d, threads=%d, timeout=%v)", target, maxDepth, concurrency, timeout)

	// Create a context with timeout
	crawlCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	result, err := Crawl(crawlCtx, opts.HTTPClient, target, maxDepth, concurrency, retries)
	if err != nil {
		return nil, fmt.Errorf("crawl failed: %w", err)
	}
	duration := time.Since(start)

	opts.Logger.Info("Crawl completed in %.2fs - URLs: %d, Params: %d, APIs: %d, JS Files: %d",
		duration.Seconds(), result.Stats.TotalURLs, result.Stats.TotalParams, result.Stats.TotalAPIs, result.Stats.TotalJSFiles)

	// Build findings
	findings := make([]registry.Finding, 0)

	// URLs
	for _, u := range result.URLs {
		findings = append(findings, registry.Finding{
			Type:     "url",
			Value:    u,
			Severity: "info",
		})
	}

	// Parameters
	for _, p := range result.Params {
		findings = append(findings, registry.Finding{
			Type:     "parameter",
			Value:    p,
			Severity: "info",
		})
	}

	// APIs
	for _, a := range result.APIs {
		findings = append(findings, registry.Finding{
			Type:     "api",
			Value:    a,
			Severity: "info",
		})
	}

	// JS Files
	for _, j := range result.JSFiles {
		findings = append(findings, registry.Finding{
			Type:     "js_file",
			Value:    j,
			Severity: "info",
		})
	}

	// Sort findings by type then value for consistent output
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Type != findings[j].Type {
			return findings[i].Type < findings[j].Type
		}
		return findings[i].Value < findings[j].Value
	})

	metadata := map[string]interface{}{
		"urls_count":       result.Stats.TotalURLs,
		"params_count":     result.Stats.TotalParams,
		"apis_count":       result.Stats.TotalAPIs,
		"js_files_count":   result.Stats.TotalJSFiles,
		"pages_crawled":    result.Stats.PagesCrawled,
		"errors":           result.Stats.Errors,
		"max_depth":        maxDepth,
		"concurrency":      concurrency,
		"duration":         duration.Seconds(),
	}

	return &registry.Result{
		Module:    m.Name(),
		Timestamp: time.Now(),
		Status:    "success",
		Target:    target,
		Findings:  findings,
		Metadata:  metadata,
	}, nil
}