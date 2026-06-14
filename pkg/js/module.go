package js

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NASHEDIxCODER/gospyder/internal/registry"
)

// JSModuleAdapter wraps JS analysis as a Module.
type JSModuleAdapter struct{}

// NewJSModule creates a new JS analysis module.
func NewJSModule() registry.Module {
	return &JSModuleAdapter{}
}

func (m *JSModuleAdapter) Name() string {
	return "js"
}

func (m *JSModuleAdapter) Description() string {
	return "JavaScript file discovery, endpoint extraction, domain enumeration, and secret detection"
}

func (m *JSModuleAdapter) Run(ctx context.Context, opts registry.Options) (*registry.Result, error) {
	target, ok := opts.Flags["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("target flag required")
	}

	timeout := time.Duration(opts.Config.Timeout) * time.Second
	if opts.Config.Timeout <= 0 {
		timeout = 10 * time.Second
	}

	threads := opts.Config.Threads
	if threads <= 0 {
		threads = 20
	}

	retries := opts.Config.Retries
	if retries <= 0 {
		retries = 1
	}

	analyzer := NewAnalyzer(opts.HTTPClient, timeout, retries, threads)
	opts.Logger.Debug("Starting JS analysis for %s (threads=%d, timeout=%v)", target, threads, timeout)

	start := time.Now()
	jsResult, err := analyzer.DiscoverAndAnalyze(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("JS analysis failed: %w", err)
	}
	duration := time.Since(start)

	// Build findings
	findings := make([]registry.Finding, 0)

	// JS Files
	for _, f := range jsResult.Files {
		status := "downloaded"
		if !f.Analyzed {
			status = "skipped"
		}
		findings = append(findings, registry.Finding{
			Type:     "js_file",
			Value:    f.URL,
			Severity: "info",
			Metadata: map[string]interface{}{
				"size":   f.Size,
				"status": status,
			},
		})
	}

	// Endpoints
	for _, e := range jsResult.Endpoints {
		findings = append(findings, registry.Finding{
			Type:     "js_endpoint",
			Value:    e.Path,
			Severity: "info",
			Metadata: map[string]interface{}{
				"source":  e.Source,
				"method":  e.Method,
				"context": e.Context,
			},
		})
	}

	// Domains
	for _, d := range jsResult.Domains {
		findings = append(findings, registry.Finding{
			Type:     "js_domain",
			Value:    d.Domain,
			Severity: "info",
			Metadata: map[string]interface{}{
				"source": d.Source,
				"type":   d.Type,
			},
		})
	}

	// Secrets
	for _, s := range jsResult.Secrets {
		findings = append(findings, registry.Finding{
			Type:        "js_secret",
			Value:       s.Type,
			Description: "Confidence: " + s.Confidence,
			Severity:    secretSeverity(s.Confidence),
			Evidence:    []string{s.Preview},
			Metadata: map[string]interface{}{
				"location":   s.Location,
				"confidence": s.Confidence,
				"preview":    s.Preview,
			},
		})
	}

	// Build categorized endpoint report
	endpointByCategory := make(map[string][]string)
	for cat, eps := range jsResult.EndpointGroups {
		for _, ep := range eps {
			label := ep.Path
			if ep.Method != "" && ep.Method != "GET" {
				label = ep.Path + " [" + ep.Method + "]"
			}
			endpointByCategory[string(cat)] = append(endpointByCategory[string(cat)], label)
		}
	}

	// Metadata for reporting
	jsURLs := make([]string, len(jsResult.Files))
	for i, f := range jsResult.Files {
		jsURLs[i] = f.URL
	}

	endpointPaths := make([]string, len(jsResult.Endpoints))
	for i, e := range jsResult.Endpoints {
		endpointPaths[i] = e.Path
	}

	domainNames := make([]string, len(jsResult.Domains))
	for i, d := range jsResult.Domains {
		domainNames[i] = d.Domain
	}

	// Create structured JSON for reporting
	analysisData, _ := json.Marshal(map[string]interface{}{
		"files":            jsResult.Files,
		"endpoints":        jsResult.Endpoints,
		"domains":          jsResult.Domains,
		"secrets":          jsResult.Secrets,
		"endpoint_groups":  jsResult.EndpointGroups,
		"stats":            jsResult.Stats,
	})

	metadata := map[string]interface{}{
		"js_files_count":       jsResult.Stats.JSFiles,
		"endpoints_count":      jsResult.Stats.Endpoints,
		"domains_count":        jsResult.Stats.Domains,
		"secrets_count":        jsResult.Stats.Secrets,
		"duration":             duration.Seconds(),
		"js_files":             jsURLs,
		"endpoints":            endpointPaths,
		"external_domains":     domainNames,
		"endpoint_categories":  endpointByCategory,
		"_analysis_json":       string(analysisData),
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

func secretSeverity(confidence string) string {
	switch confidence {
	case "HIGH":
		return "critical"
	case "MEDIUM":
		return "high"
	default:
		return "medium"
	}
}