package scanner

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NASHEDIxCODER/gospyder/internal/registry"
)

type HTTPProbeModuleAdapter struct{}

func NewHTTPProbeModule() registry.Module {
	return &HTTPProbeModuleAdapter{}
}

func (m *HTTPProbeModuleAdapter) Name() string {
	return "http"
}

func (m *HTTPProbeModuleAdapter) Description() string {
	return "HTTP probing with status, title, headers, length, and response time"
}

func (m *HTTPProbeModuleAdapter) Run(ctx context.Context, opts registry.Options) (*registry.Result, error) {
	target, ok := opts.Flags["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("target flag required")
	}

	targets := probeTargets(target, priorResult(opts, "enum"))
	opts.Logger.Info("Starting HTTP probe for %d target(s)", len(targets))

	findings := probeHTTP(ctx, opts.HTTPClient, targets, opts.Config.Threads)
	return &registry.Result{
		Module:    m.Name(),
		Timestamp: time.Now(),
		Status:    "success",
		Target:    target,
		Findings:  findings,
		Metadata: map[string]interface{}{
			"targets_probed": len(targets),
		},
	}, nil
}

type LiveHostModuleAdapter struct{}

func NewLiveHostModule() registry.Module {
	return &LiveHostModuleAdapter{}
}

func (m *LiveHostModuleAdapter) Name() string {
	return "live"
}

func (m *LiveHostModuleAdapter) Description() string {
	return "Live host detection from HTTP probe results"
}

func (m *LiveHostModuleAdapter) Run(ctx context.Context, opts registry.Options) (*registry.Result, error) {
	target, ok := opts.Flags["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("target flag required")
	}

	httpResult := priorResult(opts, "http")
	if httpResult == nil {
		httpTargets := probeTargets(target, priorResult(opts, "enum"))
		httpFindings := probeHTTP(ctx, opts.HTTPClient, httpTargets, opts.Config.Threads)
		httpResult = &registry.Result{Module: "http", Target: target, Findings: httpFindings}
	}

	seen := map[string]bool{}
	findings := []registry.Finding{}
	for _, finding := range httpResult.Findings {
		host := hostFromFinding(finding)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		findings = append(findings, registry.Finding{
			Type:     "live_host",
			Value:    host,
			Severity: "info",
			Metadata: map[string]interface{}{
				"url":         finding.Metadata["url"],
				"status_code": finding.Metadata["status_code"],
			},
		})
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].Value < findings[j].Value })
	return &registry.Result{
		Module:    m.Name(),
		Timestamp: time.Now(),
		Status:    "success",
		Target:    target,
		Findings:  findings,
		Metadata: map[string]interface{}{
			"source": "http_probe",
		},
	}, nil
}

type TechModuleAdapter struct{}

func NewTechModule() registry.Module {
	return &TechModuleAdapter{}
}

func (m *TechModuleAdapter) Name() string {
	return "tech"
}

func (m *TechModuleAdapter) Description() string {
	return "Technology fingerprinting for common web frameworks and servers"
}

func (m *TechModuleAdapter) Run(ctx context.Context, opts registry.Options) (*registry.Result, error) {
	target, ok := opts.Flags["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("target flag required")
	}

	httpResult := priorResult(opts, "http")
	targets := probeTargets(target, priorResult(opts, "enum"))
	if httpResult != nil && len(httpResult.Findings) > 0 {
		targets = urlsFromHTTPResult(httpResult)
	}

	findings := fingerprintTech(ctx, opts.HTTPClient, targets, opts.Config.Threads)
	return &registry.Result{
		Module:    m.Name(),
		Timestamp: time.Now(),
		Status:    "success",
		Target:    target,
		Findings:  findings,
		Metadata: map[string]interface{}{
			"targets_checked": len(targets),
		},
	}, nil
}

func probeTargets(target string, enumResult *registry.Result) []string {
	seen := map[string]bool{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if seen[value] {
			return
		}
		seen[value] = true
	}

	add(target)
	if enumResult != nil {
		for _, finding := range enumResult.Findings {
			add(finding.Value)
		}
	}

	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func probeHTTP(ctx context.Context, client *http.Client, targets []string, threads int) []registry.Finding {
	if threads <= 0 {
		threads = 10
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	findings := []registry.Finding{}

	for _, target := range targets {
		for _, probeURL := range candidateURLs(target) {
			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()

				finding, ok := doHTTPProbe(ctx, client, url)
				if !ok {
					return
				}
				mu.Lock()
				findings = append(findings, finding)
				mu.Unlock()
			}(probeURL)
		}
	}

	wg.Wait()
	sort.Slice(findings, func(i, j int) bool { return findings[i].Value < findings[j].Value })
	return findings
}

func doHTTPProbe(ctx context.Context, client *http.Client, probeURL string) (registry.Finding, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return registry.Finding{}, false
	}
	req.Header.Set("User-Agent", "GoSpyder/3.0")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return registry.Finding{}, false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	elapsed := time.Since(start)
	contentLength := resp.ContentLength
	if contentLength < 0 {
		contentLength = int64(len(body))
	}
	title := extractTitle(string(body))
	server := resp.Header.Get("Server")

	return registry.Finding{
		Type:        "http_probe",
		Value:       probeURL,
		Description: fmt.Sprintf("%d %s", resp.StatusCode, title),
		Severity:    "info",
		Metadata: map[string]interface{}{
			"url":              probeURL,
			"status_code":      resp.StatusCode,
			"title":            title,
			"server":           server,
			"content_length":   contentLength,
			"response_time_ms": elapsed.Milliseconds(),
		},
	}, true
}

func fingerprintTech(ctx context.Context, client *http.Client, targets []string, threads int) []registry.Finding {
	if threads <= 0 {
		threads = 10
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	findings := []registry.Finding{}
	seen := map[string]bool{}

	for _, target := range targets {
		for _, probeURL := range candidateURLs(target) {
			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()

				detections := detectTechnologies(ctx, client, url)
				mu.Lock()
				for _, detection := range detections {
					key := detection.Value + "|" + url
					if seen[key] {
						continue
					}
					seen[key] = true
					findings = append(findings, detection)
				}
				mu.Unlock()
			}(probeURL)
		}
	}

	wg.Wait()
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Value == findings[j].Value {
			return fmt.Sprint(findings[i].Metadata["url"]) < fmt.Sprint(findings[j].Metadata["url"])
		}
		return findings[i].Value < findings[j].Value
	})
	return findings
}

func detectTechnologies(ctx context.Context, client *http.Client, probeURL string) []registry.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "GoSpyder/3.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	body := strings.ToLower(string(bodyBytes))
	headers := strings.ToLower(flattenHeaders(resp.Header))
	all := body + "\n" + headers

	detections := []struct {
		name     string
		patterns []string
	}{
		{"React", []string{"reactroot", "react-dom", "__react", "_reactrootcontainer"}},
		{"Angular", []string{"ng-version", "angular", "ng-app"}},
		{"Vue", []string{"vue.js", "__vue__", "data-v-"}},
		{"WordPress", []string{"wp-content", "wp-includes", "wordpress"}},
		{"Django", []string{"csrftoken", "django"}},
		{"Flask", []string{"werkzeug", "flask"}},
		{"FastAPI", []string{"fastapi", "uvicorn"}},
		{"Nginx", []string{"server: nginx", "nginx"}},
		{"Apache", []string{"server: apache", "apache"}},
		{"Cloudflare", []string{"cf-ray", "cf-cache-status", "server: cloudflare", "cloudflare"}},
	}

	findings := []registry.Finding{}
	for _, detection := range detections {
		evidence := []string{}
		for _, pattern := range detection.patterns {
			if strings.Contains(all, pattern) {
				evidence = append(evidence, pattern)
			}
		}
		if len(evidence) == 0 {
			continue
		}
		findings = append(findings, registry.Finding{
			Type:     "technology",
			Value:    detection.name,
			Severity: "info",
			Evidence: evidence,
			Metadata: map[string]interface{}{
				"url":         probeURL,
				"status_code": resp.StatusCode,
			},
		})
	}
	return findings
}

func candidateURLs(target string) []string {
	target = strings.TrimSpace(target)
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return []string{strings.TrimRight(target, "/")}
	}
	return []string{"https://" + target, "http://" + target}
}

func extractTitle(body string) string {
	re := regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)
	matches := re.FindStringSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	title := html.UnescapeString(matches[1])
	title = regexp.MustCompile(`\s+`).ReplaceAllString(title, " ")
	return strings.TrimSpace(title)
}

func flattenHeaders(headers http.Header) string {
	var b strings.Builder
	for key, values := range headers {
		fmt.Fprintf(&b, "%s: %s\n", key, strings.Join(values, ","))
	}
	return b.String()
}

func priorResult(opts registry.Options, module string) *registry.Result {
	results, _ := opts.Flags["results"].(map[string]*registry.Result)
	if results == nil {
		return nil
	}
	return results[module]
}

func urlsFromHTTPResult(result *registry.Result) []string {
	seen := map[string]bool{}
	urls := []string{}
	for _, finding := range result.Findings {
		urlValue, _ := finding.Metadata["url"].(string)
		if urlValue == "" || seen[urlValue] {
			continue
		}
		seen[urlValue] = true
		urls = append(urls, urlValue)
	}
	sort.Strings(urls)
	return urls
}

func hostFromFinding(finding registry.Finding) string {
	urlValue, _ := finding.Metadata["url"].(string)
	urlValue = strings.TrimPrefix(urlValue, "https://")
	urlValue = strings.TrimPrefix(urlValue, "http://")
	if idx := strings.Index(urlValue, "/"); idx >= 0 {
		urlValue = urlValue[:idx]
	}
	return urlValue
}
