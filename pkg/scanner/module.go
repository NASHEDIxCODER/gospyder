package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/NASHEDIxCODER/gospyder/internal/registry"
)

// PortScanModuleAdapter wraps enhanced port scanning as a Module.
// Performs banner grabbing and service detection for every open port.
type PortScanModuleAdapter struct{}

// NewPortScanModule creates a new port scanning module with service detection.
func NewPortScanModule() registry.Module {
	return &PortScanModuleAdapter{}
}

func (m *PortScanModuleAdapter) Name() string {
	return "ports"
}

func (m *PortScanModuleAdapter) Description() string {
	return "TCP port scanning with banner grabbing and service/version detection"
}

func (m *PortScanModuleAdapter) Run(ctx context.Context, opts registry.Options) (*registry.Result, error) {
	target, ok := opts.Flags["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("target flag required")
	}

	ports, err := portsFromOptions(opts)
	if err != nil {
		return nil, err
	}

	retries, _ := opts.Flags["retry"].(int)
	if retries <= 0 {
		retries = opts.Config.Retries
	}

	scanHost := tcpScanHost(target)
	opts.Logger.Debug("Starting enhanced port scan for %s (%d ports)", scanHost, len(ports))

	scanner := &PortScanner{}
	// Use ScanWithBanners for banner grabbing + service detection in one pass
	portResults := scanner.ScanWithBanners(ctx, scanHost, ports, opts.Config.Threads, retries, opts.Config.Scanner.PortTimeout, opts.Config.Verbose)

	// For HTTP ports, perform HTTP probing to get better service/version info
	httpResults := make(map[int]string)
	for _, port := range sortedPortResults(portResults) {
		if HTTPPorts[port] {
			if pr := portResults[port]; pr != nil {
				// If we already have a banner from HTTP/HTTPS services, use it
				if pr.Service == "HTTP" || pr.Service == "HTTPS" || pr.Service == "HTTP-alt" || pr.Service == "HTTPS-alt" {
					continue // banner already captured
				}
			}
			// Probe HTTP to detect web server
			serverHeader := ProbeHTTPPort(ctx, scanHost, port, opts.Config.Scanner.PortTimeout)
			if serverHeader != "" {
				httpResults[port] = serverHeader
			}
		}
	}

	// Build findings with enhanced data
	findings := make([]registry.Finding, 0, len(portResults))
	for _, port := range sortedPortResults(portResults) {
		pr := portResults[port]
		if pr == nil {
			continue
		}

		service := pr.Service
		version := pr.Version
		banner := pr.Banner

		// Override with HTTP probe results if available (more accurate for web services)
		if httpServer, ok := httpResults[port]; ok && httpServer != "" {
			// Parse version from Server header if present
			httpService, httpVersion := DetectService(port, httpServer)
			if httpService != "" {
				service = httpService
			}
			if httpVersion != "" {
				version = httpVersion
			} else {
				// Try to extract version from Server header directly
				version = extractVersionFromServerHeader(httpServer)
			}
			// Use the Server header as banner if we didn't get one
			if banner == "" {
				banner = "HTTP/" + httpServer
			} else {
				banner = banner + " | HTTP/" + httpServer
			}
		}

		displayValue := fmt.Sprintf("%d/tcp", port)
		description := service
		if version != "" {
			description = service + " " + version
		}

		findings = append(findings, registry.Finding{
			Type:        "open_port",
			Value:       displayValue,
			Description: description,
			Severity:    "info",
			Evidence:    []string{banner},
			Metadata: map[string]interface{}{
				"port":    port,
				"service": service,
				"version": version,
				"banner":  banner,
			},
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		pi, _ := findings[i].Metadata["port"].(int)
		pj, _ := findings[j].Metadata["port"].(int)
		return pi < pj
	})

	metadata := map[string]interface{}{
		"ports_scanned": len(ports),
		"retries":       retries,
		"scan_host":     scanHost,
		"ports_open":    len(findings),
	}
	if len(httpResults) > 0 {
		metadata["http_probed"] = len(httpResults)
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

// sortedPortResults returns a sorted slice of port numbers from the results map.
func sortedPortResults(results map[int]*PortResult) []int {
	ports := make([]int, 0, len(results))
	for port := range results {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

// extractVersionFromServerHeader parses version info from HTTP Server headers.
func extractVersionFromServerHeader(server string) string {
	// Common patterns: "nginx/1.26.0", "Apache/2.4.58", "cloudflare", "Microsoft-IIS/10.0"
	if idx := strings.Index(server, "/"); idx >= 0 && idx+1 < len(server) {
		version := server[idx+1:]
		// Validate it looks like a version
		if len(version) > 0 && (version[0] >= '0' && version[0] <= '9') {
			return version
		}
	}
	return ""
}

// FuzzerModuleAdapter wraps directory fuzzing as a Module.
type FuzzerModuleAdapter struct{}

// NewFuzzerModule creates a new directory fuzzing module.
func NewFuzzerModule() registry.Module {
	return &FuzzerModuleAdapter{}
}

func (m *FuzzerModuleAdapter) Name() string {
	return "fuzz"
}

func (m *FuzzerModuleAdapter) Description() string {
	return "HTTP directory and path fuzzing with wildcard detection and response fingerprinting"
}

func (m *FuzzerModuleAdapter) Run(ctx context.Context, opts registry.Options) (*registry.Result, error) {
	target, ok := opts.Flags["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("target flag required")
	}

	wordlist, _ := opts.Flags["wordlist"].(string)
	if override, _ := opts.Flags["fuzz-wordlist"].(string); override != "" {
		wordlist = override
	}
	if wordlist == "" {
		wordlist = opts.Config.Scanner.PathWordlist
	}

	baseURL := normalizeURL(target)
	opts.Logger.Debug("Starting directory fuzz for %s", baseURL)

	// Configure fuzzer with wildcard detection
	debugMode, _ := opts.Flags["debug"].(bool)
	if !debugMode {
		debugMode = opts.Config.Verbose
	}

	fuzzerConfig := DefaultFuzzerConfig()
	fuzzerConfig.Logger = opts.Logger
	fuzzerConfig.Debug = debugMode

	fuzzer := NewFuzzer(fuzzerConfig)
	found := fuzzer.Scan(ctx, baseURL, wordlist, opts.Config.Threads)

	opts.Logger.Debug("Fuzzing complete for %s: %d findings", baseURL, len(found))

	findings := make([]registry.Finding, 0, len(found))
	for _, item := range found {
		path, status := parseFuzzFinding(baseURL, item)
		findings = append(findings, registry.Finding{
			Type:     "interesting_path",
			Value:    item,
			Severity: "info",
			Metadata: map[string]interface{}{
				"path":   path,
				"status": status,
			},
		})
	}

	return &registry.Result{
		Module:    m.Name(),
		Timestamp: time.Now(),
		Status:    "success",
		Target:    baseURL,
		Findings:  findings,
		Metadata: map[string]interface{}{
			"wordlist":        wordlist,
			"wildcard_filter": true,
		},
	}, nil
}

var knownWAFs = map[string]bool{
	"cloudflare": true,
	"akamai":     true,
	"imperva":    true,
	"aws waf":    true,
	"fastly":     true,
	"sucuri":     true,
}

// WAFModuleAdapter wraps WAF detection as a Module.
type WAFModuleAdapter struct{}

// NewWAFModule creates a new WAF detection module.
func NewWAFModule() registry.Module {
	return &WAFModuleAdapter{}
}

func (m *WAFModuleAdapter) Name() string {
	return "waf"
}

func (m *WAFModuleAdapter) Description() string {
	return "WAF provider fingerprinting and detection"
}

func (m *WAFModuleAdapter) Run(ctx context.Context, opts registry.Options) (*registry.Result, error) {
	target, ok := opts.Flags["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("target flag required")
	}

	opts.Logger.Debug("Starting WAF detection for %s", target)
	scanner := &WAFScanner{}
	detection := scanner.DetectDetailed(ctx, target)

	// isWAF helper checks if a technology name is a known WAF.
	isWAF := func(tech string) bool {
		_, ok := knownWAFs[strings.ToLower(tech)]
		return ok
	}

	// Detect WAF from prior results (HTTP headers, tech detection) when
	// active probing didn't trigger a WAF response.
	if detection.Name == "" {
		priorResults, ok := opts.Flags["results"].(map[string]*registry.Result)
		if !ok {
			priorResults = map[string]*registry.Result{}
		}

		// First pass: check technology detection results.
		if techResult, ok := priorResults["tech"]; ok {
			for _, finding := range techResult.Findings {
				if isWAF(finding.Value) {
					detection.Name = finding.Value
					detection.Confidence = "High"
					detection.Evidence = append(detection.Evidence, "Detected via technology fingerprinting")
					// Include any evidence from the tech finding
					detection.Evidence = append(detection.Evidence, finding.Evidence...)
					break
				}
			}
		}

		// Second pass: check HTTP probe results for WAF indicators.
		if detection.Name == "" {
			if httpResult, ok := priorResults["http"]; ok {
				// Collect WAF-relevant evidence from HTTP findings.
				for _, finding := range httpResult.Findings {
					url, _ := finding.Metadata["url"].(string)
					server, _ := finding.Metadata["server"].(string)
					serverLower := strings.ToLower(server)

					// We need to check the actual HTTP response headers stored
					// in the http probe data. Reuse the scanned URL to check.
					if url == "" {
						continue
					}

					// Check for Cloudflare indicators.
					wafDetected, evidence := checkWAFFromURL(ctx, url)
					if wafDetected != nil {
						detection = *wafDetected
						detection.Evidence = append(detection.Evidence, evidence...)
						break
					}

					// Fallback: check Server header directly from metadata.
					if serverLower == "cloudflare" {
						detection.Name = "Cloudflare"
						detection.Confidence = "High"
						detection.Evidence = append(detection.Evidence, "Server: cloudflare")
						break
					}
					if strings.Contains(serverLower, "akamaighost") || strings.Contains(serverLower, "akamai") {
						detection.Name = "Akamai"
						detection.Confidence = "High"
						detection.Evidence = append(detection.Evidence, "Server: "+server)
						break
					}
				}
			}
		}
	}

	findings := []registry.Finding{}
	if detection.Name != "" {
		findings = append(findings, registry.Finding{
			Type:     "waf",
			Value:    detection.Name,
			Severity: "info",
			Evidence: detection.Evidence,
			Metadata: map[string]interface{}{
				"confidence": detection.Confidence,
			},
		})
	}

	return &registry.Result{
		Module:    m.Name(),
		Timestamp: time.Now(),
		Status:    "success",
		Target:    target,
		Findings:  findings,
	}, nil
}

// checkWAFFromURL performs a lightweight HTTP HEAD/GET to check for WAF indicators
// from a known URL. Returns the WAFDetection if found, along with evidence.
func checkWAFFromURL(ctx context.Context, urlStr string) (*WAFDetection, []string) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("User-Agent", "GoSpyder/3.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	headers := resp.Header
	var evidence []string
	server := strings.ToLower(headers.Get("Server"))
	setCookies := headers["Set-Cookie"]

	// Cloudflare detection
	cloudflareEvidence := []string{}
	if strings.Contains(server, "cloudflare") {
		cloudflareEvidence = append(cloudflareEvidence, "Server: cloudflare")
	}
	if headers.Get("CF-RAY") != "" {
		cloudflareEvidence = append(cloudflareEvidence, "CF-RAY header present")
	}
	if headers.Get("CF-Cache-Status") != "" {
		cloudflareEvidence = append(cloudflareEvidence, "CF-Cache-Status header present")
	}
	if headers.Get("CF-Request-ID") != "" {
		cloudflareEvidence = append(cloudflareEvidence, "CF-Request-ID header present")
	}
	for _, c := range setCookies {
		lc := strings.ToLower(c)
		if strings.Contains(lc, "__cf_bm") || strings.Contains(lc, "cf_clearance") {
			cloudflareEvidence = append(cloudflareEvidence, "Cloudflare cookie present")
			break
		}
	}
	if len(cloudflareEvidence) >= 2 {
		return &WAFDetection{
			Name:       "Cloudflare",
			Confidence: "High",
			Evidence:   cloudflareEvidence,
		}, cloudflareEvidence
	}
	if len(cloudflareEvidence) == 1 {
		return &WAFDetection{
			Name:       "Cloudflare",
			Confidence: "Medium",
			Evidence:   cloudflareEvidence,
		}, cloudflareEvidence
	}

	// Akamai detection
	if strings.Contains(server, "akamaighost") || strings.Contains(server, "akamai") {
		evidence = append(evidence, "Server: "+headers.Get("Server"))
	}
	if headers.Get("X-Akamai") != "" || headers.Get("X-Akamai-Transformed") != "" {
		evidence = append(evidence, "Akamai headers present")
	}
	for _, c := range setCookies {
		lc := strings.ToLower(c)
		if strings.Contains(lc, "ak_bmsc") || strings.Contains(lc, "_abck") {
			evidence = append(evidence, "Akamai cookie present")
			break
		}
	}
	if len(evidence) >= 1 {
		return &WAFDetection{
			Name:       "Akamai",
			Confidence: "High",
			Evidence:   evidence,
		}, evidence
	}

	// Imperva detection
	impervaEvidence := []string{}
	if headers.Get("X-Iinfo") != "" {
		impervaEvidence = append(impervaEvidence, "X-Iinfo header present")
	}
	if strings.Contains(strings.ToLower(headers.Get("X-CDN")), "incapsula") {
		impervaEvidence = append(impervaEvidence, "X-CDN: Incapsula")
	}
	for _, c := range setCookies {
		lc := strings.ToLower(c)
		if strings.Contains(lc, "incap_ses") || strings.Contains(lc, "visid_incap") {
			impervaEvidence = append(impervaEvidence, "Imperva cookie present")
			break
		}
	}
	if len(impervaEvidence) >= 1 {
		return &WAFDetection{
			Name:       "Incapsula (Imperva)",
			Confidence: "High",
			Evidence:   impervaEvidence,
		}, impervaEvidence
	}

	// AWS WAF detection
	awsEvidence := []string{}
	if headers.Get("X-Amzn-RequestId") != "" {
		awsEvidence = append(awsEvidence, "X-Amzn-RequestId header present")
	}
	if headers.Get("X-Amzn-Trace-Id") != "" {
		awsEvidence = append(awsEvidence, "X-Amzn-Trace-Id header present")
	}
	if strings.Contains(server, "awselb") || strings.Contains(server, "amazon") {
		awsEvidence = append(awsEvidence, "Server: "+headers.Get("Server"))
	}
	for _, c := range setCookies {
		lc := strings.ToLower(c)
		if strings.Contains(lc, "aws-waf-token") {
			awsEvidence = append(awsEvidence, "AWS WAF cookie present")
			break
		}
	}
	if len(awsEvidence) >= 1 {
		return &WAFDetection{
			Name:       "AWS WAF",
			Confidence: "High",
			Evidence:   awsEvidence,
		}, awsEvidence
	}

	// Fastly detection
	fastlyEvidence := []string{}
	if headers.Get("X-Served-By") != "" && strings.Contains(strings.ToLower(headers.Get("X-Served-By")), "cache") {
		fastlyEvidence = append(fastlyEvidence, "X-Served-By header present")
	}
	if headers.Get("X-Cache") != "" && strings.Contains(strings.ToLower(headers.Get("X-Cache")), "cache") {
		fastlyEvidence = append(fastlyEvidence, "X-Cache header present")
	}
	if strings.Contains(server, "fastly") {
		fastlyEvidence = append(fastlyEvidence, "Server: fastly")
	}
	if len(fastlyEvidence) >= 1 {
		return &WAFDetection{
			Name:       "Fastly",
			Confidence: "High",
			Evidence:   fastlyEvidence,
		}, fastlyEvidence
	}

	// Sucuri detection
	sucuriEvidence := []string{}
	if headers.Get("X-Sucuri-ID") != "" {
		sucuriEvidence = append(sucuriEvidence, "X-Sucuri-ID header present")
	}
	if strings.Contains(server, "sucuri") {
		sucuriEvidence = append(sucuriEvidence, "Server: sucuri")
	}
	for _, c := range setCookies {
		lc := strings.ToLower(c)
		if strings.Contains(lc, "sucuricp") {
			sucuriEvidence = append(sucuriEvidence, "Sucuri cookie present")
			break
		}
	}
	if len(sucuriEvidence) >= 1 {
		return &WAFDetection{
			Name:       "Sucuri",
			Confidence: "High",
			Evidence:   sucuriEvidence,
		}, sucuriEvidence
	}

	return nil, nil
}

func portsFromOptions(opts registry.Options) ([]int, error) {
	raw, _ := opts.Flags["ports-list"].(string)
	if raw == "" {
		return append([]int(nil), opts.Config.Scanner.DefaultPorts...), nil
	}

	ports := []int{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			end, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			for port := start; port <= end; port++ {
				ports = append(ports, port)
			}
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func serviceName(port int) string {
	services := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		6379:  "Redis",
		8000:  "HTTP-alt",
		8080:  "HTTP-alt",
		8443:  "HTTPS-alt",
		9000:  "HTTP-alt",
		27017: "MongoDB",
	}
	if service, ok := services[port]; ok {
		return service
	}
	return "unknown"
}

func normalizeURL(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return strings.TrimRight(target, "/")
	}
	return "https://" + strings.TrimRight(target, "/")
}

func parseFuzzFinding(_ string, item string) (string, int) {
	status := 0
	open := strings.LastIndex(item, "[")
	close := strings.LastIndex(item, "]")
	if open >= 0 && close > open {
		status, _ = strconv.Atoi(item[open+1 : close])
		item = strings.TrimSpace(item[:open])
	}

	parsed, err := url.Parse(item)
	if err != nil || parsed.Path == "" {
		return item, status
	}
	if parsed.Path == "" {
		return "/", status
	}
	return parsed.Path, status
}

func tcpScanHost(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		parsed, err := url.Parse(target)
		if err == nil && parsed.Host != "" {
			host := parsed.Hostname()
			if host != "" {
				return host
			}
			if splitHost, _, err := net.SplitHostPort(parsed.Host); err == nil {
				return splitHost
			}
			return parsed.Host
		}
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}
	return target
}
