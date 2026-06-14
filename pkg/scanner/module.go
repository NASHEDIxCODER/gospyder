package scanner

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/NASHEDIxCODER/gospyder/internal/registry"
)

// PortScanModuleAdapter wraps port scanning as a Module.
type PortScanModuleAdapter struct{}

// NewPortScanModule creates a new port scanning module.
func NewPortScanModule() registry.Module {
	return &PortScanModuleAdapter{}
}

func (m *PortScanModuleAdapter) Name() string {
	return "ports"
}

func (m *PortScanModuleAdapter) Description() string {
	return "TCP port scanning with service detection for common ports"
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
	scanHost := tcpScanHost(target)
	opts.Logger.Info("Starting port scan for %s", scanHost)
	scanner := &PortScanner{}
	openPorts := scanner.ScanWithRetry(ctx, scanHost, ports, opts.Config.Threads, retries, opts.Config.Verbose)
	sort.Ints(openPorts)

	findings := make([]registry.Finding, 0, len(openPorts))
	for _, port := range openPorts {
		findings = append(findings, registry.Finding{
			Type:        "open_port",
			Value:       fmt.Sprintf("%d/tcp", port),
			Description: serviceName(port),
			Severity:    "info",
			Metadata: map[string]interface{}{
				"port":    port,
				"service": serviceName(port),
			},
		})
	}

	return &registry.Result{
		Module:    m.Name(),
		Timestamp: time.Now(),
		Status:    "success",
		Target:    target,
		Findings:  findings,
		Metadata: map[string]interface{}{
			"ports_scanned": len(ports),
			"retries":       retries,
			"scan_host":     scanHost,
		},
	}, nil
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
	return "HTTP directory and path fuzzing with comprehensive wordlist"
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
	opts.Logger.Info("Starting directory fuzz for %s", baseURL)
	fuzzer := &Fuzzer{}
	found := fuzzer.Scan(ctx, baseURL, wordlist, opts.Config.Threads)

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
			"wordlist": wordlist,
		},
	}, nil
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

	opts.Logger.Info("Starting WAF detection for %s", target)
	scanner := &WAFScanner{}
	detection := scanner.DetectDetailed(ctx, target)

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
