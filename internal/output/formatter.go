package output

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/NASHEDIxCODER/gospyder/internal/registry"
)

// Formatter handles output formatting for different formats
type Formatter struct {
	format string
	colors bool
	pretty bool
}

// New creates a new formatter
func New(format string, colors bool, pretty bool) *Formatter {
	return &Formatter{
		format: format,
		colors: colors,
		pretty: pretty,
	}
}

// Format converts data to the configured format
func (f *Formatter) Format(data interface{}) (string, error) {
	switch f.format {
	case "json":
		return f.formatJSON(data)
	case "csv":
		return f.formatCSV(data)
	case "txt":
		return f.formatTXT(data)
	default:
		return "", fmt.Errorf("unknown format: %s", f.format)
	}
}

func (f *Formatter) formatJSON(data interface{}) (string, error) {
	var bytes []byte
	var err error

	if f.pretty {
		bytes, err = json.MarshalIndent(data, "", "  ")
	} else {
		bytes, err = json.Marshal(data)
	}

	return string(bytes), err
}

func (f *Formatter) formatCSV(data interface{}) (string, error) {
	// Convert data to string representation
	// For now, return a placeholder
	return fmt.Sprintf("%v", data), nil
}

func (f *Formatter) formatTXT(data interface{}) (string, error) {
	switch v := data.(type) {
	case *registry.Result:
		return f.formatRegistryResult(v), nil
	case registry.Result:
		return f.formatRegistryResult(&v), nil
	case []*registry.Result:
		return f.formatReconResults(v), nil
	case []registry.Result:
		results := make([]*registry.Result, 0, len(v))
		for i := range v {
			results = append(results, &v[i])
		}
		return f.formatReconResults(results), nil
	}

	return fmt.Sprintf("%v", data), nil
}

func (f *Formatter) formatRegistryResult(result *registry.Result) string {
	if result == nil {
		return ""
	}

	switch result.Module {
	case "enum":
		return f.formatEnum(result)
	case "ports":
		return f.formatPorts(result)
	case "fuzz":
		return f.formatFuzz(result)
	case "waf":
		return f.formatWAF(result)
	case "http":
		return f.formatHTTP(result)
	case "live":
		return f.formatLive(result)
	case "tech":
		return f.formatTech(result)
	case "js":
		return f.formatJS(result)
	default:
		return f.formatGeneric(result)
	}
}

func (f *Formatter) formatBanner(title string) string {
	cyan := ""
	reset := ""
	if f.colors {
		cyan = ColorCyan
		reset = ColorReset
	}
	return fmt.Sprintf("%s═══════════════════════════════════════\n%s\n═══════════════════════════════════════%s\n", cyan, title, reset)
}

func (f *Formatter) formatEnum(result *registry.Result) string {
	var b strings.Builder
	b.WriteString(f.formatBanner("SUBDOMAIN ENUMERATION"))
	if len(result.Findings) > 0 {
		for _, finding := range sortedFindings(result.Findings) {
			tag := "[FOUND]"
			if f.colors {
				tag = ColorGreen + tag + ColorReset
			}
			fmt.Fprintf(&b, "%s %s\n", tag, finding.Value)
		}
	}
	return b.String()
}

func (f *Formatter) formatPorts(result *registry.Result) string {
	var b strings.Builder
	b.WriteString(f.formatBanner("PORT SCANNING"))
	if len(result.Findings) > 0 {
		for _, finding := range sortedFindings(result.Findings) {
			port := finding.Value
			service := finding.Description
			if service == "" {
				service = "unknown"
			}
			banner := ""
			if len(finding.Evidence) > 0 {
				banner = finding.Evidence[0]
			}
			// If no Evidence field, check Metadata for banner
			if banner == "" {
				if m, ok := finding.Metadata["banner"].(string); ok {
					banner = m
				}
			}

			tag := "[OPEN]"
			if f.colors {
				tag = ColorGreen + tag + ColorReset
			}

			// Format: [OPEN] 22/tcp   SSH OpenSSH 9.6
			if banner != "" {
				bannerCompact := compactBanner(banner)
				fmt.Fprintf(&b, "%s %-8s %-12s %s\n", tag, port, service, bannerCompact)
			} else {
				fmt.Fprintf(&b, "%s %-8s %s\n", tag, port, service)
			}
		}
	} else {
		fmt.Fprintln(&b, "None found")
	}
	return b.String()
}

// compactBanner returns a short, display-friendly version of a banner.
func compactBanner(banner string) string {
	// Take the first line only
	if idx := strings.Index(banner, "\n"); idx >= 0 {
		banner = banner[:idx]
	}
	// Remove HTTP prefix noise
	banner = strings.TrimPrefix(banner, "HTTP/")
	banner = strings.TrimSpace(banner)
	// Truncate if too long
	if len(banner) > 60 {
		banner = banner[:60] + "..."
	}
	return banner
}

func (f *Formatter) formatFuzz(result *registry.Result) string {
	var b strings.Builder
	b.WriteString(f.formatBanner("DIRECTORY FUZZING"))
	if len(result.Findings) > 0 {
		for _, finding := range sortedFindings(result.Findings) {
			status := metadataInt(finding.Metadata, "status")
			path := metadataString(finding.Metadata, "path")
			if path == "" {
				path = finding.Value
			}
			tag := "[FOUND]"
			if f.colors {
				tag = ColorGreen + tag + ColorReset
			}
			fmt.Fprintf(&b, "%s %d %s\n", tag, status, path)
		}
	} else {
		fmt.Fprintln(&b, "None found")
	}
	return b.String()
}

func (f *Formatter) formatWAF(result *registry.Result) string {
	var b strings.Builder
	b.WriteString(f.formatBanner("WAF DETECTION"))
	if len(result.Findings) > 0 {
		finding := result.Findings[0]
		tag := "[WAF]"
		if f.colors {
			tag = ColorGreen + tag + ColorReset
		}
		fmt.Fprintf(&b, "%s %s\n", tag, finding.Value)
		confidence := metadataString(finding.Metadata, "confidence")
		if confidence == "" {
			confidence = "High"
		}
		fmt.Fprintf(&b, "Confidence: %s\n", confidence)
		if len(finding.Evidence) > 0 {
			for _, evidence := range finding.Evidence {
				fmt.Fprintf(&b, "  Evidence: %s\n", evidence)
			}
		}
	} else {
		tag := "[WAF]"
		if f.colors {
			tag = ColorGreen + tag + ColorReset
		}
		fmt.Fprintf(&b, "%s None detected\n", tag)
	}
	return b.String()
}

func (f *Formatter) formatHTTP(result *registry.Result) string {
	var b strings.Builder
	b.WriteString(f.formatBanner("HTTP PROBE"))
	if len(result.Findings) > 0 {
		for _, finding := range sortedFindings(result.Findings) {
			url := metadataString(finding.Metadata, "url")
			if url == "" {
				url = finding.Value
			}
			status := metadataInt(finding.Metadata, "status_code")
			title := metadataString(finding.Metadata, "title")
			tag := "[LIVE]"
			if f.colors {
				tag = ColorGreen + tag + ColorReset
			}
			if title != "" {
				fmt.Fprintf(&b, "%s %s %d %q\n", tag, url, status, title)
			} else {
				fmt.Fprintf(&b, "%s %s %d\n", tag, url, status)
			}
		}
	} else {
		fmt.Fprintln(&b, "None found")
	}
	return b.String()
}

func (f *Formatter) formatLive(result *registry.Result) string {
	var b strings.Builder
	b.WriteString(f.formatBanner("LIVE HOSTS"))
	if len(result.Findings) > 0 {
		for _, finding := range sortedFindings(result.Findings) {
			tag := "[LIVE]"
			if f.colors {
				tag = ColorGreen + tag + ColorReset
			}
			fmt.Fprintf(&b, "%s %s\n", tag, finding.Value)
		}
	}
	return b.String()
}

func (f *Formatter) formatTech(result *registry.Result) string {
	var b strings.Builder
	b.WriteString(f.formatBanner("TECHNOLOGY DETECTION"))
	if len(result.Findings) > 0 {
		// Aggregate counts
		counts := make(map[string]int)
		for _, finding := range result.Findings {
			counts[finding.Value]++
		}

		// Sort by frequency
		type techCount struct {
			Name  string
			Count int
		}
		var sortedTechs []techCount
		for name, count := range counts {
			sortedTechs = append(sortedTechs, techCount{Name: name, Count: count})
		}
		sort.Slice(sortedTechs, func(i, j int) bool {
			if sortedTechs[i].Count == sortedTechs[j].Count {
				return sortedTechs[i].Name < sortedTechs[j].Name
			}
			return sortedTechs[i].Count > sortedTechs[j].Count
		})

		for _, tech := range sortedTechs {
			tag := "[TECH]"
			if f.colors {
				tag = ColorGreen + tag + ColorReset
			}
			if tech.Count > 1 {
				fmt.Fprintf(&b, "%s %s (%d hosts)\n", tag, tech.Name, tech.Count)
			} else {
				fmt.Fprintf(&b, "%s %s\n", tag, tech.Name)
			}
		}
	} else {
		fmt.Fprintln(&b, "None found")
	}
	return b.String()
}

func (f *Formatter) formatJS(result *registry.Result) string {
	var b strings.Builder
	b.WriteString(f.formatBanner("JAVASCRIPT ANALYSIS"))

	// --- Endpoint Categories (from new metadata) ---
	categories, hasCategories := result.Metadata["endpoint_categories"].(map[string][]string)
	jsFilesCount := metadataInt(result.Metadata, "js_files_count")
	endpointsCount := metadataInt(result.Metadata, "endpoints_count")
	domainsCount := metadataInt(result.Metadata, "domains_count")
	secretsCount := metadataInt(result.Metadata, "secrets_count")

	// JS Files section
	jsFiles := filterFindings(result.Findings, "js_file")
	if len(jsFiles) > 0 {
		b.WriteString("\nJS Files:\n")
		for _, finding := range sortedFindings(jsFiles) {
			tag := "[JS]"
			if f.colors {
				tag = ColorGreen + tag + ColorReset
			}
			size := metadataInt(finding.Metadata, "size")
			sizeStr := ""
			if size > 0 {
				sizeStr = fmt.Sprintf(" (%d bytes)", size)
			}
			fmt.Fprintf(&b, "%s %s%s\n", tag, finding.Value, sizeStr)
		}
	}

	// Categorized endpoints (if available)
	if hasCategories && len(categories) > 0 {
		b.WriteString("\nEndpoints:\n")
		// Print categories in a defined order
		catOrder := []string{"Authentication", "API", "GraphQL", "Uploads", "Admin", "User", "Other"}
		for _, catName := range catOrder {
			eps, ok := categories[catName]
			if !ok || len(eps) == 0 {
				continue
			}
			tag := "[ENDPOINT]"
			if f.colors {
				tag = ColorYellow + tag + ColorReset
			}
			fmt.Fprintf(&b, "\n  %s:\n", catName)
			for _, ep := range eps {
				fmt.Fprintf(&b, "    - %s\n", ep)
			}
		}
	} else {
		// Fallback to old flat format
		endpoints := filterFindings(result.Findings, "js_endpoint")
		if len(endpoints) > 0 {
			b.WriteString("\nEndpoints:\n")
			for _, finding := range sortedFindings(endpoints) {
				tag := "[ENDPOINT]"
				if f.colors {
					tag = ColorYellow + tag + ColorReset
				}
				method := metadataString(finding.Metadata, "method")
				methodStr := ""
				if method != "" && method != "GET" {
					methodStr = " [" + method + "]"
				}
				fmt.Fprintf(&b, "%s %s%s\n", tag, finding.Value, methodStr)
			}
		}
	}

	// Domains section
	domains := filterFindings(result.Findings, "js_domain")
	if len(domains) > 0 {
		b.WriteString("\nDomains:\n")
		for _, finding := range sortedFindings(domains) {
			tag := "[DOMAIN]"
			if f.colors {
				tag = ColorCyan + tag + ColorReset
			}
			dType := metadataString(finding.Metadata, "type")
			typeStr := ""
			if dType == "websocket" {
				typeStr = " [WS]"
			}
			fmt.Fprintf(&b, "%s %s%s\n", tag, finding.Value, typeStr)
		}
	}

	// Secrets section
	secrets := filterFindings(result.Findings, "js_secret")
	if len(secrets) > 0 {
		b.WriteString("\nPotential Secrets:\n")
		for _, finding := range sortedFindings(secrets) {
			confidence := metadataString(finding.Metadata, "confidence")
			var tagStr string
			switch confidence {
			case "HIGH":
				tagStr = "[CRITICAL]"
				if f.colors {
					tagStr = ColorRed + tagStr + ColorReset
				}
			case "MEDIUM":
				tagStr = "[WARNING]"
				if f.colors {
					tagStr = ColorYellow + tagStr + ColorReset
				}
			default:
				tagStr = "[NOTE]"
				if f.colors {
					tagStr = ColorReset + tagStr
				}
			}
			preview := ""
			if len(finding.Evidence) > 0 {
				preview = " " + finding.Evidence[0]
			}
			fmt.Fprintf(&b, "%s %s (%s)%s\n", tagStr, finding.Value, confidence, preview)
		}
	}

	// Statistics summary
	b.WriteString("\n")
	b.WriteString(f.formatBanner("JAVASCRIPT STATISTICS"))
	fmt.Fprintf(&b, "  JS Files:   %d\n", jsFilesCount)
	fmt.Fprintf(&b, "  Endpoints:  %d\n", endpointsCount)
	fmt.Fprintf(&b, "  Domains:    %d\n", domainsCount)
	fmt.Fprintf(&b, "  Secrets:    %d\n", secretsCount)

	if len(result.Findings) == 0 && jsFilesCount == 0 {
		fmt.Fprintln(&b, "No JavaScript files found")
	}

	return b.String()
}

func filterFindings(findings []registry.Finding, ftype string) []registry.Finding {
	var out []registry.Finding
	for _, f := range findings {
		if f.Type == ftype {
			out = append(out, f)
		}
	}
	return out
}

// nsNameFilter matches infrastructure name server patterns like ns1, ns2, ns3, etc.
var nsNameFilter = regexp.MustCompile(`^ns[0-9]+\.`)

// isInfrastructureName returns true if the domain appears to be infrastructure
// (e.g., nameservers like ns1.example.com, ns2.example.com).
func isInfrastructureName(domain string) bool {
	return nsNameFilter.MatchString(domain)
}

func (f *Formatter) formatReconResults(results []*registry.Result) string {
	var b strings.Builder
	summary := map[string]int{}
	waf := "None"

	for _, result := range results {
		if result == nil {
			continue
		}

		formatted := f.formatRegistryResult(result)
		if formatted != "" {
			b.WriteString(formatted)
			b.WriteString("\n")
		}

		switch result.Module {
		case "enum":
			// Count only non-infrastructure findings for accurate summary.
			// DNS infrastructure like ns1, ns2 should not dominate recon stats.
			filteredCount := 0
			for _, finding := range result.Findings {
				if !isInfrastructureName(finding.Value) {
					filteredCount++
				}
			}
			summary["Subdomains"] = filteredCount
		case "ports":
			summary["Open Ports"] = len(result.Findings)
		case "fuzz":
			summary["Paths"] = len(result.Findings)
		case "waf":
			if len(result.Findings) > 0 {
				waf = result.Findings[0].Value
			}
		case "http":
			summary["HTTP Responses"] = len(result.Findings)
		case "live":
			summary["Live Hosts"] = len(result.Findings)
		case "tech":
			uniqueTechs := make(map[string]bool)
			for _, f := range result.Findings {
				uniqueTechs[f.Value] = true
			}
			summary["Technologies"] = len(uniqueTechs)
		}
	}

	cyan := ""
	magenta := ""
	reset := ""
	if f.colors {
		cyan = ColorCyan
		magenta = ColorPurple
		reset = ColorReset
	}

	b.WriteString(fmt.Sprintf("%s╔════════════════════════════════════╗%s\n", cyan, reset))
	b.WriteString(fmt.Sprintf("%s║          RECON SUMMARY             ║%s\n", cyan, reset))
	b.WriteString(fmt.Sprintf("%s╠════════════════════════════════════╣%s\n", cyan, reset))

	printRow := func(label string, val interface{}) {
		valStr := fmt.Sprintf("%v", val)
		paddedVal := fmt.Sprintf("%-15s", valStr)
		if f.colors {
			paddedVal = magenta + paddedVal + reset
		}
		fmt.Fprintf(&b, "%s║%s %-16s │ %s%s║%s\n", cyan, reset, label, paddedVal, cyan, reset)
	}

	printRow("Subdomains", summary["Subdomains"])
	printRow("Live Hosts", summary["Live Hosts"])
	printRow("Open Ports", summary["Open Ports"])
	printRow("Paths", summary["Paths"])
	printRow("Technologies", summary["Technologies"])
	printRow("WAF", waf)

	b.WriteString(fmt.Sprintf("%s╚════════════════════════════════════╝%s\n", cyan, reset))

	return b.String()
}

func (f *Formatter) formatGeneric(result *registry.Result) string {
	var b strings.Builder
	b.WriteString(f.formatBanner(strings.ToUpper(result.Module) + " MODULE"))
	for _, finding := range result.Findings {
		tag := "[FOUND]"
		if f.colors {
			tag = ColorGreen + tag + ColorReset
		}
		fmt.Fprintf(&b, "%s %s: %s\n", tag, finding.Type, finding.Value)
	}
	return b.String()
}

func sortedFindings(findings []registry.Finding) []registry.Finding {
	out := append([]registry.Finding(nil), findings...)
	sort.Slice(out, func(i, j int) bool {
		return out[i].Value < out[j].Value
	})
	return out
}

func metadataString(metadata map[string]interface{}, key string) string {
	if metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return value
}

func metadataInt(metadata map[string]interface{}, key string) int {
	if metadata == nil {
		return 0
	}
	switch value := metadata[key].(type) {
	case int:
		return value
	case float64:
		return int(value)
	default:
		return 0
	}
}

func metadataInt64(metadata map[string]interface{}, key string) int64 {
	if metadata == nil {
		return 0
	}
	switch value := metadata[key].(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case float64:
		return int64(value)
	default:
		return 0
	}
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// FormatList formats a list of strings with optional coloring
func (f *Formatter) FormatList(items []string) string {
	if len(items) == 0 {
		return ""
	}

	return strings.Join(items, "\n")
}