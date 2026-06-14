package output

import (
	"encoding/json"
	"fmt"
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
		return formatReconResults(v), nil
	case []registry.Result:
		results := make([]*registry.Result, 0, len(v))
		for i := range v {
			results = append(results, &v[i])
		}
		return formatReconResults(results), nil
	}

	return fmt.Sprintf("%v", data), nil
}

func (f *Formatter) formatRegistryResult(result *registry.Result) string {
	if result == nil {
		return ""
	}

	switch result.Module {
	case "enum":
		return formatEnum(result)
	case "ports":
		return formatPorts(result)
	case "fuzz":
		return formatFuzz(result)
	case "waf":
		return formatWAF(result)
	case "http":
		return formatHTTP(result)
	case "live":
		return formatLive(result)
	case "tech":
		return formatTech(result)
	default:
		return formatGeneric(result)
	}
}

func formatEnum(result *registry.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n\n", result.Target)
	b.WriteString("Subdomains Found:\n")
	if len(result.Findings) == 0 {
		b.WriteString("None\n")
	} else {
		for _, finding := range sortedFindings(result.Findings) {
			fmt.Fprintf(&b, "* %s\n", finding.Value)
		}
	}
	fmt.Fprintf(&b, "\nTotal Found: %d\n", len(result.Findings))
	return b.String()
}

func formatPorts(result *registry.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n\n", result.Target)
	b.WriteString("Open Ports:\n")
	if len(result.Findings) == 0 {
		b.WriteString("None\n")
	} else {
		for _, finding := range sortedFindings(result.Findings) {
			port := finding.Value
			service := finding.Description
			if service == "" {
				service = "unknown"
			}
			fmt.Fprintf(&b, "%-8s %s\n", port, service)
		}
	}
	fmt.Fprintf(&b, "\nTotal Open Ports: %d\n", len(result.Findings))
	return b.String()
}

func formatFuzz(result *registry.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n\n", result.Target)
	b.WriteString("Interesting Paths:\n")
	if len(result.Findings) == 0 {
		b.WriteString("None\n")
	} else {
		for _, finding := range sortedFindings(result.Findings) {
			status := metadataInt(finding.Metadata, "status")
			path := metadataString(finding.Metadata, "path")
			if path == "" {
				path = finding.Value
			}
			fmt.Fprintf(&b, "%d %s\n", status, path)
		}
	}
	fmt.Fprintf(&b, "\nSummary:\nTotal Found: %d\n", len(result.Findings))
	return b.String()
}

func formatWAF(result *registry.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n\n", result.Target)
	if len(result.Findings) == 0 {
		b.WriteString("No WAF detected\n")
		return b.String()
	}

	finding := result.Findings[0]
	fmt.Fprintf(&b, "WAF Detected: %s\n\n", finding.Value)
	confidence := metadataString(finding.Metadata, "confidence")
	if confidence == "" {
		confidence = "Medium"
	}
	fmt.Fprintf(&b, "Confidence: %s\n\n", confidence)
	if len(finding.Evidence) > 0 {
		b.WriteString("Evidence:\n")
		for _, evidence := range finding.Evidence {
			fmt.Fprintf(&b, "* %s\n", evidence)
		}
	}
	return b.String()
}

func formatHTTP(result *registry.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n\n", result.Target)
	b.WriteString("HTTP Probe Results:\n")
	if len(result.Findings) == 0 {
		b.WriteString("None\n")
	} else {
		for _, finding := range sortedFindings(result.Findings) {
			url := metadataString(finding.Metadata, "url")
			status := metadataInt(finding.Metadata, "status_code")
			title := metadataString(finding.Metadata, "title")
			server := metadataString(finding.Metadata, "server")
			length := metadataInt64(finding.Metadata, "content_length")
			responseTime := metadataInt64(finding.Metadata, "response_time_ms")
			fmt.Fprintf(&b, "%s\n", url)
			fmt.Fprintf(&b, "  Status: %d\n", status)
			fmt.Fprintf(&b, "  Title: %s\n", emptyDash(title))
			fmt.Fprintf(&b, "  Server: %s\n", emptyDash(server))
			fmt.Fprintf(&b, "  Content Length: %d\n", length)
			fmt.Fprintf(&b, "  Response Time: %dms\n", responseTime)
		}
	}
	fmt.Fprintf(&b, "\nTotal HTTP Responses: %d\n", len(result.Findings))
	return b.String()
}

func formatLive(result *registry.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n\n", result.Target)
	b.WriteString("Live Hosts:\n")
	if len(result.Findings) == 0 {
		b.WriteString("None\n")
	} else {
		for _, finding := range sortedFindings(result.Findings) {
			fmt.Fprintf(&b, "* %s\n", finding.Value)
		}
	}
	fmt.Fprintf(&b, "\nTotal Live Hosts: %d\n", len(result.Findings))
	return b.String()
}

func formatTech(result *registry.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n\n", result.Target)
	b.WriteString("Technology Fingerprints:\n")
	if len(result.Findings) == 0 {
		b.WriteString("None\n")
	} else {
		for _, finding := range sortedFindings(result.Findings) {
			url := metadataString(finding.Metadata, "url")
			fmt.Fprintf(&b, "* %s", finding.Value)
			if url != "" {
				fmt.Fprintf(&b, " (%s)", url)
			}
			if len(finding.Evidence) > 0 {
				fmt.Fprintf(&b, " evidence=%s", strings.Join(finding.Evidence, ","))
			}
			b.WriteString("\n")
		}
	}
	fmt.Fprintf(&b, "\nTotal Technologies: %d\n", len(result.Findings))
	return b.String()
}

func formatReconResults(results []*registry.Result) string {
	var b strings.Builder
	target := ""
	summary := map[string]int{}
	waf := "None"
	byModule := map[string]*registry.Result{}

	for _, result := range results {
		if result == nil {
			continue
		}
		byModule[result.Module] = result
		if target == "" {
			target = result.Target
		}
		switch result.Module {
		case "enum":
			summary["Subdomains"] = len(result.Findings)
		case "ports":
			summary["Open Ports"] = len(result.Findings)
		case "fuzz":
			summary["Interesting Paths"] = len(result.Findings)
		case "waf":
			if len(result.Findings) > 0 {
				waf = result.Findings[0].Value
			}
		case "http":
			summary["HTTP Responses"] = len(result.Findings)
		case "live":
			summary["Live Hosts"] = len(result.Findings)
		case "tech":
			summary["Technologies"] = len(result.Findings)
		}
	}

	fmt.Fprintf(&b, "Target: %s\n\n", target)
	fmt.Fprintf(&b, "Subdomains: %d\n", summary["Subdomains"])
	fmt.Fprintf(&b, "Live Hosts: %d\n", summary["Live Hosts"])
	fmt.Fprintf(&b, "Open Ports: %d\n", summary["Open Ports"])
	fmt.Fprintf(&b, "WAF: %s\n", waf)
	fmt.Fprintf(&b, "Interesting Paths: %d\n", summary["Interesting Paths"])
	fmt.Fprintf(&b, "HTTP Responses: %d\n", summary["HTTP Responses"])
	fmt.Fprintf(&b, "Technologies: %d\n", summary["Technologies"])

	b.WriteString("\nFindings\n")
	b.WriteString("--------\n")
	writeReconSection(&b, "Subdomains", byModule["enum"], func(f registry.Finding) string { return f.Value })
	writeReconSection(&b, "Open Ports", byModule["ports"], func(f registry.Finding) string {
		if f.Description == "" {
			return f.Value
		}
		return fmt.Sprintf("%s %s", f.Value, f.Description)
	})
	writeReconSection(&b, "Directory Findings", byModule["fuzz"], func(f registry.Finding) string {
		return fmt.Sprintf("%d %s", metadataInt(f.Metadata, "status"), metadataString(f.Metadata, "path"))
	})
	writeReconSection(&b, "HTTP Probe", byModule["http"], func(f registry.Finding) string {
		return fmt.Sprintf("%s %d %q", metadataString(f.Metadata, "url"), metadataInt(f.Metadata, "status_code"), metadataString(f.Metadata, "title"))
	})
	writeReconSection(&b, "Live Hosts", byModule["live"], func(f registry.Finding) string { return f.Value })
	writeReconSection(&b, "Technologies", byModule["tech"], func(f registry.Finding) string {
		return fmt.Sprintf("%s %s", f.Value, metadataString(f.Metadata, "url"))
	})
	return b.String()
}

func writeReconSection(b *strings.Builder, title string, result *registry.Result, line func(registry.Finding) string) {
	fmt.Fprintf(b, "\n%s:\n", title)
	if result == nil || len(result.Findings) == 0 {
		b.WriteString("None\n")
		return
	}
	for _, finding := range sortedFindings(result.Findings) {
		fmt.Fprintf(b, "- %s\n", line(finding))
	}
}

func formatGeneric(result *registry.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n\n", result.Target)
	for _, finding := range result.Findings {
		fmt.Fprintf(&b, "* %s: %s\n", finding.Type, finding.Value)
	}
	fmt.Fprintf(&b, "\nTotal Found: %d\n", len(result.Findings))
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
