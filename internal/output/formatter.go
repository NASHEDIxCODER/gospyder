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
			tag := "[OPEN]"
			if f.colors {
				tag = ColorGreen + tag + ColorReset
			}
			fmt.Fprintf(&b, "%s %-8s %s\n", tag, port, service)
		}
	} else {
		fmt.Fprintln(&b, "None found")
	}
	return b.String()
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
		for _, finding := range sortedFindings(result.Findings) {
			tag := "[TECH]"
			if f.colors {
				tag = ColorGreen + tag + ColorReset
			}
			fmt.Fprintf(&b, "%s %s\n", tag, finding.Value)
		}
	} else {
		fmt.Fprintln(&b, "None found")
	}
	return b.String()
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
			summary["Subdomains"] = len(result.Findings)
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
