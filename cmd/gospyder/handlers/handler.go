package handlers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/NASHEDIxCODER/gospyder/internal/app"
	"github.com/NASHEDIxCODER/gospyder/internal/registry"
	"github.com/NASHEDIxCODER/gospyder/internal/workspace"
)

// Handler base structure for all command handlers
type Handler struct {
	moduleNames []string
}

// NewHandler creates a new handler
func NewHandler(moduleNames ...string) *Handler {
	return &Handler{
		moduleNames: moduleNames,
	}
}

// ExecuteModule executes a single module with given flags
func ExecuteModule(moduleName string, flags map[string]interface{}) error {
	result, err := RunModule(moduleName, flags)
	if err != nil {
		return err
	}

	ctx := app.Global()
	formatted, err := ctx.Formatter.Format(result)
	if err != nil {
		return err
	}
	fmt.Print(formatted)
	if formatted != "" && formatted[len(formatted)-1] != '\n' {
		fmt.Println()
	}
	if savePath, err := saveModuleResult(result, flags, formatted); err != nil {
		return err
	} else if savePath != "" {
		fmt.Printf("\nResults saved to:\n%s\n", displayWorkspacePath(savePath))
	}
	return nil
}

// RunModule executes a single module and returns structured results.
func RunModule(moduleName string, flags map[string]interface{}) (*registry.Result, error) {
	ctx := app.Global()
	appCtx, cancel := context.WithTimeout(context.Background(), time.Duration(ctx.Config.Timeout)*time.Second)
	defer cancel()

	module, err := ctx.Registry.Get(moduleName)
	if err != nil {
		return nil, fmt.Errorf("module not found: %w", err)
	}

	opts := registry.Options{
		Config:     ctx.Config,
		Logger:     ctx.Logger,
		Formatter:  ctx.Formatter,
		Workspace:  ctx.Workspace,
		HTTPClient: ctx.HTTPClient,
		Flags:      flags,
		Errors:     ctx.Errors,
	}

	ctx.Logger.Info("Starting module: %s", moduleName)
	start := time.Now()

	result, err := module.Run(appCtx, opts)
	if err != nil {
		ctx.Logger.Error("Module %s failed: %v", moduleName, err)
		return nil, err
	}

	duration := time.Since(start)
	if result != nil {
		result.Duration = duration.Seconds()
	}
	ctx.Logger.Info("Module %s completed in %.2fs", moduleName, duration.Seconds())

	return result, nil
}

// ExecuteModules executes multiple modules
func ExecuteModules(moduleNames []string, flags map[string]interface{}) error {
	results := make([]*registry.Result, 0, len(moduleNames))
	priorResults := map[string]*registry.Result{}

	for _, moduleName := range moduleNames {

		// Create module-specific flags copy
		moduleFlags := make(map[string]interface{})
		for k, v := range flags {
			moduleFlags[k] = v
		}

		// Route correct target format per module
		switch moduleName {

		case "enum", "ports":
			if host, ok := flags["host"]; ok {
				moduleFlags["target"] = host
			}

		case "fuzz", "waf", "http", "tech":
			if url, ok := flags["url"]; ok {
				moduleFlags["target"] = url
			}

		case "live":
			if host, ok := flags["host"]; ok {
				moduleFlags["target"] = host
			}
		}

		moduleFlags["results"] = priorResults

		result, err := RunModule(moduleName, moduleFlags)
		if err != nil {
			return err
		}

		results = append(results, result)

		if result != nil {
			priorResults[result.Module] = result
		}
	}

	ctx := app.Global()

	formatted, err := ctx.Formatter.Format(results)
	if err != nil {
		return err
	}

	fmt.Print(formatted)

	if formatted != "" && formatted[len(formatted)-1] != '\n' {
		fmt.Println()
	}

	if savePath, err := saveReconResults(results, flags, formatted); err != nil {
		return err
	} else if savePath != "" {
		fmt.Printf("\nResults saved to:\n%s\n", displayWorkspacePath(savePath))
	}

	return nil
}

func saveModuleResult(result *registry.Result, flags map[string]interface{}, formatted string) (string, error) {
	if result == nil || !workspaceEnabled(flags) {
		return "", nil
	}

	ws := workspaceForTarget(result.Target)
	content := moduleWorkspaceContent(result, formatted)
	_, err := ws.SaveResult(result.Module, workspaceFileName(result.Module), []byte(content))
	if err != nil {
		return "", err
	}
	return ws.Path, nil
}

func saveReconResults(results []*registry.Result, flags map[string]interface{}, summary string) (string, error) {
	if len(results) == 0 || !workspaceEnabled(flags) {
		return "", nil
	}

	target := targetFromFlags(flags)
	if target == "" {
		target = results[0].Target
	}
	ws := workspaceForTarget(target)

	for _, result := range results {
		if result == nil {
			continue
		}
		content := moduleWorkspaceContent(result, "")
		if _, err := ws.SaveResult(result.Module, workspaceFileName(result.Module), []byte(content)); err != nil {
			return "", err
		}
	}

	if _, err := ws.SaveResult("recon", "recon-summary.txt", []byte(summary)); err != nil {
		return "", err
	}
	return ws.Path, nil
}

func workspaceEnabled(flags map[string]interface{}) bool {
	ctx := app.Global()
	enabled := ctx.Config.Workspace.Enabled
	if flagValue, ok := flags["workspace"].(bool); ok {
		enabled = flagValue
	}
	return enabled
}

func workspaceForTarget(target string) *workspace.Workspace {
	ctx := app.Global()
	return workspace.NewForTarget(ctx.Config.Workspace.Path, target)
}

func targetFromFlags(flags map[string]interface{}) string {
	target, _ := flags["target"].(string)
	return target
}

func workspaceFileName(module string) string {
	switch module {
	case "enum":
		return "subdomains.txt"
	case "ports":
		return "ports.txt"
	case "fuzz":
		return "fuzz.txt"
	case "waf":
		return "waf.txt"
	case "http":
		return "http-probe.txt"
	case "live":
		return "live-hosts.txt"
	case "tech":
		return "technologies.txt"
	default:
		return module + ".txt"
	}
}

func moduleWorkspaceContent(result *registry.Result, formatted string) string {
	var b strings.Builder
	writeReportHeader(&b, result)

	switch result.Module {
	case "enum":
		b.WriteString("Subdomains:\n")
		writeFindingLines(&b, result, func(f registry.Finding) string { return f.Value }, "No subdomains found")
	case "ports":
		b.WriteString("Open Ports:\n")
		writeFindingLines(&b, result, func(f registry.Finding) string {
			line := f.Value
			if f.Description != "" {
				line += " " + f.Description
			}
			// Include banner if available
			if len(f.Evidence) > 0 && f.Evidence[0] != "" {
				line += " (" + f.Evidence[0] + ")"
			} else if b, ok := f.Metadata["banner"].(string); ok && b != "" {
				line += " (" + b + ")"
			}
			return line
		}, "No open ports found")
	case "fuzz":
		b.WriteString("Directory Findings:\n")
		writeFindingLines(&b, result, func(f registry.Finding) string {
			status, _ := f.Metadata["status"].(int)
			path, _ := f.Metadata["path"].(string)
			if path == "" {
				path = f.Value
			}
			return fmt.Sprintf("%d %s", status, path)
		}, "No interesting paths found")
	case "waf":
		if len(result.Findings) == 0 {
			b.WriteString("No WAF detected\n")
			return b.String()
		}
		for _, finding := range result.Findings {
			fmt.Fprintf(&b, "WAF Detected: %s\n", finding.Value)
			confidence, _ := finding.Metadata["confidence"].(string)
			if confidence != "" {
				fmt.Fprintf(&b, "Confidence: %s\n", confidence)
			}
			if len(finding.Evidence) > 0 {
				b.WriteString("Evidence:\n")
				for _, evidence := range finding.Evidence {
					fmt.Fprintf(&b, "- %s\n", evidence)
				}
			}
		}
	case "http":
		b.WriteString("HTTP Probe Results:\n")
		writeFindingLines(&b, result, httpProbeLine, "No HTTP responses received")
	case "live":
		b.WriteString("Live Hosts:\n")
		writeFindingLines(&b, result, func(f registry.Finding) string { return f.Value }, "No live hosts found")
	case "tech":
		b.WriteString("Technology Fingerprints:\n")
		writeFindingLines(&b, result, techLine, "No technologies detected")
	default:
		if formatted != "" {
			b.WriteString(formatted)
		} else {
			writeFindingLines(&b, result, func(f registry.Finding) string { return f.Value }, "No findings")
		}
	}
	return b.String()
}

func writeReportHeader(b *strings.Builder, result *registry.Result) {
	fmt.Fprintf(b, "GoSpyder Report\n")
	fmt.Fprintf(b, "===============\n\n")
	fmt.Fprintf(b, "Module: %s\n", result.Module)
	fmt.Fprintf(b, "Target: %s\n", result.Target)
	fmt.Fprintf(b, "Status: %s\n", result.Status)
	fmt.Fprintf(b, "Scanned At: %s\n", result.Timestamp.Format(time.RFC3339))
	if result.Duration > 0 {
		fmt.Fprintf(b, "Duration: %.2fs\n", result.Duration)
	}
	fmt.Fprintf(b, "Findings: %d\n", len(result.Findings))
	if len(result.Metadata) > 0 {
		b.WriteString("Metadata:\n")
		for _, key := range sortedMetadataKeys(result.Metadata) {
			fmt.Fprintf(b, "- %s: %v\n", key, result.Metadata[key])
		}
	}
	b.WriteString("\n")
}

func writeFindingLines(b *strings.Builder, result *registry.Result, line func(registry.Finding) string, empty string) {
	if len(result.Findings) == 0 {
		fmt.Fprintf(b, "%s\n", empty)
		return
	}
	for _, finding := range result.Findings {
		fmt.Fprintln(b, line(finding))
	}
}

func sortedMetadataKeys(metadata map[string]interface{}) []string {
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func httpProbeLine(f registry.Finding) string {
	url, _ := f.Metadata["url"].(string)
	status, _ := f.Metadata["status_code"].(int)
	title, _ := f.Metadata["title"].(string)
	server, _ := f.Metadata["server"].(string)
	length, _ := f.Metadata["content_length"].(int64)
	responseTime, _ := f.Metadata["response_time_ms"].(int64)
	return fmt.Sprintf("%s status=%d title=%q server=%q length=%d response_time=%dms", url, status, title, server, length, responseTime)
}

func techLine(f registry.Finding) string {
	url, _ := f.Metadata["url"].(string)
	return fmt.Sprintf("%s %s", f.Value, url)
}

func displayWorkspacePath(path string) string {
	rel, err := filepath.Rel(".", path)
	if err == nil && !strings.HasPrefix(rel, "..") {
		path = rel
	}
	path = filepath.ToSlash(filepath.Clean(path))
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return path
}

// PrintModuleList prints all available modules
func PrintModuleList() {
	ctx := app.Global()
	modules := ctx.Registry.List()

	if len(modules) == 0 {
		fmt.Println("No modules registered")
		return
	}

	fmt.Println("\nAvailable Modules:")
	fmt.Println("==================")
	for _, m := range modules {
		fmt.Printf("  %s\n", m.Name)
		fmt.Printf("    %s\n", m.Description)
	}
	fmt.Println()
}

// ValidateFlags validates required flags
func ValidateFlags(flags map[string]interface{}, required []string) error {
	for _, reqFlag := range required {
		if _, ok := flags[reqFlag]; !ok {
			return fmt.Errorf("required flag missing: %s", reqFlag)
		}
	}
	return nil
}

// PrintUsage prints module usage information
func PrintUsage(moduleName string) {
	ctx := app.Global()
	module, err := ctx.Registry.Get(moduleName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	fmt.Printf("Module: %s\n", module.Name())
	fmt.Printf("Description: %s\n\n", module.Description())
}
