package handlers

import (
	"flag"
	"fmt"
	"strings"

	"github.com/NASHEDIxCODER/gospyder/internal/app"
	targetparser "github.com/NASHEDIxCODER/gospyder/internal/target"
)

type GlobalOptions struct {
	Threads *int
	Timeout *int
	Verbose *bool
	Output  *string
}

func addGlobalFlags(fs *flag.FlagSet) *GlobalOptions {
	return &GlobalOptions{
		Threads: fs.Int("t", 0, "number of threads"),
		Timeout: fs.Int("timeout", 0, "timeout in seconds"),
		Verbose: fs.Bool("v", false, "verbose mode"),
		Output:  fs.String("o", "", "output file"),
	}
}

func applyGlobalFlags(opts *GlobalOptions, flags map[string]interface{}) {
	ctx := app.Global()
	if *opts.Threads > 0 {
		ctx.Config.Threads = *opts.Threads
		ctx.Config.Crawler.Concurrency = *opts.Threads
	}
	if *opts.Timeout > 0 {
		ctx.Config.Timeout = *opts.Timeout
	}
	if *opts.Verbose {
		ctx.Config.Verbose = true
		ctx.Logger.SetVerbosity(true)
	}
	if *opts.Output != "" {
		flags["output"] = *opts.Output
	}
}

// HandleEnum handles subdomain enumeration command
func HandleEnum(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gospyder enum <domain> [options]")
	}

	fs := flag.NewFlagSet("enum", flag.ContinueOnError)
	wordlist := fs.String("w", "wordlists/subdomains.txt", "subdomain wordlist")
	mode := fs.String("mode", "active", "enum mode: active, passive, both")
	workspace := fs.Bool("workspace", true, "save results to workspace")
	globalOpts := addGlobalFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	flags := map[string]interface{}{
		"target":    args[0],
		"wordlist":  *wordlist,
		"mode":      *mode,
		"workspace": *workspace,
	}
	applyGlobalFlags(globalOpts, flags)

	return ExecuteModule("enum", flags)
}

// HandlePorts handles port scanning command
func HandlePorts(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gospyder ports <domain> [options]")
	}

	cfg := app.Global().Config
	fs := flag.NewFlagSet("ports", flag.ContinueOnError)
	portsList := fs.String("ports-list", "", "ports to scan, e.g. 80,443,8000-8010")
	retry := fs.Int("retry", cfg.Retries, "retry attempts for failed connections")
	workspace := fs.Bool("workspace", true, "save results to workspace")
	globalOpts := addGlobalFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	remaining := fs.Args()
	if len(remaining) < 1 {
		return fmt.Errorf("usage: gospyder ports <domain> [options]")
	}
	target := remaining[0]

	flags := map[string]interface{}{
		"target":     target,
		"retry":      *retry,
		"ports-list": *portsList,
		"workspace":  *workspace,
	}
	applyGlobalFlags(globalOpts, flags)
	return ExecuteModule("ports", flags)
}

// HandleFuzz handles directory fuzzing command
func HandleFuzz(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gospyder fuzz <url> [options]")
	}

	fs := flag.NewFlagSet("fuzz", flag.ContinueOnError)
	wordlist := fs.String("fuzz-wordlist", "wordlists/paths.txt", "path wordlist")
	workspace := fs.Bool("workspace", true, "save results to workspace")
	globalOpts := addGlobalFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	flags := map[string]interface{}{
		"target":    args[0],
		"wordlist":  *wordlist,
		"workspace": *workspace,
	}
	applyGlobalFlags(globalOpts, flags)

	return ExecuteModule("fuzz", flags)
}

// HandleWAF handles WAF detection command
func HandleWAF(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gospyder waf <domain> [options]")
	}

	fs := flag.NewFlagSet("waf", flag.ContinueOnError)
	workspace := fs.Bool("workspace", true, "save results to workspace")
	globalOpts := addGlobalFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	flags := map[string]interface{}{
		"target":    args[0],
		"workspace": *workspace,
	}
	applyGlobalFlags(globalOpts, flags)

	return ExecuteModule("waf", flags)
}

// HandleHTTP handles HTTP probe command.
func HandleHTTP(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gospyder http <domain-or-url> [options]")
	}

	fs := flag.NewFlagSet("http", flag.ContinueOnError)
	workspace := fs.Bool("workspace", true, "save results to workspace")
	globalOpts := addGlobalFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	flags := map[string]interface{}{
		"target":    args[0],
		"workspace": *workspace,
	}
	applyGlobalFlags(globalOpts, flags)

	return ExecuteModule("http", flags)
}

// HandleLive handles live host detection command.
func HandleLive(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gospyder live <domain-or-url> [options]")
	}

	fs := flag.NewFlagSet("live", flag.ContinueOnError)
	workspace := fs.Bool("workspace", true, "save results to workspace")
	globalOpts := addGlobalFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	flags := map[string]interface{}{
		"target":    args[0],
		"workspace": *workspace,
	}
	applyGlobalFlags(globalOpts, flags)

	return ExecuteModule("live", flags)
}

// HandleTech handles technology fingerprinting command.
func HandleTech(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gospyder tech <domain-or-url> [options]")
	}

	fs := flag.NewFlagSet("tech", flag.ContinueOnError)
	workspace := fs.Bool("workspace", true, "save results to workspace")
	globalOpts := addGlobalFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	flags := map[string]interface{}{
		"target":    args[0],
		"workspace": *workspace,
	}
	applyGlobalFlags(globalOpts, flags)

	return ExecuteModule("tech", flags)
}

// HandleCrawl handles web crawling command
func HandleCrawl(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gospyder crawl <url> [options]")
	}

	fs := flag.NewFlagSet("crawl", flag.ContinueOnError)
	depth := fs.Int("depth", 0, "crawl depth (default: from config, usually 3)")
	workspace := fs.Bool("workspace", true, "save results to workspace")
	globalOpts := addGlobalFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	flags := map[string]interface{}{
		"target":    args[0],
		"depth":     *depth,
		"workspace": *workspace,
	}
	applyGlobalFlags(globalOpts, flags)

	return ExecuteModule("crawl", flags)
}

// HandleJS handles JavaScript analysis command
func HandleJS(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gospyder js <url> [options]")
	}

	fs := flag.NewFlagSet("js", flag.ContinueOnError)
	workspace := fs.Bool("workspace", true, "save results to workspace")
	globalOpts := addGlobalFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	flags := map[string]interface{}{
		"target":    args[0],
		"workspace": *workspace,
	}
	applyGlobalFlags(globalOpts, flags)

	return ExecuteModule("js", flags)
}

// HandleRecon handles full reconnaissance command
func HandleRecon(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gospyder recon <domain> [options]")
	}

	fs := flag.NewFlagSet("recon", flag.ContinueOnError)
	enumWordlist := fs.String("w", "wordlists/subdomains.txt", "subdomain wordlist")
	fuzzWordlist := fs.String("fuzz-wordlist", "wordlists/paths.txt", "path wordlist")
	portsList := fs.String("ports-list", "", "ports to scan")
	workspace := fs.Bool("workspace", true, "save results to workspace")
	globalOpts := addGlobalFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	// Execute multiple modules in sequence
	modules := []string{"enum", "ports", "fuzz", "waf", "http", "live", "tech", "js"}
	parsed, err := targetparser.Normalize(args[0])
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	flags := map[string]interface{}{
		"host":          parsed.Host,
		"url":           parsed.URL,
		"wordlist":      *enumWordlist,
		"fuzz-wordlist": *fuzzWordlist,
		"ports-list":    *portsList,
		"mode":          "active",
		"workspace":     *workspace,
	}
	applyGlobalFlags(globalOpts, flags)

	ctx := app.Global()
	ctx.Logger.Debug("Starting full reconnaissance for %s", args[0])

	return ExecuteModules(modules, flags)
}

// HandleList lists all available modules
func HandleList() error {
	PrintModuleList()
	return nil
}

// HandleHelp handles help command
func HandleHelp(moduleName string) error {
	if moduleName == "" {
		printGlobalHelp()
		return nil
	}

	ctx := app.Global()
	module, err := ctx.Registry.Get(moduleName)
	if err != nil {
		return fmt.Errorf("module not found: %s", moduleName)
	}

	PrintUsage(module.Name())
	return nil
}

func printGlobalHelp() {
	fmt.Print(strings.TrimLeft(`
GoSpyder - Complete Reconnaissance Framework
=============================================

Usage:
  gospyder [command] [target] [options]

Commands:
  enum                 Subdomain enumeration
  ports                Port scanning
  fuzz                 Directory fuzzing
  waf                  WAF detection
  http                 HTTP probe
  live                 Live host detection
  tech                 Technology fingerprinting
  crawl                Web crawling (URLs, parameters, APIs, JS files)
  js                   JavaScript analysis (endpoints, secrets, domains)
  recon                Full reconnaissance (all modules)
  list                 List all available modules
  help [module]        Show help for specific module

Global Options:
  -t <threads>         Number of concurrent threads (default: 100)
  -timeout <seconds>   Timeout in seconds (default: 10)
  -v                   Enable verbose output
  -o <file>            Save report to file

Examples:
  gospyder enum example.com
  gospyder ports example.com
  gospyder fuzz https://example.com
  gospyder js https://example.com
  gospyder recon example.com
  gospyder help

For more information, visit: https://github.com/NASHEDIxCODER/gospyder
`, "\n"))
}
