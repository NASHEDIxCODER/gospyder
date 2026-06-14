package main

import (
	"context"
	"fmt"
	"os"

	"github.com/NASHEDIxCODER/gospyder/cmd/gospyder/handlers"
	"github.com/NASHEDIxCODER/gospyder/internal/app"
	"github.com/NASHEDIxCODER/gospyder/internal/config"
	"github.com/NASHEDIxCODER/gospyder/internal/output"
	"github.com/NASHEDIxCODER/gospyder/internal/registry"
	enumModule "github.com/NASHEDIxCODER/gospyder/pkg/enum"
	scannerModule "github.com/NASHEDIxCODER/gospyder/pkg/scanner"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
)

func PrintBanner() {
	banner := `
 ██████╗  ██████╗ ███████╗██████╗ ██╗   ██╗██████╗ ███████╗██████╗ 
██╔════╝ ██╔═══██╗██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
██║  ███╗██║   ██║███████╗██████╔╝ ╚████╔╝ ██║  ██║█████╗  ██████╔╝
██║   ██║██║   ██║╚════██║██╔═══╝   ╚██╔╝  ██║  ██║██╔══╝  ██╔══██╗
╚██████╔╝╚██████╔╝███████║██║        ██║   ██████╔╝███████╗██║  ██║
 ╚═════╝  ╚═════╝ ╚══════╝╚═╝        ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

                by nashedi_x_coder
`
	fmt.Printf("%s%s%s\n", ColorCyan, banner, ColorReset)
}

func PrintSuccess(msg string) {
	fmt.Printf("%s%s%s\n", ColorGreen, output.Success(msg), ColorReset)
}

func PrintInfo(msg string) {
	fmt.Printf("%s%s%s\n", ColorBlue, output.Info(msg), ColorReset)
}

func PrintError(msg string) {
	fmt.Fprintf(os.Stderr, "%s%s%s\n", ColorRed, output.Error(msg), ColorReset)
}

func PrintWarning(msg string) {
	fmt.Printf("%s%s%s\n", ColorYellow, output.Warn(msg), ColorReset)
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	if err := app.Initialize(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize application: %v\n", err)
		os.Exit(1)
	}
	defer app.Cleanup()

	ctx := app.Global()
	registerModules(ctx)

	if len(os.Args) < 2 {
		PrintBanner()
		handlers.HandleHelp("")
		return
	}

	command := os.Args[1]
	args := os.Args[2:]

	PrintBanner()

	var execErr error
	switch command {
	case "enum":
		execErr = handlers.HandleEnum(args)
	case "ports":
		execErr = handlers.HandlePorts(args)
	case "fuzz":
		execErr = handlers.HandleFuzz(args)
	case "waf":
		execErr = handlers.HandleWAF(args)
	case "http":
		execErr = handlers.HandleHTTP(args)
	case "live":
		execErr = handlers.HandleLive(args)
	case "tech":
		execErr = handlers.HandleTech(args)
	case "recon":
		execErr = handlers.HandleRecon(args)
	case "list":
		execErr = handlers.HandleList()
	case "help":
		if len(args) > 0 {
			execErr = handlers.HandleHelp(args[0])
		} else {
			execErr = handlers.HandleHelp("")
		}
	case "-h", "--help":
		handlers.HandleHelp("")
	case "-v", "--version":
		fmt.Println("GoSpyder v3.0 - Modular Reconnaissance Framework")
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		handlers.HandleHelp("")
		os.Exit(1)
	}

	if execErr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", execErr)
		os.Exit(1)
	}
}

func registerModules(appCtx *app.AppContext) {
	modules := []struct {
		name   string
		module interface{ Name() string }
	}{
		{"enum", enumModule.NewModule()},
		{"ports", scannerModule.NewPortScanModule()},
		{"fuzz", scannerModule.NewFuzzerModule()},
		{"waf", scannerModule.NewWAFModule()},
		{"http", scannerModule.NewHTTPProbeModule()},
		{"live", scannerModule.NewLiveHostModule()},
		{"tech", scannerModule.NewTechModule()},
	}

	for _, m := range modules {
		if mod, ok := m.module.(interface {
			Name() string
			Description() string
			Run(context.Context, registry.Options) (*registry.Result, error)
		}); ok {
			if err := appCtx.Registry.Register(m.name, mod); err != nil {
				appCtx.Logger.Error("Failed to register module %s: %v", m.name, err)
			} else {
				appCtx.Logger.Debug("Registered module: %s", m.name)
			}
		}
	}
}
