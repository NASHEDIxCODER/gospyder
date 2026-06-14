package enum

import (
	"context"
	"fmt"
	"time"

	"github.com/NASHEDIxCODER/gospyder/internal/registry"
	"github.com/NASHEDIxCODER/gospyder/pkg/resolver"
)

// ModuleAdapter wraps enum functionality as a Module
type ModuleAdapter struct {
	engine *Engine
}

// NewModule creates a new subdomain enumeration module
func NewModule() registry.Module {
	// Initialize with default resolver pool
	pool := resolver.NewPool([]string{
		"8.8.8.8",
		"8.8.4.4",
		"1.1.1.1",
		"1.0.0.1",
	})

	return &ModuleAdapter{
		engine: NewEngine(pool, 100),
	}
}

// Name returns the module name
func (m *ModuleAdapter) Name() string {
	return "enum"
}

// Description returns the module description
func (m *ModuleAdapter) Description() string {
	return "Subdomain enumeration via active DNS brute-force and passive Certificate Transparency"
}

// Run executes subdomain enumeration.
func (m *ModuleAdapter) Run(ctx context.Context, opts registry.Options) (*registry.Result, error) {
	// Extract flags
	target, ok := opts.Flags["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("target flag required")
	}

	wordlist, _ := opts.Flags["wordlist"].(string)
	if wordlist == "" {
		wordlist = "wordlists/subdomains.txt"
	}

	modeStr, _ := opts.Flags["mode"].(string)
	if modeStr == "" {
		modeStr = "active"
	}

	mode, err := enumMode(modeStr)
	if err != nil {
		return nil, err
	}

	opts.Logger.Info("Starting subdomain enumeration for %s", target)
	subdomains := m.engine.Run(ctx, target, wordlist, mode)

	findings := make([]registry.Finding, 0, len(subdomains))
	for _, subdomain := range subdomains {
		findings = append(findings, registry.Finding{
			Type:     "subdomain",
			Value:    subdomain,
			Severity: "info",
		})
	}

	return &registry.Result{
		Module:    m.Name(),
		Timestamp: time.Now(),
		Status:    "success",
		Target:    target,
		Findings:  findings,
		Metadata: map[string]interface{}{
			"wordlist": wordlist,
			"mode":     modeStr,
		},
	}, nil
}

func enumMode(mode string) (EnumMode, error) {
	switch mode {
	case "active":
		return ModeActive, nil
	case "passive":
		return ModePassive, nil
	case "both":
		return ModeBoth, nil
	default:
		return ModeActive, fmt.Errorf("invalid enum mode %q", mode)
	}
}
