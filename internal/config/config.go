package config

import "time"

// Config holds all application configuration
type Config struct {
	// Core settings
	Threads int
	Timeout int
	Retries int
	Verbose bool

	// HTTP settings
	HTTP HTTPConfig

	// Module settings
	Scanner ScannerConfig
	Crawler CrawlerConfig

	// Output settings
	Output OutputConfig

	// Workspace settings
	Workspace WorkspaceConfig
}

type HTTPConfig struct {
	Timeout        time.Duration
	UserAgent      string
	FollowRedirect bool
	MaxRedirects   int
}

type ScannerConfig struct {
	DefaultPorts []int
	PathWordlist string
	PortTimeout  time.Duration
}

type CrawlerConfig struct {
	MaxDepth    int
	Concurrency int
}

type OutputConfig struct {
	Format string // json, csv, txt, html
	Colors bool
	Pretty bool
}

type WorkspaceConfig struct {
	Enabled bool
	Path    string
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		Threads: 100,
		Timeout: 10,
		Retries: 2,
		Verbose: false,
		HTTP: HTTPConfig{
			Timeout:        10 * time.Second,
			UserAgent:      "GoSpyder/3.0",
			FollowRedirect: true,
			MaxRedirects:   10,
		},
		Scanner: ScannerConfig{
			DefaultPorts: []int{22, 80, 443, 8080, 8443, 3000, 5000, 9000},
			PathWordlist: "wordlists/paths.txt",
			PortTimeout:  3 * time.Second,
		},
		Crawler: CrawlerConfig{
			MaxDepth:    3,
			Concurrency: 50,
		},
		Output: OutputConfig{
			Format: "txt",
			Colors: true,
			Pretty: true,
		},
		Workspace: WorkspaceConfig{
			Enabled: true,
			Path:    "./reports",
		},
	}
}

// Load loads configuration (for now returns defaults)
// TODO: Implement YAML loading with CLI flag overrides
func Load() (*Config, error) {
	return DefaultConfig(), nil
}
