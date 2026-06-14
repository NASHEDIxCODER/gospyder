package config

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Threads != 100 {
		t.Fatalf("Threads = %d, want 100", cfg.Threads)
	}
	if cfg.Timeout != 10 {
		t.Fatalf("Timeout = %d, want 10", cfg.Timeout)
	}
	if cfg.Retries != 2 {
		t.Fatalf("Retries = %d, want 2", cfg.Retries)
	}
	if cfg.HTTP.Timeout != 10*time.Second {
		t.Fatalf("HTTP.Timeout = %s, want 10s", cfg.HTTP.Timeout)
	}
	if len(cfg.Scanner.DefaultPorts) == 0 {
		t.Fatal("Scanner.DefaultPorts is empty")
	}
	if cfg.Scanner.PathWordlist == "" {
		t.Fatal("Scanner.PathWordlist is empty")
	}
	if cfg.Output.Format != "txt" {
		t.Fatalf("Output.Format = %q, want txt", cfg.Output.Format)
	}
	if !cfg.Workspace.Enabled {
		t.Fatal("Workspace.Enabled = false, want true")
	}
	if cfg.Workspace.Path != "./reports" {
		t.Fatalf("Workspace.Path = %q, want ./reports", cfg.Workspace.Path)
	}
}

func TestLoadReturnsDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}
	if cfg.HTTP.UserAgent != "GoSpyder/3.0" {
		t.Fatalf("HTTP.UserAgent = %q, want GoSpyder/3.0", cfg.HTTP.UserAgent)
	}
}
