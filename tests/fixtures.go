package tests

import (
	"testing"

	"github.com/NASHEDIxCODER/gospyder/internal/app"
	"github.com/NASHEDIxCODER/gospyder/internal/config"
)

// Setup initializes application for testing
func Setup(t *testing.T) *config.Config {
	cfg := config.DefaultConfig()
	cfg.Verbose = false

	if err := app.Initialize(cfg); err != nil {
		t.Fatalf("Failed to initialize app: %v", err)
	}

	t.Cleanup(func() {
		app.Cleanup()
		app.Reset()
	})

	return cfg
}

// GetTestDataPath returns path to test data directory
func GetTestDataPath() string {
	return "tests/testdata"
}
