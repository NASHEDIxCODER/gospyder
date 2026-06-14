package mocks

import (
	"github.com/NASHEDIxCODER/gospyder/internal/config"
)

// MockConfig returns a test configuration
func MockConfig() *config.Config {
	return &config.Config{
		Threads: 10,
		Timeout: 5,
		Retries: 1,
		Verbose: false,
		HTTP: config.HTTPConfig{
			Timeout: 5,
		},
		Output: config.OutputConfig{
			Format: "json",
			Colors: false,
			Pretty: true,
		},
	}
}
