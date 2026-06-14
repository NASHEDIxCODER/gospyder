package registry

import (
	"context"
	"net/http"
	"time"

	"github.com/NASHEDIxCODER/gospyder/internal/config"
	"github.com/NASHEDIxCODER/gospyder/internal/errors"
	"github.com/NASHEDIxCODER/gospyder/internal/logger"
	"github.com/NASHEDIxCODER/gospyder/internal/workspace"
)

// Module is the interface all reconnaissance modules must implement
type Module interface {
	// Name returns the unique identifier for this module
	Name() string

	// Description returns human-readable module description
	Description() string

	// Run executes the module with given options
	// Returns error if module execution failed
	Run(ctx context.Context, opts Options) (*Result, error)
}

// Options contains shared resources all modules can access
type Options struct {
	// Shared services
	Config     *config.Config
	Logger     *logger.Logger
	Formatter  Formatter
	Workspace  *workspace.Workspace
	HTTPClient *http.Client

	// Module-specific CLI flags (passed from command handler)
	Flags map[string]interface{}

	// Error collection
	Errors *errors.Collector
}

// Formatter is the minimal output formatter contract modules can use without
// coupling the registry package to a concrete output implementation.
type Formatter interface {
	Format(data interface{}) (string, error)
}

// Result is the standardized output from any module execution
type Result struct {
	Module    string                 `json:"module"`
	Timestamp time.Time              `json:"timestamp"`
	Status    string                 `json:"status"` // "success", "error", "partial"
	Target    string                 `json:"target,omitempty"`
	Findings  []Finding              `json:"findings,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Errors    []string               `json:"errors,omitempty"`
	Duration  float64                `json:"duration_seconds,omitempty"`
}

// Finding is a single user-facing discovery produced by a module.
type Finding struct {
	Type        string                 `json:"type"`
	Value       string                 `json:"value"`
	Description string                 `json:"description,omitempty"`
	Severity    string                 `json:"severity,omitempty"`
	Evidence    []string               `json:"evidence,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ModuleInfo describes a registered module
type ModuleInfo struct {
	Name        string
	Description string
	Version     string
}
