package app

import (
	"net/http"
	"sync"

	"github.com/NASHEDIxCODER/gospyder/internal/config"
	"github.com/NASHEDIxCODER/gospyder/internal/errors"
	"github.com/NASHEDIxCODER/gospyder/internal/logger"
	"github.com/NASHEDIxCODER/gospyder/internal/output"
	"github.com/NASHEDIxCODER/gospyder/internal/registry"
	"github.com/NASHEDIxCODER/gospyder/internal/workspace"
)

var (
	globalContext *AppContext
	contextMutex  sync.Mutex
)

// AppContext holds all application-level services and provides dependency injection
type AppContext struct {
	Config     *config.Config
	Logger     *logger.Logger
	Formatter  *output.Formatter
	Workspace  *workspace.Workspace
	Registry   *registry.Registry
	HTTPClient *http.Client
	Errors     *errors.Collector
}

// Initialize creates and stores global application context
func Initialize(cfg *config.Config) error {
	contextMutex.Lock()
	defer contextMutex.Unlock()

	logger := logger.New(cfg.Verbose)
	formatter := output.New(cfg.Output.Format, cfg.Output.Colors, cfg.Output.Pretty)
	errCollector := errors.NewCollector()
	reg := registry.New()
	ws := workspace.New(cfg.Workspace.Path)

	httpClient := &http.Client{
		Timeout: cfg.HTTP.Timeout,
	}

	globalContext = &AppContext{
		Config:     cfg,
		Logger:     logger,
		Formatter:  formatter,
		Workspace:  ws,
		Registry:   reg,
		HTTPClient: httpClient,
		Errors:     errCollector,
	}

	logger.Debug("Application context initialized")
	return nil
}

// Global returns the global application context
// Panics if context not initialized
func Global() *AppContext {
	contextMutex.Lock()
	defer contextMutex.Unlock()

	if globalContext == nil {
		panic("application context not initialized - call Initialize() first")
	}

	return globalContext
}

// Cleanup cleans up resources
func Cleanup() {
	contextMutex.Lock()
	defer contextMutex.Unlock()

	if globalContext != nil {
		if globalContext.HTTPClient != nil {
			globalContext.HTTPClient.CloseIdleConnections()
		}
		if globalContext.Logger != nil {
			globalContext.Logger.Debug("Application cleanup complete")
		}
	}
}

// IsInitialized checks if application context is initialized
func IsInitialized() bool {
	contextMutex.Lock()
	defer contextMutex.Unlock()

	return globalContext != nil
}

// Reset resets the global context (for testing)
func Reset() {
	contextMutex.Lock()
	defer contextMutex.Unlock()

	globalContext = nil
}
