# Phase 0: Detailed Implementation Plan - Module Registry Architecture

## 🎯 Phase 0 Overview

**Goal**: Establish scalable, extensible architecture for 25+ modules using Module Registry pattern

**Duration**: 5 days

**Output**:
- Clean command architecture
- Module registry system
- Foundation packages
- Testing framework
- Backward compatibility

---

## 📐 Architecture: Module Registry Pattern

### Why Not Switch/Case?

**Problem with traditional command routing**:
```go
// ❌ Unmaintainable at scale
func main() {
    switch command {
    case "enum":
        // 50+ lines of enum logic
    case "ports":
        // 50+ lines of port logic
    case "probe":
        // 50+ lines of probe logic
    // ... repeat 22+ more times
    // Total: 1500+ lines in one switch
    }
}
```

**Benefits of Module Registry**:
```go
// ✅ Scalable, maintainable, extensible
registry.Register("enum", subdomain.NewModule())
registry.Register("ports", portscan.NewModule())
registry.Register("probe", probe.NewModule())
// ... repeat 22+ times
// Each module is self-contained
// Main logic: just call registry.Get(cmd).Run()
```

---

## 🏗️ Core Architecture

### 1. Module Interface (All modules implement this)

**File**: `internal/registry/module.go`

```go
package registry

import (
	"context"
	"time"
)

// Module is the interface all reconnaissance modules must implement
type Module interface {
	// Name returns the unique identifier for this module
	Name() string

	// Description returns human-readable module description
	Description() string

	// Run executes the module with given options
	// Returns error if module execution failed
	Run(ctx context.Context, opts Options) error
}

// Options contains shared resources all modules can access
type Options struct {
	// Shared services
	Config      *config.Config
	Logger      *logger.Logger
	Formatter   *output.Formatter
	Workspace   *workspace.Workspace
	Registry    *Registry
	HTTPClient  *http.Client

	// Module-specific CLI flags (passed from command handler)
	Flags       map[string]interface{}

	// Error collection
	Errors      *errors.Collector
}

// Result is the standardized output from any module execution
type Result struct {
	Module      string        `json:"module"`
	Timestamp   time.Time     `json:"timestamp"`
	Status      string        `json:"status"`     // "success", "error", "partial"
	Target      string        `json:"target"`
	Count       int           `json:"count"`
	Data        interface{}   `json:"data"`
	Errors      []string      `json:"errors,omitempty"`
	Duration    float64       `json:"duration_seconds"`
}

// ModuleInfo describes a registered module
type ModuleInfo struct {
	Name        string
	Description string
	Version     string
}
```

### 2. Module Registry Implementation

**File**: `internal/registry/registry.go`

```go
package registry

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Registry manages module registration and execution
type Registry struct {
	modules map[string]Module
	mu      sync.RWMutex
}

// New creates a new module registry
func New() *Registry {
	return &Registry{
		modules: make(map[string]Module),
	}
}

// Register adds a module to the registry
func (r *Registry) Register(name string, module Module) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.modules[name]; exists {
		return fmt.Errorf("module %s already registered", name)
	}

	r.modules[name] = module
	return nil
}

// Get retrieves a module by name
func (r *Registry) Get(name string) (Module, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	module, exists := r.modules[name]
	if !exists {
		return nil, fmt.Errorf("unknown module: %s", name)
	}

	return module, nil
}

// List returns all registered module information
func (r *Registry) List() []ModuleInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	modules := make([]ModuleInfo, 0, len(r.modules))
	for _, module := range r.modules {
		modules = append(modules, ModuleInfo{
			Name:        module.Name(),
			Description: module.Description(),
		})
	}

	// Sort by name
	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Name < modules[j].Name
	})

	return modules
}

// Run executes a module by name
func (r *Registry) Run(ctx context.Context, name string, opts Options) error {
	module, err := r.Get(name)
	if err != nil {
		return err
	}

	return module.Run(ctx, opts)
}

// Count returns number of registered modules
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.modules)
}
```

---

## 📦 Foundation Packages

### 1. internal/config/ - Configuration Management

**File**: `internal/config/config.go`

```go
package config

import "time"

// Config holds all application configuration
type Config struct {
	// Core settings
	Threads  int
	Timeout  int
	Retries  int
	Verbose  bool

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

// Load loads configuration (YAML file + CLI overrides)
func Load() (*Config, error) {
	// TODO: Implement YAML loading with CLI flag overrides
	return DefaultConfig(), nil
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
			DefaultPorts: []int{22, 80, 443, ...},
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
			Enabled: false,
			Path:    "./projects",
		},
	}
}
```

### 2. internal/logger/ - Logging

**File**: `internal/logger/logger.go`

```go
package logger

import (
	"fmt"
	"io"
	"os"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

type Logger struct {
	level     Level
	out       io.Writer
	verbosity bool
}

func New(verbosity bool) *Logger {
	level := LevelInfo
	if verbosity {
		level = LevelDebug
	}

	return &Logger{
		level:     level,
		out:       os.Stderr,
		verbosity: verbosity,
	}
}

func (l *Logger) Debug(msg string, args ...interface{}) {
	if l.level <= LevelDebug {
		l.log("DEBUG", msg, args...)
	}
}

func (l *Logger) Info(msg string, args ...interface{}) {
	if l.level <= LevelInfo {
		l.log("INFO", msg, args...)
	}
}

func (l *Logger) Warn(msg string, args ...interface{}) {
	if l.level <= LevelWarn {
		l.log("WARN", msg, args...)
	}
}

func (l *Logger) Error(msg string, args ...interface{}) {
	if l.level <= LevelError {
		l.log("ERROR", msg, args...)
	}
}

func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.log("FATAL", msg, args...)
	os.Exit(1)
}

func (l *Logger) log(level, msg string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(l.out, "[%s] [%s] %s\n", timestamp, level, fmt.Sprintf(msg, args...))
}
```

### 3. internal/output/ - Output Formatting

**File**: `internal/output/formatter.go`

```go
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
)

type Formatter struct {
	format string
	colors bool
}

func New(format string, colors bool) *Formatter {
	return &Formatter{
		format: format,
		colors: colors,
	}
}

func (f *Formatter) Format(data interface{}) (string, error) {
	switch f.format {
	case "json":
		return f.formatJSON(data)
	case "csv":
		return f.formatCSV(data)
	case "txt":
		return f.formatTXT(data)
	default:
		return "", fmt.Errorf("unknown format: %s", f.format)
	}
}

func (f *Formatter) formatJSON(data interface{}) (string, error) {
	bytes, err := json.MarshalIndent(data, "", "  ")
	return string(bytes), err
}

func (f *Formatter) formatCSV(data interface{}) (string, error) {
	// TODO: Implement CSV formatting
	return "", nil
}

func (f *Formatter) formatTXT(data interface{}) (string, error) {
	// TODO: Implement TXT formatting
	return "", nil
}
```

**File**: `internal/output/colors.go`

```go
package output

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
)

func Success(msg string) string {
	return ColorGreen + "✓ " + msg + ColorReset
}

func Error(msg string) string {
	return ColorRed + "✗ " + msg + ColorReset
}

func Info(msg string) string {
	return ColorBlue + "ℹ " + msg + ColorReset
}

func Warn(msg string) string {
	return ColorYellow + "⚠ " + msg + ColorReset
}
```

### 4. internal/workspace/ - Project Management

**File**: `internal/workspace/workspace.go`

```go
package workspace

import (
	"os"
	"path/filepath"
)

type Workspace struct {
	Path string
	Name string
}

func New(path string) *Workspace {
	return &Workspace{
		Path: path,
		Name: filepath.Base(path),
	}
}

// Initialize creates project structure
func (w *Workspace) Initialize() error {
	dirs := []string{
		w.Path,
		filepath.Join(w.Path, "results"),
		filepath.Join(w.Path, "screenshots"),
		filepath.Join(w.Path, "cache"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return nil
}

// SaveResult saves module results to file
func (w *Workspace) SaveResult(module string, data []byte) error {
	filePath := filepath.Join(w.Path, "results", module+".json")
	return os.WriteFile(filePath, data, 0644)
}
```

### 5. internal/errors/ - Error Handling

**File**: `internal/errors/errors.go`

```go
package errors

import "fmt"

// Error types
type ErrorType int

const (
	ErrorTypeNetwork ErrorType = iota
	ErrorTypeTimeout
	ErrorTypeValidation
	ErrorTypeConfig
	ErrorTypeIO
)

// CustomError represents an application error
type CustomError struct {
	Type    ErrorType
	Message string
	Cause   error
}

func (e *CustomError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func NewNetworkError(msg string, cause error) *CustomError {
	return &CustomError{Type: ErrorTypeNetwork, Message: msg, Cause: cause}
}

func NewTimeoutError(msg string) *CustomError {
	return &CustomError{Type: ErrorTypeTimeout, Message: msg}
}

func NewValidationError(msg string) *CustomError {
	return &CustomError{Type: ErrorTypeValidation, Message: msg}
}

// Collector aggregates errors during execution
type Collector struct {
	errors []error
}

func NewCollector() *Collector {
	return &Collector{
		errors: make([]error, 0),
	}
}

func (c *Collector) Add(err error) {
	if err != nil {
		c.errors = append(c.errors, err)
	}
}

func (c *Collector) HasErrors() bool {
	return len(c.errors) > 0
}

func (c *Collector) Errors() []error {
	return c.errors
}
```

### 6. internal/app/ - Application Context

**File**: `internal/app/context.go`

```go
package app

import (
	"github.com/NASHEDIxCODER/gospyder/internal/config"
	"github.com/NASHEDIxCODER/gospyder/internal/errors"
	"github.com/NASHEDIxCODER/gospyder/internal/logger"
	"github.com/NASHEDIxCODER/gospyder/internal/output"
	"github.com/NASHEDIxCODER/gospyder/internal/registry"
	"github.com/NASHEDIxCODER/gospyder/internal/workspace"
	"net/http"
	"sync"
)

var (
	globalContext *AppContext
	contextMutex  sync.Mutex
)

// AppContext holds all application-level services
type AppContext struct {
	Config      *config.Config
	Logger      *logger.Logger
	Formatter   *output.Formatter
	Workspace   *workspace.Workspace
	Registry    *registry.Registry
	HTTPClient  *http.Client
	Errors      *errors.Collector
}

// Initialize creates and stores global application context
func Initialize(cfg *config.Config) error {
	contextMutex.Lock()
	defer contextMutex.Unlock()

	logger := logger.New(cfg.Verbose)
	formatter := output.New(cfg.Output.Format, cfg.Output.Colors)
	errCollector := errors.NewCollector()
	reg := registry.New()

	globalContext = &AppContext{
		Config:     cfg,
		Logger:     logger,
		Formatter:  formatter,
		Registry:   reg,
		HTTPClient: &http.Client{},
		Errors:     errCollector,
	}

	return nil
}

// Global returns the global application context
func Global() *AppContext {
	contextMutex.Lock()
	defer contextMutex.Unlock()

	if globalContext == nil {
		panic("application context not initialized")
	}

	return globalContext
}

// Cleanup cleans up resources
func Cleanup() {
	contextMutex.Lock()
	defer contextMutex.Unlock()

	if globalContext != nil && globalContext.HTTPClient != nil {
		globalContext.HTTPClient.CloseIdleConnections()
	}
}
```

---

## 🔄 Refactored Module Examples

### How Existing Modules Become Registry Modules

**Before** (pkg/enum/engine.go - Current):
```go
type Engine struct { ... }
func (e *Engine) Run(ctx context.Context, target string, wordlist string, mode EnumMode) { ... }
```

**After** (pkg/enum/module.go - Refactored):
```go
type Module struct {
	engine *Engine
}

func (m *Module) Name() string {
	return "enum"
}

func (m *Module) Description() string {
	return "Subdomain enumeration via active and passive discovery"
}

func (m *Module) Run(ctx context.Context, opts registry.Options) error {
	target := opts.Flags["target"].(string)
	wordlist := opts.Flags["wordlist"].(string)
	mode := opts.Flags["mode"].(string)

	opts.Logger.Info("Starting subdomain enumeration for %s", target)

	result, err := m.engine.Run(ctx, target, wordlist, parseMode(mode))
	if err != nil {
		return err
	}

	opts.Logger.Info("Found %d subdomains", len(result))
	return nil
}
```

---

## 🆕 Crawler Module Architecture

**File**: `internal/crawler/crawler.go` (Not implemented, architecture only)

```go
package crawler

import (
	"context"
	"time"
)

type Crawler interface {
	Name() string
	Crawl(ctx context.Context, opts CrawlOptions) (*CrawlResult, error)
}

type CrawlOptions struct {
	Target      string
	Depth       int
	Concurrency int
	Timeout     time.Duration
	UserAgent   string
	Filters     CrawlFilters
}

type CrawlResult struct {
	URLs            []string
	Forms           []Form
	JavaScripts     []JS
	Parameters      []Parameter
	GraphQLEndpoint string
	Emails          []string
	Comments        []string
	Technologies    []string
}

type Form struct {
	URL     string
	Method  string
	Action  string
	Inputs  []FormInput
}

type JS struct {
	URL    string
	Source string
}

type Parameter struct {
	Name  string
	Value string
	URL   string
}

type CrawlFilters struct {
	AllowPatterns []string
	DenyPatterns  []string
	InternalOnly  bool
}

// Crawler will be used by multiple future modules:
// - Phase 2.7: URL Discovery
// - Phase 3: JavaScript Recon
// - Phase 3.5: Parameter Discovery
// - Phase 3.7: GraphQL Detection
```

---

## 📋 Implementation Checklist for Phase 0

### Foundation Packages
- [ ] `internal/registry/module.go` - Module interface
- [ ] `internal/registry/registry.go` - Registry implementation
- [ ] `internal/config/config.go` - Configuration
- [ ] `internal/logger/logger.go` - Logging
- [ ] `internal/output/formatter.go` - Formatting
- [ ] `internal/output/colors.go` - Colors
- [ ] `internal/workspace/workspace.go` - Project management
- [ ] `internal/errors/errors.go` - Error handling
- [ ] `internal/app/context.go` - App context/DI

### Module Refactoring
- [ ] `pkg/enum/module.go` - Enum as module
- [ ] `pkg/scanner/portscan_module.go` - Port scanner as module
- [ ] `pkg/scanner/fuzzer_module.go` - Fuzzer as module
- [ ] `pkg/scanner/waf_module.go` - WAF as module

### Command Handling
- [ ] `cmd/gospyder/main.go` - Refactored entry point
- [ ] `cmd/gospyder/handlers/handler.go` - Base handler
- [ ] `cmd/gospyder/handlers/enum.go` - Enum handler
- [ ] `cmd/gospyder/handlers/ports.go` - Ports handler
- [ ] `cmd/gospyder/handlers/fuzz.go` - Fuzz handler
- [ ] `cmd/gospyder/handlers/waf.go` - WAF handler

### Testing Foundation
- [ ] `tests/fixtures.go` - Test helpers
- [ ] `tests/mocks/logger.go` - Mock logger
- [ ] `tests/mocks/config.go` - Mock config
- [ ] Example tests
- [ ] Test data fixtures

### Backward Compatibility
- [ ] Legacy flag mapping
- [ ] Existing CLI still works
- [ ] All outputs unchanged

### Documentation
- [ ] Update README.md
- [ ] Create ARCHITECTURE.md
- [ ] Add CLI examples
- [ ] Document module interface

---

## ✅ Success Criteria for Phase 0

**Functional**:
- ✅ All foundation packages created and tested
- ✅ Module registry working
- ✅ Existing modules converted to registry modules
- ✅ New command architecture functional
- ✅ All existing CLI commands still work
- ✅ All output formats unchanged

**Code Quality**:
- ✅ No circular dependencies
- ✅ Clear separation of concerns
- ✅ All packages documented
- ✅ Example usage provided
- ✅ Error handling consistent
- ✅ Logging working across all modules

**Testing**:
- ✅ Test framework set up
- ✅ Mock implementations ready
- ✅ Sample tests passing
- ✅ Integration tests passing

**Backward Compatibility**:
- ✅ Old CLI flags work
- ✅ Old output formats work
- ✅ No breaking changes
- ✅ Migration guide documented

---

## 🎯 After Phase 0 Completion

### Deliverables
1. **PHASE_0_SUMMARY.md** - Refactoring summary
2. **ARCHITECTURE_UPDATED.md** - New architecture diagram
3. **MIGRATION_GUIDE.md** - For users/contributors
4. **API_DOCUMENTATION.md** - Module interface docs

### Verification Script
```bash
# All should pass
go build -o gospyder ./cmd/gospyder/
./gospyder -h
./gospyder enum -h
./gospyder ports -h
./gospyder fuzz -h
./gospyder waf -h
./gospyder list-modules

# Test old compatibility
./gospyder -d example.com -enum
./gospyder -d example.com -ports
```

### Ready for Phase 1
After Phase 0 approval, we'll implement:
- HTTP Probe Engine
- Live Host Detection
- Technology Fingerprinting

Using the clean, scalable architecture established in Phase 0.

---

**Status**: Ready for Phase 0 implementation
