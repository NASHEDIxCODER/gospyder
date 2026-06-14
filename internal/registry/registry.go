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
func (r *Registry) Run(ctx context.Context, name string, opts Options) (*Result, error) {
	module, err := r.Get(name)
	if err != nil {
		return nil, err
	}

	return module.Run(ctx, opts)
}

// Count returns number of registered modules
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.modules)
}

// All returns all registered modules (for iteration)
func (r *Registry) All() map[string]Module {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return a copy to prevent external mutation
	result := make(map[string]Module)
	for k, v := range r.modules {
		result[k] = v
	}
	return result
}
