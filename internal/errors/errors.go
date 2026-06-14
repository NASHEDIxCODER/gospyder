package errors

import (
	"fmt"
	"sync"
)

// ErrorType categorizes different error types
type ErrorType int

const (
	ErrorTypeNetwork ErrorType = iota
	ErrorTypeTimeout
	ErrorTypeValidation
	ErrorTypeConfig
	ErrorTypeIO
	ErrorTypeNotFound
	ErrorTypeUnknown
)

// CustomError represents an application error
type CustomError struct {
	Type    ErrorType
	Message string
	Cause   error
}

// Error returns the error message
func (e *CustomError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// NewNetworkError creates a network error
func NewNetworkError(msg string, cause error) *CustomError {
	return &CustomError{Type: ErrorTypeNetwork, Message: msg, Cause: cause}
}

// NewTimeoutError creates a timeout error
func NewTimeoutError(msg string) *CustomError {
	return &CustomError{Type: ErrorTypeTimeout, Message: msg}
}

// NewValidationError creates a validation error
func NewValidationError(msg string) *CustomError {
	return &CustomError{Type: ErrorTypeValidation, Message: msg}
}

// NewConfigError creates a config error
func NewConfigError(msg string, cause error) *CustomError {
	return &CustomError{Type: ErrorTypeConfig, Message: msg, Cause: cause}
}

// NewIOError creates an IO error
func NewIOError(msg string, cause error) *CustomError {
	return &CustomError{Type: ErrorTypeIO, Message: msg, Cause: cause}
}

// NewNotFoundError creates a not found error
func NewNotFoundError(msg string) *CustomError {
	return &CustomError{Type: ErrorTypeNotFound, Message: msg}
}

// Collector aggregates errors during execution
type Collector struct {
	errors []error
	mu     sync.Mutex
}

// NewCollector creates a new error collector
func NewCollector() *Collector {
	return &Collector{
		errors: make([]error, 0),
	}
}

// Add adds an error to the collection
func (c *Collector) Add(err error) {
	if err != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.errors = append(c.errors, err)
	}
}

// HasErrors checks if there are any errors
func (c *Collector) HasErrors() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.errors) > 0
}

// Errors returns all collected errors
func (c *Collector) Errors() []error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return a copy
	result := make([]error, len(c.errors))
	copy(result, c.errors)
	return result
}

// Count returns the number of collected errors
func (c *Collector) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.errors)
}

// Clear clears all collected errors
func (c *Collector) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errors = make([]error, 0)
}
