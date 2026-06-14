package mocks

import (
	"github.com/NASHEDIxCODER/gospyder/internal/errors"
)

// MockErrorCollector is a test error collector
type MockErrorCollector struct {
	collector *errors.Collector
}

// NewMockErrorCollector creates a new mock error collector
func NewMockErrorCollector() *MockErrorCollector {
	return &MockErrorCollector{
		collector: errors.NewCollector(),
	}
}

// Add adds an error
func (m *MockErrorCollector) Add(err error) {
	m.collector.Add(err)
}

// HasErrors checks if there are errors
func (m *MockErrorCollector) HasErrors() bool {
	return m.collector.HasErrors()
}

// Errors returns collected errors
func (m *MockErrorCollector) Errors() []error {
	return m.collector.Errors()
}

// Count returns error count
func (m *MockErrorCollector) Count() int {
	return m.collector.Count()
}
