package mocks

import (
	"fmt"
	"io"
)

// MockLogger is a test logger that captures output
type MockLogger struct {
	messages []string
	writer   io.Writer
}

// NewMockLogger creates a new mock logger
func NewMockLogger() *MockLogger {
	return &MockLogger{
		messages: make([]string, 0),
	}
}

// Debug logs debug message
func (m *MockLogger) Debug(msg string, args ...interface{}) {
	m.messages = append(m.messages, fmt.Sprintf("[DEBUG] "+msg, args...))
}

// Info logs info message
func (m *MockLogger) Info(msg string, args ...interface{}) {
	m.messages = append(m.messages, fmt.Sprintf("[INFO] "+msg, args...))
}

// Warn logs warning message
func (m *MockLogger) Warn(msg string, args ...interface{}) {
	m.messages = append(m.messages, fmt.Sprintf("[WARN] "+msg, args...))
}

// Error logs error message
func (m *MockLogger) Error(msg string, args ...interface{}) {
	m.messages = append(m.messages, fmt.Sprintf("[ERROR] "+msg, args...))
}

// Fatal logs fatal message (doesn't exit in tests)
func (m *MockLogger) Fatal(msg string, args ...interface{}) {
	m.messages = append(m.messages, fmt.Sprintf("[FATAL] "+msg, args...))
}

// Messages returns captured messages
func (m *MockLogger) Messages() []string {
	return m.messages
}

// Contains checks if a message was logged
func (m *MockLogger) Contains(text string) bool {
	for _, msg := range m.messages {
		if msg == text || contains(msg, text) {
			return true
		}
	}
	return false
}

func contains(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
