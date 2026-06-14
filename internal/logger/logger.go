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

// Logger provides structured logging
type Logger struct {
	level     Level
	out       io.Writer
	verbosity bool
}

// New creates a new logger
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

// Debug logs debug level messages
func (l *Logger) Debug(msg string, args ...interface{}) {
	if l.level <= LevelDebug {
		l.log("DEBUG", msg, args...)
	}
}

// Info logs info level messages
func (l *Logger) Info(msg string, args ...interface{}) {
	if l.level <= LevelInfo {
		l.log("INFO", msg, args...)
	}
}

// Warn logs warning level messages
func (l *Logger) Warn(msg string, args ...interface{}) {
	if l.level <= LevelWarn {
		l.log("WARN", msg, args...)
	}
}

// Error logs error level messages
func (l *Logger) Error(msg string, args ...interface{}) {
	if l.level <= LevelError {
		l.log("ERROR", msg, args...)
	}
}

// Fatal logs fatal level messages and exits
func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.log("FATAL", msg, args...)
	os.Exit(1)
}

func (l *Logger) log(level, msg string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	formatted := fmt.Sprintf(msg, args...)
	fmt.Fprintf(l.out, "[%s] [%s] %s\n", timestamp, level, formatted)
}
