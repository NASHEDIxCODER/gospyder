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

// Success wraps message with green success color
func Success(msg string) string {
	return ColorGreen + "✓ " + msg + ColorReset
}

// Error wraps message with red error color
func Error(msg string) string {
	return ColorRed + "✗ " + msg + ColorReset
}

// Info wraps message with blue info color
func Info(msg string) string {
	return ColorBlue + "ℹ " + msg + ColorReset
}

// Warn wraps message with yellow warning color
func Warn(msg string) string {
	return ColorYellow + "⚠ " + msg + ColorReset
}
