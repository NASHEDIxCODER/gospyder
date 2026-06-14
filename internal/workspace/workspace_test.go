package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewForTargetSanitizesAndSavesResult(t *testing.T) {
	root := t.TempDir()
	ws := NewForTarget(root, "https://example.com:8443/path")

	if !strings.HasPrefix(ws.Path, root) {
		t.Fatalf("workspace path %q does not start with root %q", ws.Path, root)
	}
	if strings.Contains(ws.Path, "https://") || strings.Contains(ws.Path, "/path") {
		t.Fatalf("workspace path was not sanitized: %q", ws.Path)
	}

	saved, err := ws.SaveResult("enum", "subdomains.txt", []byte("www.example.com\n"))
	if err != nil {
		t.Fatalf("SaveResult() error = %v", err)
	}

	data, err := os.ReadFile(saved)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "www.example.com\n" {
		t.Fatalf("saved data = %q, want subdomain line", string(data))
	}

	if _, err := os.Stat(filepath.Join(ws.Path, "metadata.json")); err != nil {
		t.Fatalf("metadata.json missing: %v", err)
	}
}

func TestSanitizeTargetFallback(t *testing.T) {
	if got := SanitizeTarget("!!!"); got != "unknown-target" {
		t.Fatalf("SanitizeTarget() = %q, want unknown-target", got)
	}
}
