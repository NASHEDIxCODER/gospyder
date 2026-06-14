package workspace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Workspace represents a project workspace
type Workspace struct {
	Path     string
	Name     string
	Created  time.Time
	Metadata WorkspaceMetadata
}

// WorkspaceMetadata holds workspace metadata
type WorkspaceMetadata struct {
	Target      string                 `json:"target"`
	Created     time.Time              `json:"created"`
	LastUpdated time.Time              `json:"last_updated"`
	Modules     map[string]ModuleState `json:"modules"`
}

// ModuleState tracks module execution state
type ModuleState struct {
	LastRun    time.Time `json:"last_run"`
	Status     string    `json:"status"` // "success", "error", "pending"
	ResultFile string    `json:"result_file"`
}

// New creates a new workspace
func New(path string) *Workspace {
	now := time.Now()
	return &Workspace{
		Path:    path,
		Name:    filepath.Base(path),
		Created: now,
		Metadata: WorkspaceMetadata{
			Target:  filepath.Base(path),
			Created: now,
			Modules: make(map[string]ModuleState),
		},
	}
}

// NewForTarget creates a workspace under root using a filesystem-safe target name.
func NewForTarget(root, target string) *Workspace {
	ws := New(filepath.Join(root, SanitizeTarget(target)))
	ws.Metadata.Target = target
	return ws
}

// Initialize creates project directory structure
func (w *Workspace) Initialize() error {
	dirs := []string{
		w.Path,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	// Create metadata file
	return w.saveMetadata()
}

// SaveResult saves module results to a file in the workspace root.
func (w *Workspace) SaveResult(module, filename string, data []byte) (string, error) {
	if filename == "" {
		filename = module + ".txt"
	}
	if err := w.Initialize(); err != nil {
		return "", err
	}

	filePath := filepath.Join(w.Path, filename)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return "", err
	}

	// Update metadata
	w.Metadata.Modules[module] = ModuleState{
		LastRun:    time.Now(),
		Status:     "success",
		ResultFile: filePath,
	}
	w.Metadata.LastUpdated = time.Now()

	return filePath, w.saveMetadata()
}

// SanitizeTarget converts a target into a safe workspace directory name.
func SanitizeTarget(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.Trim(target, "/")
	if target == "" {
		return "unknown-target"
	}

	re := regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	safe := re.ReplaceAllString(target, "_")
	safe = strings.Trim(safe, "._-")
	if safe == "" {
		return "unknown-target"
	}
	return safe
}

func (w *Workspace) String() string {
	return fmt.Sprintf("%s%c", filepath.Clean(w.Path), os.PathSeparator)
}

// saveMetadata saves workspace metadata to file
func (w *Workspace) saveMetadata() error {
	metaPath := filepath.Join(w.Path, "metadata.json")
	data, err := json.MarshalIndent(w.Metadata, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metaPath, data, 0644)
}

// Load loads a workspace from disk
func Load(path string) (*Workspace, error) {
	ws := New(path)

	metaPath := filepath.Join(path, "metadata.json")
	if _, err := os.Stat(metaPath); err == nil {
		data, err := os.ReadFile(metaPath)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &ws.Metadata); err != nil {
			return nil, err
		}
	}

	return ws, nil
}
