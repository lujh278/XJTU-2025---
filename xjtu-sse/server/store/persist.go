package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"searchable-encryption-go/server/sse"
)

// SaveState persists backend state as JSON.
func SaveState(path string, backend *InMemory) error {
	if backend == nil {
		return errors.New("backend is nil")
	}
	return writeJSON(path, backend.State(), 0o600)
}

// LoadState restores backend from JSON. Missing file yields empty backend.
func LoadState(path string) (*InMemory, error) {
	var state sse.State
	if err := readJSON(path, &state); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewInMemory(), nil
		}
		return nil, err
	}
	return NewInMemoryFromState(state), nil
}

func writeJSON(path string, value any, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write file %s: %w", path, err)
	}
	return nil
}

func readJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file %s: %w", path, err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("unmarshal json %s: %w", path, err)
	}
	return nil
}
