package crypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SaveMasterKey persists master keys as JSON.
func SaveMasterKey(path string, key MasterKey) error {
	if err := key.Validate(); err != nil {
		return err
	}
	return writeJSON(path, key, 0o600)
}

// LoadMasterKey reads and validates master keys from JSON.
func LoadMasterKey(path string) (MasterKey, error) {
	var key MasterKey
	if err := readJSON(path, &key); err != nil {
		return MasterKey{}, err
	}
	if err := key.Validate(); err != nil {
		return MasterKey{}, err
	}
	return key, nil
}

// SaveClientState persists client state as JSON.
func SaveClientState(path string, state ClientState) error {
	if state.KeywordCounters == nil {
		state.KeywordCounters = make(map[string]uint64)
	}
	return writeJSON(path, state, 0o600)
}

// LoadClientState reads client state from JSON. If file does not exist, an empty state is returned.
func LoadClientState(path string) (ClientState, error) {
	var state ClientState
	if err := readJSON(path, &state); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewClientState(), nil
		}
		return ClientState{}, err
	}
	if state.KeywordCounters == nil {
		state.KeywordCounters = make(map[string]uint64)
	}
	return state, nil
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
