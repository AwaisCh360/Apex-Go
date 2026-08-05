package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

const SecretFileMode = 0600

// WriteSecretText securely writes text to a file with 0600 permissions using an atomic rename.
func WriteSecretText(path string, text string) error {
	// Create parent directories if they don't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directories for secret file: %w", err)
	}

	// Prepare temporary file path
	tmpPath := path + ".tmp"
	_ = os.Remove(tmpPath) // Ensure it's clean before starting

	// Create new temporary file securely
	file, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, SecretFileMode)
	if err != nil {
		return fmt.Errorf("failed to create temporary secret file: %w", err)
	}

	// Write text
	if _, err := file.WriteString(text); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write to temporary secret file: %w", err)
	}

	// Close file before renaming
	if err := file.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to close temporary secret file: %w", err)
	}

	// Atomic rename to target path
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath) // Cleanup on rename error
		return fmt.Errorf("failed to atomic rename secret file: %w", err)
	}

	return nil
}
