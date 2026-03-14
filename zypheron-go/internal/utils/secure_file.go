package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

// SecureFileWriter provides utilities for writing files with secure permissions
type SecureFileWriter struct {
	umask int
}

// NewSecureFileWriter creates a new secure file writer
func NewSecureFileWriter() *SecureFileWriter {
	return &SecureFileWriter{
		umask: 0077, // Restrictive umask: only owner has permissions
	}
}

// WriteSecure writes data to a file with owner-only permissions (0600)
// This is suitable for security-sensitive files like scan results, secrets, etc.
func (w *SecureFileWriter) WriteSecure(filename string, data []byte) error {
	// Ensure parent directory exists with secure permissions
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Set restrictive umask
	oldMask := setUmask(w.umask)
	defer setUmask(oldMask)

	// Write file with secure permissions
	// The umask ensures the file is created with restricted permissions
	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	// Explicitly chmod to ensure correct permissions
	// (defense in depth - ensures permissions are correct even if umask fails)
	if err := os.Chmod(filename, 0600); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	return nil
}

// WritePublic writes data to a file with read-only permissions for others (0644)
// This is suitable for non-sensitive output files
func (w *SecureFileWriter) WritePublic(filename string, data []byte) error {
	// Ensure parent directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file with public read permissions
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// AppendSecure appends data to a file with owner-only permissions
func (w *SecureFileWriter) AppendSecure(filename string, data []byte) error {
	// Ensure file exists with secure permissions
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		// File doesn't exist, create it securely
		return w.WriteSecure(filename, data)
	}

	// Open file for appending
	oldMask := setUmask(w.umask)
	defer setUmask(oldMask)

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	// Ensure permissions are correct
	if err := os.Chmod(filename, 0600); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	return nil
}

// CreateTempSecure creates a temporary file with secure permissions
func (w *SecureFileWriter) CreateTempSecure(dir, pattern string) (*os.File, error) {
	// Set restrictive umask
	oldMask := setUmask(w.umask)
	defer setUmask(oldMask)

	// Ensure directory exists with secure permissions
	if dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Create temp file
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	// Ensure permissions are correct
	if err := os.Chmod(file.Name(), 0600); err != nil {
		file.Close()
		os.Remove(file.Name())
		return nil, fmt.Errorf("failed to set permissions: %w", err)
	}

	return file, nil
}

// ValidateFilePermissions checks if a file has secure permissions (owner-only)
func ValidateFilePermissions(filename string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("cannot stat file: %w", err)
	}

	perm := info.Mode().Perm()

	// Check if file is world-readable or world-writable or group-readable or group-writable
	if perm&0077 != 0 {
		return fmt.Errorf("file has insecure permissions: %o (expected 0600)", perm)
	}

	return nil
}

// EnforceStartupUmask sets a restrictive umask at application startup
// Call this in main() to ensure all file operations default to secure permissions
func EnforceStartupUmask() int {
	return setUmask(0077)
}

// setUmask sets the umask and returns the old value
// Note: This is platform-specific
func setUmask(mask int) int {
	// This is a simple wrapper that could be extended for cross-platform support
	return syscallUmask(mask)
}
