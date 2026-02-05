package crypto

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

const (
	saltFileName = "salt"
	saltSize     = 16 // 128 bits (recommended minimum)
)

// GetOrCreateSalt returns a user-specific salt for key derivation.
// The salt is stored in ~/.keyopol/salt and is generated on first use.
// Salt is NOT secret - it's stored in plaintext to prevent rainbow table attacks.
func GetOrCreateSalt() ([]byte, error) {
	saltPath, err := getSaltPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get salt path: %w", err)
	}

	// Check if salt file exists
	if _, err := os.Stat(saltPath); err == nil {
		// Salt exists, read it
		salt, err := os.ReadFile(saltPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read salt: %w", err)
		}

		// Validate salt size
		if len(salt) != saltSize {
			return nil, fmt.Errorf("invalid salt size: expected %d bytes, got %d", saltSize, len(salt))
		}

		return salt, nil
	}

	// Salt doesn't exist, generate new one
	return generateAndSaveSalt(saltPath)
}

// generateAndSaveSalt creates a new random salt and saves it to disk
func generateAndSaveSalt(saltPath string) ([]byte, error) {
	// Generate cryptographically secure random salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}

	// Ensure config directory exists
	configDir := filepath.Dir(saltPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write salt to file (plaintext is OK - salt is not secret)
	if err := os.WriteFile(saltPath, salt, 0644); err != nil {
		return nil, fmt.Errorf("failed to write salt: %w", err)
	}

	return salt, nil
}

// getSaltPath returns the full path to the salt file
func getSaltPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	return filepath.Join(homeDir, ".keyopol", saltFileName), nil
}

// ResetSalt removes the existing salt file. USE WITH CAUTION!
// This will make all existing encrypted secrets unrecoverable.
func ResetSalt() error {
	saltPath, err := getSaltPath()
	if err != nil {
		return err
	}

	if err := os.Remove(saltPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove salt: %w", err)
	}

	return nil
}
