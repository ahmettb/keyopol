package crypto

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// PromptMasterPassword securely prompts the user for their master password.
// The password is NOT echoed to the terminal for security.
// This is the recommended way to get the master password instead of environment variables.
func PromptMasterPassword(prompt string) (string, error) {
	if prompt == "" {
		prompt = "Enter master password: "
	}

	fmt.Print(prompt)

	// Read password without echo (works on Windows, Linux, macOS)
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	fmt.Println() // New line after password input

	password := string(passwordBytes)

	// Security: Zero out the byte array
	for i := range passwordBytes {
		passwordBytes[i] = 0
	}

	// Validate password
	password = strings.TrimSpace(password)
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	return password, nil
}

// PromptMasterPasswordWithConfirmation prompts for password twice and ensures they match.
// Used when creating a new master password or changing it.
func PromptMasterPasswordWithConfirmation() (string, error) {
	password1, err := PromptMasterPassword("Create master password: ")
	if err != nil {
		return "", err
	}

	password2, err := PromptMasterPassword("Confirm master password: ")
	if err != nil {
		return "", err
	}

	if password1 != password2 {
		return "", fmt.Errorf("passwords do not match")
	}

	return password1, nil
}

// GetMasterPasswordSecure gets master password securely.
// Priority:
// 1. If KEYOPOL_MASTER_KEY env var is set (for CI/CD), use it
// 2. Otherwise, prompt user (secure, recommended for interactive use)
func GetMasterPasswordSecure() (string, error) {
	// Check environment variable first (for automation/CI)
	envPassword := os.Getenv("KEYOPOL_MASTER_KEY")
	if envPassword != "" {
		// Warning: Using env var is less secure than prompt
		return envPassword, nil
	}

	// Interactive mode: Prompt user
	return PromptMasterPassword("Master password: ")
}

// SecureString represents a string that will be zeroed out when no longer needed
type SecureString struct {
	data []byte
}

// NewSecureString creates a new secure string that will be zeroed on cleanup
func NewSecureString(s string) *SecureString {
	return &SecureString{
		data: []byte(s),
	}
}

// String returns the string value
func (s *SecureString) String() string {
	return string(s.data)
}

// Destroy zeros out the underlying data
func (s *SecureString) Destroy() {
	for i := range s.data {
		s.data[i] = 0
	}
}
