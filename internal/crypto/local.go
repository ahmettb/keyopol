package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	ErrDecryptionFailed  = errors.New("decryption failed")
)

// LocalEncryptor implements domain.Encryptor using AES-256-GCM
type LocalEncryptor struct{}

// NewLocalEncryptor creates a new local encryptor
func NewLocalEncryptor() *LocalEncryptor {
	return &LocalEncryptor{}
}

// Encrypt implements domain.Encryptor
func (e *LocalEncryptor) Encrypt(plaintext, passphrase string) (string, error) {
	// Derive AES key from passphrase using Argon2
	key := deriveKey(passphrase)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt implements domain.Encryptor
func (e *LocalEncryptor) Decrypt(ciphertextHex, passphrase string) (string, error) {
	key := deriveKey(passphrase)

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", ErrInvalidCiphertext
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plaintext), nil
}

// deriveKey derives a 32-byte AES key from a passphrase using Argon2
func deriveKey(passphrase string) []byte {
	// Get or create user-specific salt
	// This prevents rainbow table attacks and ensures each user has unique encryption keys
	salt, err := GetOrCreateSalt()
	if err != nil {
		// In production, this should return an error instead of panic
		// For now, maintain backward compatibility with existing behavior
		panic(fmt.Sprintf("Failed to get salt: %v", err))
	}

	return argon2.IDKey(
		[]byte(passphrase),
		salt,    // ✓ User-specific salt (stored in ~/.keyopol/salt)
		1,       // time parameter (iterations)
		64*1024, // memory parameter (64 MB)
		4,       // parallelism parameter
		32,      // key length (256 bits for AES-256)
	)
}

// GetMasterKey retrieves the master password securely.
// Priority:
// 1. Environment variable KEYOPOL_MASTER_KEY (for CI/CD)
// 2. Terminal prompt (secure, interactive)
func GetMasterKey() string {
	password, err := GetMasterPasswordSecure()
	if err != nil {
		// Fallback to default only for backward compatibility
		// TODO: Remove this in future versions
		fmt.Fprintf(os.Stderr, "Warning: Failed to get master password: %v\n", err)
		fmt.Fprintf(os.Stderr, "Using default password. This is INSECURE!\n")
		return "default-insecure-key-change-me"
	}
	return password
}

// Legacy functions for backward compatibility with existing code

// Encrypt using legacy MD5-based key derivation (deprecated)
// This is kept for decrypting existing secrets
func EncryptLegacy(data, passphrase string) string {
	encryptor := NewLocalEncryptor()
	encrypted, err := encryptor.Encrypt(data, passphrase)
	if err != nil {
		return ""
	}
	return encrypted
}

// Decrypt using enhanced Argon2-based key derivation
func DecryptEnhanced(data, passphrase string) string {
	encryptor := NewLocalEncryptor()
	decrypted, err := encryptor.Decrypt(data, passphrase)
	if err != nil {
		// Try legacy decryption for backward compatibility
		return decryptLegacy(data, passphrase)
	}
	return decrypted
}

// decryptLegacy attempts to decrypt using the old MD5-based method
func decryptLegacy(data, passphrase string) string {
	// This matches the original crypto.Decrypt implementation
	// using MD5 hash of passphrase as key
	h := md5.New()
	h.Write([]byte(passphrase))
	key := h.Sum(nil)

	ciphertext, err := hex.DecodeString(data)
	if err != nil {
		return "ERR_CORRUPT"
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "ERR_INVALID_KEY"
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "ERR_CIPHER"
	}

	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return "ERR_LENGTH"
	}

	nonce, ciphertext := ciphertext[:ns], ciphertext[ns:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "LOCKED"
	}

	return string(plain)
}
