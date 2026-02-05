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
	"strings"

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

func (e *LocalEncryptor) Encrypt(plaintext, passphrase string) (string, error) {
	// 1. Get/Create local salt
	salt, err := GetOrCreateSalt()
	if err != nil {
		return "", fmt.Errorf("failed to get salt: %w", err)
	}

	// 2. Derive key using this salt
	key := deriveKey(passphrase, salt)

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

	// 3. Format: <hex_salt>:<hex_ciphertext>
	// This makes the secret portable across machines
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(ciphertext), nil
}

func (e *LocalEncryptor) Decrypt(ciphertextHex, passphrase string) (string, error) {
	var salt []byte
	var actualCiphertextHex string

	// 1. Check if the ciphertext has a portable salt prefix (格式: salt:ciphertext)
	if strings.Contains(ciphertextHex, ":") {
		parts := strings.Split(ciphertextHex, ":")
		if len(parts) == 2 {
			s, err := hex.DecodeString(parts[0])
			if err == nil {
				salt = s
				actualCiphertextHex = parts[1]
			}
		}
	}

	// 2. Fallback to local machine salt if no portable salt is found (backward compatibility)
	if salt == nil {
		s, err := GetOrCreateSalt()
		if err != nil {
			return "", fmt.Errorf("failed to get local salt: %w", err)
		}
		salt = s
		actualCiphertextHex = ciphertextHex
	}

	// 3. Derive key and decrypt
	key := deriveKey(passphrase, salt)

	ciphertext, err := hex.DecodeString(actualCiphertextHex)
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

// deriveKey derives a 32-byte AES key from a passphrase and salt using Argon2
func deriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(passphrase),
		salt,
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
