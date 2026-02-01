package crypto

import (
	"crypto/md5"
	"encoding/hex"
	"os"
)

func GetMasterKeyLegacy() string {
	k := os.Getenv("KEYOPOL_MASTER_KEY")
	if k == "" {
		k = "default-insecure-key-change-me"
	}
	h := md5.New()
	h.Write([]byte(k))
	return hex.EncodeToString(h.Sum(nil))
}

// Encrypt wraps the new Argon2-based encryption
func Encrypt(data, passphrase string) string {
	encryptor := NewLocalEncryptor()
	encrypted, err := encryptor.Encrypt(data, passphrase)
	if err != nil {
		// Legacy behavior swallowed errors, so we log and return empty (or handle better if possible)
		// For TUI crash prevention, returning empty string is safer than panic,
		// though ideally we should propagate errors.
		return ""
	}
	return encrypted
}

// Decrypt wraps the enhanced decryption (supports both Argon2 and Legacy MD5)
func Decrypt(data, passphrase string) string {
	return DecryptEnhanced(data, passphrase)
}
