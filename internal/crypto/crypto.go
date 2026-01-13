package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
)

func GetMasterKey() string {
	k := os.Getenv("KEYOPOL_MASTER_KEY")
	if k == "" {
		k = "default-insecure-key-change-me"
	}
	h := md5.New()
	h.Write([]byte(k))
	return hex.EncodeToString(h.Sum(nil))
}

func Encrypt(data, passphrase string) string {
	block, _ := aes.NewCipher([]byte(passphrase))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return hex.EncodeToString(gcm.Seal(nonce, nonce, []byte(data), nil))
}

func Decrypt(data, passphrase string) string {
	key := []byte(passphrase)
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
