package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"keyopol-app/internal/domain"
)

// EnvelopeEncryptedSecret represents a secret encrypted using envelope encryption pattern.
// This is the AWS KMS best practice for encrypting data:
// 1. Generate a data encryption key (DEK) from KMS
// 2. Encrypt the secret with the DEK using AES-256-GCM
// 3. Store both the encrypted DEK and the ciphertext
// 4. To decrypt: decrypt the DEK with KMS, then decrypt the ciphertext with DEK
type EnvelopeEncryptedSecret struct {
	EncryptedDataKey string `json:"encryptedDataKey"` // Base64-encoded KMS-encrypted DEK
	Ciphertext       string `json:"ciphertext"`       // Base64-encoded AES-GCM ciphertext
	Nonce            string `json:"nonce"`            // Base64-encoded AES-GCM nonce
	Algorithm        string `json:"algorithm"`        // "AES-256-GCM"
	Version          string `json:"version"`          // Envelope encryption version (for future compatibility)
}

// EncryptWithEnvelope encrypts plaintext using envelope encryption with AWS KMS.
//
// Process:
// 1. Calls KMS GenerateDataKey to get a 256-bit data encryption key
// 2. Encrypts the plaintext with the data key using AES-256-GCM
// 3. Returns a JSON envelope containing the encrypted data key and ciphertext
// 4. The plaintext data key is zeroed out immediately after use
//
// This approach allows encryption of large secrets (>4KB) and reduces KMS API calls.
func EncryptWithEnvelope(ctx context.Context, plaintext string, kmsProvider domain.KMSProvider, kmsKeyID string) (string, error) {
	if kmsProvider == nil {
		return "", fmt.Errorf("KMS provider is required for envelope encryption")
	}

	if plaintext == "" {
		return "", fmt.Errorf("plaintext cannot be empty")
	}

	// Step 1: Generate a data encryption key from KMS
	// This returns both the plaintext DEK and the KMS-encrypted version
	plainDataKey, encryptedDataKey, err := kmsProvider.GenerateDataKey(ctx, kmsKeyID)
	if err != nil {
		return "", fmt.Errorf("failed to generate data key from KMS: %w", err)
	}

	// SECURITY: Zero out plaintext data key when done
	defer zeroBytes(plainDataKey)

	// Step 2: Encrypt the secret with the data key using AES-256-GCM
	block, err := aes.NewCipher(plainDataKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt plaintext
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Step 3: Create envelope structure
	envelope := EnvelopeEncryptedSecret{
		EncryptedDataKey: base64.StdEncoding.EncodeToString(encryptedDataKey),
		Ciphertext:       base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:            base64.StdEncoding.EncodeToString(nonce),
		Algorithm:        "AES-256-GCM",
		Version:          "1",
	}

	// Step 4: Serialize to JSON
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("failed to marshal envelope: %w", err)
	}

	return string(envelopeJSON), nil
}

// DecryptWithEnvelope decrypts a secret that was encrypted with envelope encryption.
//
// Process:
// 1. Parse the JSON envelope
// 2. Decrypt the data encryption key using KMS
// 3. Decrypt the ciphertext using the data key and AES-256-GCM
// 4. Return the plaintext secret
func DecryptWithEnvelope(ctx context.Context, envelopeJSON string, kmsProvider domain.KMSProvider) (string, error) {
	if kmsProvider == nil {
		return "", fmt.Errorf("KMS provider is required for envelope decryption")
	}

	if envelopeJSON == "" {
		return "", fmt.Errorf("envelope JSON cannot be empty")
	}

	// Step 1: Parse the envelope
	var envelope EnvelopeEncryptedSecret
	if err := json.Unmarshal([]byte(envelopeJSON), &envelope); err != nil {
		return "", fmt.Errorf("failed to parse envelope: %w", err)
	}

	// Validate envelope version
	if envelope.Version != "1" {
		return "", fmt.Errorf("unsupported envelope version: %s", envelope.Version)
	}

	// Validate algorithm
	if envelope.Algorithm != "AES-256-GCM" {
		return "", fmt.Errorf("unsupported encryption algorithm: %s", envelope.Algorithm)
	}

	// Step 2: Decrypt the data encryption key using KMS
	encryptedDataKey, err := base64.StdEncoding.DecodeString(envelope.EncryptedDataKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted data key: %w", err)
	}

	plainDataKey, err := kmsProvider.DecryptWithKMS(ctx, encryptedDataKey)
	if err != nil {
		return "", fmt.Errorf("KMS decryption failed: %w", err)
	}

	// SECURITY: Zero out plaintext data key when done
	defer zeroBytes(plainDataKey)

	// Step 3: Decrypt the ciphertext using the data key
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}

	block, err := aes.NewCipher(plainDataKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM mode: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}

// zeroBytes overwrites the byte slice with zeros to prevent sensitive data from lingering in memory.
// This is a defense-in-depth measure against memory dumps and swap files.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// IsEnvelopeEncrypted checks if a string is an envelope-encrypted secret
// by attempting to parse it as JSON with the expected structure.
func IsEnvelopeEncrypted(data string) bool {
	var envelope EnvelopeEncryptedSecret
	err := json.Unmarshal([]byte(data), &envelope)
	if err != nil {
		return false
	}

	// Check if it has the required fields
	return envelope.EncryptedDataKey != "" &&
		envelope.Ciphertext != "" &&
		envelope.Nonce != "" &&
		envelope.Algorithm != ""
}
