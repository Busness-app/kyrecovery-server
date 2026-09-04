package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

const (
	KeyLength   = 32 // 256-bit AES key
	NonceLength = 12 // Standard GCM nonce length
)

// GenerateRandomBytes returns cryptographically secure random bytes of length n.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// EncryptAESGCM encrypts plaintext with the given 256-bit key and returns (ciphertext, nonce, error).
// An authenticated additional data (AAD) slice may optionally be provided.
func EncryptAESGCM(plaintext []byte, key []byte, additionalData []byte) ([]byte, []byte, error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("invalid key size: got %d bytes, expected 32 bytes", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM AEAD: %w", err)
	}
	nonce, err := GenerateRandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nonce, nil
}

// DecryptAESGCM decrypts ciphertext using AES-256-GCM with key, nonce, and optional AAD.
func DecryptAESGCM(ciphertext []byte, key []byte, nonce []byte, additionalData []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: got %d bytes, expected 32 bytes", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM AEAD: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: got %d, expected %d", len(nonce), gcm.NonceSize())
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, errors.New("decryption failed: authentication tag mismatch or corrupt ciphertext")
	}
	return plaintext, nil
}

// ComputeSHA256 returns hex string or raw hash of data.
func ComputeSHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
