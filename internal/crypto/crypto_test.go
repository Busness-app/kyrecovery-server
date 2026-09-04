package crypto_test

import (
	"bytes"
	"testing"

	"github.com/Busness-app/kyrecovery-server/internal/crypto"
)

func TestAESGCMEnvelope(t *testing.T) {
	key, err := crypto.GenerateRandomBytes(crypto.KeyLength)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}
	plaintext := []byte("capsule-database-and-secret-payload-test-content")
	aad := []byte("capsule-id-12345")

	ciphertext, nonce, err := crypto.EncryptAESGCM(plaintext, key, aad)
	if err != nil {
		t.Fatalf("EncryptAESGCM failed: %v", err)
	}

	decrypted, err := crypto.DecryptAESGCM(ciphertext, key, nonce, aad)
	if err != nil {
		t.Fatalf("DecryptAESGCM failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted text mismatch: got %q, expected %q", decrypted, plaintext)
	}

	// Test tamper detection
	tamperedCiphertext := append([]byte(nil), ciphertext...)
	tamperedCiphertext[0] ^= 0xFF
	if _, err := crypto.DecryptAESGCM(tamperedCiphertext, key, nonce, aad); err == nil {
		t.Fatalf("expected decryption error on tampered ciphertext")
	}
}

func TestArgon2PassphraseKDF(t *testing.T) {
	passphrase := "correct-horse-battery-staple"
	salt, err := crypto.GenerateRandomBytes(crypto.SaltLength)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}
	key1, err := crypto.DeriveKeyFromPassphrase(passphrase, salt)
	if err != nil {
		t.Fatalf("DeriveKeyFromPassphrase failed: %v", err)
	}
	key2, err := crypto.DeriveKeyFromPassphrase(passphrase, salt)
	if err != nil {
		t.Fatalf("DeriveKeyFromPassphrase second run failed: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatalf("Argon2id derivation is not deterministic for same salt and password")
	}
}
