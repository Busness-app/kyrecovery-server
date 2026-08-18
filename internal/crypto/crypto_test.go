package crypto_test

import (
	"bytes"
	"testing"

	"kyrecovery-server/internal/crypto"
)

func TestShamirSecretSharing(t *testing.T) {
	secret := []byte("kyrecovery-super-secret-master-key-32b!!")
	threshold := 3
	total := 5

	shares, err := crypto.Split(secret, threshold, total)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}
	if len(shares) != total {
		t.Fatalf("expected %d shares, got %d", total, len(shares))
	}

	// Test exact threshold reconstruction with shares (0, 2, 4)
	subset := []crypto.Share{shares[0], shares[2], shares[4]}
	recovered, err := crypto.Combine(subset, threshold)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Fatalf("recovered secret mismatch: got %q, expected %q", recovered, secret)
	}

	// Test with another subset (1, 2, 3)
	subset2 := []crypto.Share{shares[1], shares[2], shares[3]}
	recovered2, err := crypto.Combine(subset2, threshold)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}
	if !bytes.Equal(recovered2, secret) {
		t.Fatalf("recovered secret mismatch: got %q, expected %q", recovered2, secret)
	}

	// Test failure with fewer than threshold shares
	insufficient := []crypto.Share{shares[0], shares[1]}
	if _, err := crypto.Combine(insufficient, threshold); err == nil {
		t.Fatalf("expected error when combining fewer than threshold shares")
	}

	// Test share string serialization and parsing
	str := shares[0].String()
	parsed, err := crypto.ParseShare(str)
	if err != nil {
		t.Fatalf("ParseShare failed: %v", err)
	}
	if parsed.Index != shares[0].Index || !bytes.Equal(parsed.Value, shares[0].Value) {
		t.Fatalf("parsed share does not match original")
	}
}

func TestAESGCMEnvelope(t *testing.T) {
	key, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey failed: %v", err)
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
