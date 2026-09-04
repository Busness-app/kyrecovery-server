// Package secrets manages the server key that protects credentials stored in SQLite.
//
// The key lives outside the database — in KYRECOVERY_SECRET_KEY or in a 0600 key file
// beside it — so a stolen database (or a replicated copy of one) yields no usable
// credentials. It does not protect against an attacker who already has the data
// directory or the running process.
package secrets

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Busness-app/ky-primitives/keyfile"
	"golang.org/x/crypto/hkdf"

	"github.com/Busness-app/kyrecovery-server/internal/crypto"
)

// EnvKey overrides the on-disk key file. Value must be 32 bytes, hex or base64.
const EnvKey = "KYRECOVERY_SECRET_KEY"

// KeyFileName is the key file created next to the SQLite database.
const KeyFileName = "secret.key"

const sealedPrefix = "enc:v1:"

// Keyring derives purpose-specific keys from a single 256-bit server key.
type Keyring struct {
	master []byte
	dir    string
}

// Load returns the keyring for dataDir, creating a new key file on first run.
// An empty dataDir yields an ephemeral key (in-memory databases only).
func Load(dataDir string) (*Keyring, error) {
	if key, ok, err := keyfile.FromEnv(EnvKey, crypto.KeyLength); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", EnvKey, err)
	} else if ok {
		return &Keyring{master: key, dir: dataDir}, nil
	}
	if dataDir == "" {
		return Ephemeral()
	}

	key, err := keyfile.LoadOrCreate(filepath.Join(dataDir, KeyFileName), crypto.KeyLength)
	if err != nil {
		return nil, err
	}
	return &Keyring{master: key, dir: dataDir}, nil
}

// Ephemeral returns a keyring backed by a random key that is never persisted.
func Ephemeral() (*Keyring, error) {
	key, err := crypto.GenerateRandomBytes(crypto.KeyLength)
	if err != nil {
		return nil, err
	}
	return &Keyring{master: key}, nil
}

func (k *Keyring) derive(info string) []byte {
	out := make([]byte, crypto.KeyLength)
	r := hkdf.New(sha256.New, k.master, nil, []byte(info))
	if _, err := io.ReadFull(r, out); err != nil {
		panic("secrets: hkdf failed: " + err.Error()) // sha256 HKDF cannot fail for 32 bytes
	}
	return out
}

// LedgerKey returns the HMAC key that binds audit events to this server.
func (k *Keyring) LedgerKey() []byte {
	return k.derive("kyrecovery/audit-ledger/v1")
}

// Seal encrypts a stored credential. Empty and already-sealed values pass through.
func (k *Keyring) Seal(plaintext string) (string, error) {
	if plaintext == "" || IsSealed(plaintext) {
		return plaintext, nil
	}
	ct, nonce, err := crypto.EncryptAESGCM([]byte(plaintext), k.derive("kyrecovery/db-secrets/v1"), nil)
	if err != nil {
		return "", err
	}
	return sealedPrefix + base64.StdEncoding.EncodeToString(append(nonce, ct...)), nil
}

// Open decrypts a value produced by Seal. A stored value that is not a sealed envelope is
// an error, not a credential: returning it unchanged would let anyone who can write the
// database choose a plaintext secret the server then uses as if it had sealed it itself.
// Empty is not a value and stays empty.
func (k *Keyring) Open(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if !IsSealed(stored) {
		return "", errors.New("stored secret is not sealed")
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, sealedPrefix))
	if err != nil || len(blob) <= crypto.NonceLength {
		return "", errors.New("corrupt sealed secret")
	}
	pt, err := crypto.DecryptAESGCM(blob[crypto.NonceLength:], k.derive("kyrecovery/db-secrets/v1"), blob[:crypto.NonceLength], nil)
	if err != nil {
		return "", fmt.Errorf("failed decrypting stored secret (wrong %s or key file?): %w", EnvKey, err)
	}
	return string(pt), nil
}

// IsSealed reports whether a stored value is already encrypted.
func IsSealed(s string) bool {
	return strings.HasPrefix(s, sealedPrefix)
}
