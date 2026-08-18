package adapter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"os"

	"kyrecovery-server/internal/capsule"
	_ "modernc.org/sqlite"
)

// KyPasswordRecipe returns the standard declarative recipe for KyPassword.
func KyPasswordRecipe() GenericRecipe {
	return GenericRecipe{
		ServiceName:  "kypassword",
		IncludePaths: []string{"data", "keys", "config"},
		Dependencies: []capsule.Dependency{
			{Name: "KY_VAULT_SALT", Type: "env", Required: true, Description: "Master vault derivation salt"},
			{Name: "PORT_8081", Type: "port", Required: true, Description: "KyPassword API listener port"},
		},
		VerifyChecks: GenericVerifyRules{
			CheckSQLiteDatabases: true,
			ValidateCertificates: true,
			ValidateJSONFiles:    true,
			RequiredFiles:        []string{"data/kypassword.db", "keys/vault_ecdsa.key"},
		},
	}
}

// KyPasswordAdapter implements recovery capture and restore verification using the declarative generic recipe.
type KyPasswordAdapter struct {
	*GenericAdapter
}

// NewKyPasswordAdapter creates a new KyPassword recovery adapter driven by declarative rules.
func NewKyPasswordAdapter() *KyPasswordAdapter {
	return &KyPasswordAdapter{
		GenericAdapter: NewGenericAdapter(KyPasswordRecipe()),
	}
}

// Helper generators for tests and mock demo captures
func generateSampleKyPasswordDB() ([]byte, error) {
	tmpFile, err := os.CreateTemp("", "kypassword-sample-*.db")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	dbConn, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE vaults (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		ciphertext_blob BLOB NOT NULL,
		nonce BLOB NOT NULL,
		version INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT INTO vaults (id, user_id, name, ciphertext_blob, nonce) VALUES 
		('vlt-001', 'usr-001', 'Primary Keyring', X'0102030405060708', X'aabbccddeeff001122334455');
	`
	if _, err := dbConn.Exec(schema); err != nil {
		dbConn.Close()
		return nil, err
	}
	dbConn.Close()

	return os.ReadFile(tmpPath)
}

func generateSampleECDSAKeyPEM() ([]byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}
