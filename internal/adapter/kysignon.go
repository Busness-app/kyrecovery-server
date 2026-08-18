package adapter

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"os"

	"kyrecovery-server/internal/capsule"
	_ "modernc.org/sqlite"
)

// KySignOnRecipe returns the standard declarative recipe for KySignOn.
func KySignOnRecipe() GenericRecipe {
	return GenericRecipe{
		ServiceName:  "kysignon",
		IncludePaths: []string{"data", "keys", "config"},
		Dependencies: []capsule.Dependency{
			{Name: "KY_ISSUER", Type: "env", Required: true, Description: "KySignOn OIDC Issuer URL"},
			{Name: "KY_ADMIN_EMAIL", Type: "env", Required: true, Description: "Administrator contact email"},
			{Name: "PORT_8080", Type: "port", Required: true, Description: "KySignOn main HTTP listener port"},
		},
		VerifyChecks: GenericVerifyRules{
			CheckSQLiteDatabases: true,
			ValidateCertificates: true,
			ValidateJSONFiles:    true,
			RequiredFiles:        []string{"data/kysignon.db", "keys/token_signing_rsa.key"},
		},
	}
}

// KySignOnAdapter implements recovery capture and restore verification using the declarative generic recipe.
type KySignOnAdapter struct {
	*GenericAdapter
}

// NewKySignOnAdapter creates a new KySignOn recovery adapter driven by declarative rules.
func NewKySignOnAdapter() *KySignOnAdapter {
	return &KySignOnAdapter{
		GenericAdapter: NewGenericAdapter(KySignOnRecipe()),
	}
}

// Helper generators for tests and mock demo captures
func generateSampleKySignOnDB() ([]byte, error) {
	tmpFile, err := os.CreateTemp("", "kysignon-sample-*.db")
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
	CREATE TABLE users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		name TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user',
		status TEXT NOT NULL DEFAULT 'active',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT INTO users (id, email, name, role, status) VALUES 
		('usr-001', 'admin@kysecurity.local', 'Primary Administrator', 'admin', 'active'),
		('usr-002', 'operator@kysecurity.local', 'Security Operator', 'operator', 'active');
	`
	if _, err := dbConn.Exec(schema); err != nil {
		dbConn.Close()
		return nil, err
	}
	dbConn.Close()

	return os.ReadFile(tmpPath)
}

func generateSampleRSAKeyPEM() ([]byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der := x509.MarshalPKCS1PrivateKey(privKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}
