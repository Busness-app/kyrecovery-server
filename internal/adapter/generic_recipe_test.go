package adapter_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kyrecovery-server/internal/adapter"
	"kyrecovery-server/internal/capsule"

	_ "modernc.org/sqlite"
)

// buildRestoredService lays out a restored payload: a real SQLite database, a PEM
// signing key, and the declarative recipe that names both.
func buildRestoredService(t *testing.T, recipeJSON string, keyPEM []byte) string {
	t.Helper()
	dir := t.TempDir()

	for _, sub := range []string{"data", "certs"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0700); err != nil {
			t.Fatalf("MkdirAll %s failed: %v", sub, err)
		}
	}

	conn, err := sql.Open("sqlite", filepath.Join(dir, "data/app.db"))
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	if _, err := conn.Exec("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)"); err != nil {
		t.Fatalf("CREATE TABLE failed: %v", err)
	}
	conn.Close()

	if keyPEM != nil {
		if err := os.WriteFile(filepath.Join(dir, "certs/signing.key"), keyPEM, 0600); err != nil {
			t.Fatalf("WriteFile signing key failed: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "kyrecovery-recipe.json"), []byte(recipeJSON), 0600); err != nil {
		t.Fatalf("WriteFile recipe failed: %v", err)
	}
	return dir
}

func rsaKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func ecdsaKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey failed: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func checkByName(result *adapter.DrillResult, name string) *adapter.CheckItem {
	for i := range result.Checks {
		if result.Checks[i].Name == name {
			return &result.Checks[i]
		}
	}
	return nil
}

const recipeWithDeclaredChecks = `{
  "service_name": "kynotes",
  "verify_checks": {
    "check_sqlite_integrity": true,
    "sqlite_paths": ["data/app.db"],
    "test_signing_key_path": "certs/signing.key",
    "signing_algorithm": "%s",
    "required_files": ["data/app.db"],
    "expected_env": ["KY_ISSUER"],
    "expected_ports": [8080]
  }
}`

func declaredManifest() *capsule.Manifest {
	return &capsule.Manifest{
		CapsuleID:   "cap-kynotes-1",
		ServiceName: "kynotes",
		Dependencies: []capsule.Dependency{
			{Name: "KY_ISSUER", Type: "env", Required: true},
			{Name: "8080", Type: "port", Required: true},
		},
	}
}

func TestGenericRecipeDeclaredChecksPass(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		algorithm string
		keyPEM    []byte
	}{
		{"rsa", rsaKeyPEM(t)},
		{"ecdsa", ecdsaKeyPEM(t)},
	} {
		t.Run(tc.algorithm, func(t *testing.T) {
			dir := buildRestoredService(t, strings.Replace(recipeWithDeclaredChecks, "%s", tc.algorithm, 1), tc.keyPEM)

			result, err := adapter.NewGenericAdapter().VerifyRestore(ctx, dir, declaredManifest())
			if err != nil {
				t.Fatalf("VerifyRestore failed: %v", err)
			}
			if !result.Passed {
				t.Fatalf("expected drill to pass, got checks: %+v", result.Checks)
			}
			for _, name := range []string{"sqlite_check:data/app.db", "signing_key:certs/signing.key", "expected_env", "expected_ports"} {
				check := checkByName(result, name)
				if check == nil {
					t.Fatalf("declared check %q never ran: %+v", name, result.Checks)
				}
				if !check.Passed {
					t.Fatalf("declared check %q failed: %s", name, check.Message)
				}
			}
			// The explicit path check must not be repeated by the extension scan.
			var sqliteChecks int
			for _, check := range result.Checks {
				if check.Name == "sqlite_check:data/app.db" {
					sqliteChecks++
				}
			}
			if sqliteChecks != 1 {
				t.Fatalf("expected data/app.db checked once, got %d", sqliteChecks)
			}
		})
	}
}

func TestGenericRecipeDeclaredChecksCatchDamage(t *testing.T) {
	ctx := context.Background()
	recipe := strings.Replace(recipeWithDeclaredChecks, "%s", "rsa", 1)

	t.Run("unusable signing key", func(t *testing.T) {
		dir := buildRestoredService(t, recipe, rsaKeyPEM(t))
		keyPath := filepath.Join(dir, "certs/signing.key")
		data, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatalf("ReadFile failed: %v", err)
		}
		if err := os.WriteFile(keyPath, data[:len(data)/2], 0600); err != nil {
			t.Fatalf("WriteFile truncated key failed: %v", err)
		}

		result, err := adapter.NewGenericAdapter().VerifyRestore(ctx, dir, declaredManifest())
		if err != nil {
			t.Fatalf("VerifyRestore failed: %v", err)
		}
		if check := checkByName(result, "signing_key:certs/signing.key"); check == nil || check.Passed {
			t.Fatalf("truncated signing key should fail the drill: %+v", result.Checks)
		}
		if result.Passed {
			t.Fatal("drill passed despite an unusable signing key")
		}
	})

	t.Run("algorithm mismatch", func(t *testing.T) {
		dir := buildRestoredService(t, recipe, ecdsaKeyPEM(t))
		result, err := adapter.NewGenericAdapter().VerifyRestore(ctx, dir, declaredManifest())
		if err != nil {
			t.Fatalf("VerifyRestore failed: %v", err)
		}
		if check := checkByName(result, "signing_key:certs/signing.key"); check == nil || check.Passed {
			t.Fatalf("ECDSA key declared as rsa should fail: %+v", result.Checks)
		}
	})

	t.Run("dropped declarations", func(t *testing.T) {
		dir := buildRestoredService(t, recipe, rsaKeyPEM(t))
		manifest := declaredManifest()
		manifest.Dependencies = nil

		result, err := adapter.NewGenericAdapter().VerifyRestore(ctx, dir, manifest)
		if err != nil {
			t.Fatalf("VerifyRestore failed: %v", err)
		}
		for _, name := range []string{"expected_env", "expected_ports"} {
			if check := checkByName(result, name); check == nil || check.Passed {
				t.Fatalf("%s should fail when the manifest drops the declaration: %+v", name, result.Checks)
			}
		}
		if result.Passed {
			t.Fatal("drill passed despite missing declared dependencies")
		}
	})
}

// A required file that restores empty is a failed restore, not a satisfied one.
func TestGenericRecipeRequiredFileMustBeNonEmpty(t *testing.T) {
	dir := buildRestoredService(t, strings.Replace(recipeWithDeclaredChecks, "%s", "rsa", 1), rsaKeyPEM(t))
	if err := os.WriteFile(filepath.Join(dir, "data/app.db"), nil, 0600); err != nil {
		t.Fatalf("truncating database failed: %v", err)
	}

	result, err := adapter.NewGenericAdapter().VerifyRestore(context.Background(), dir, declaredManifest())
	if err != nil {
		t.Fatalf("VerifyRestore failed: %v", err)
	}
	check := checkByName(result, "required_file:data/app.db")
	if check == nil || check.Passed {
		t.Fatalf("empty required file should fail: %+v", result.Checks)
	}
	if !strings.Contains(check.Message, "empty") {
		t.Fatalf("expected an empty-file message, got %q", check.Message)
	}
}
