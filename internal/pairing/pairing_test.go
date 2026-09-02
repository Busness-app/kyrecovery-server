package pairing_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/adapter"
	"github.com/Busness-app/kyrecovery-server/internal/capsule"
	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/pairing"
)

func TestPairingAndSelfDeclaredIngest(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	// 1. Admin generates pairing code
	pending, err := pairing.GeneratePairingCode(ctx, database, 10*time.Minute, "auto-declare", "New App")
	if err != nil {
		t.Fatalf("GeneratePairingCode failed: %v", err)
	}
	if len(pending.PairingCode) != 6 || pending.Status != "pending" {
		t.Fatalf("unexpected pending record: %+v", pending)
	}

	// 2. Client product claims the pairing code
	claimed, err := database.ClaimPairingCode(ctx, pending.PairingCode, "kynotes", "KyNotes Production Cluster")
	if err != nil {
		t.Fatalf("ClaimPairingCode failed: %v", err)
	}
	if claimed.Status != "paired" || claimed.ServiceName != "kynotes" {
		t.Fatalf("claimed app mismatch: %+v", claimed)
	}

	// 3. Verify token lookup
	tokenApp, err := database.GetPairedAppByToken(ctx, claimed.APIToken)
	if err != nil || tokenApp == nil {
		t.Fatalf("GetPairedAppByToken failed: %v", err)
	}
	if tokenApp.ID != claimed.ID {
		t.Fatalf("token app ID mismatch")
	}

	// 4. Test Ingest of Self-Declared Backup
	mockDB := base64.StdEncoding.EncodeToString([]byte("mock-db-content-12345"))
	mockConf := base64.StdEncoding.EncodeToString([]byte(`{"notes_version": "2.0"}`))

	payload := pairing.SelfDeclaredBackupPayload{
		ServiceName: "kynotes",
		AppName:     "KyNotes Prod",
		AppVersion:  "v2.1.0",
		Threshold:   2,
		TotalShares: 3,
		Dependencies: []capsule.Dependency{
			{Name: "PORT_8087", Type: "port", Required: true, Description: "KyNotes port"},
		},
		VerifyRecipe: adapter.GenericVerifyRules{
			CheckSQLiteDatabases: true,
			ValidateJSONFiles:    true,
		},
		Files: map[string]string{
			"data/notes.db":   mockDB,
			"config/app.json": mockConf,
		},
	}

	files, deps, recipe, err := pairing.IngestSelfDeclaredBackup(payload, pairing.DefaultIngestLimits())
	if err != nil {
		t.Fatalf("IngestSelfDeclaredBackup failed: %v", err)
	}
	if len(files) != 2 || len(deps) != 1 || recipe.ServiceName != "kynotes" {
		t.Fatalf("ingested payload mismatch: files=%d, deps=%d, recipe=%+v", len(files), len(deps), recipe)
	}
}

// The published wire format (files array, dependency declaration object,
// verification_recipe key) must decode to the same payload as the compact form.
func TestSelfDeclaredPayloadAcceptsPublishedWireFormat(t *testing.T) {
	body := []byte(`{
		"service_name": "kynotes",
		"app_version": "1.4.2",
		"threshold": 2,
		"total_shares": 3,
		"files": [
			{"path": "data/notes.db", "data_base64": "bW9jay1kYg==", "mode": 384},
			{"path": "certs/jwt_signing.key", "data_base64": "bW9jay1rZXk=", "mode": 384}
		],
		"dependencies": {"ports": [8080], "env": ["KY_ISSUER", "DATABASE_URL"]},
		"verification_recipe": {
			"check_sqlite_integrity": true,
			"sqlite_paths": ["data/notes.db"],
			"test_signing_key_path": "certs/jwt_signing.key",
			"signing_algorithm": "rsa",
			"required_files": ["data/notes.db"],
			"expected_env": ["KY_ISSUER", "DATABASE_URL"],
			"expected_ports": [8080]
		}
	}`)

	var payload pairing.SelfDeclaredBackupPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decoding published wire format failed: %v", err)
	}

	files, deps, recipe, err := pairing.IngestSelfDeclaredBackup(payload, pairing.DefaultIngestLimits())
	if err != nil {
		t.Fatalf("IngestSelfDeclaredBackup failed: %v", err)
	}
	if len(files) != 2 || string(files["data/notes.db"]) != "mock-db" {
		t.Fatalf("files array form decoded wrong: %v", files)
	}
	if len(deps) != 3 {
		t.Fatalf("expected 3 declared dependencies, got %d: %+v", len(deps), deps)
	}
	var ports, envs int
	for _, dep := range deps {
		switch dep.Type {
		case "port":
			ports++
		case "env":
			envs++
		}
	}
	if ports != 1 || envs != 2 {
		t.Fatalf("dependency declaration mapped wrong: ports=%d envs=%d", ports, envs)
	}
	if !recipe.VerifyChecks.CheckSQLiteIntegrity ||
		recipe.VerifyChecks.TestSigningKeyPath != "certs/jwt_signing.key" ||
		recipe.VerifyChecks.SigningAlgorithm != "rsa" ||
		len(recipe.VerifyChecks.SQLitePaths) != 1 ||
		len(recipe.VerifyChecks.ExpectedEnv) != 2 ||
		len(recipe.VerifyChecks.ExpectedPorts) != 1 {
		t.Fatalf("verification_recipe not applied: %+v", recipe.VerifyChecks)
	}
}

// Paths that would escape the restore directory are refused at the API boundary.
func TestSelfDeclaredIngestRejectsPathTraversal(t *testing.T) {
	for _, bad := range []string{"../../etc/cron.d/pwn", "/etc/passwd", "data/../../escape"} {
		payload := pairing.SelfDeclaredBackupPayload{
			ServiceName: "kynotes",
			Files:       pairing.BackupFiles{bad: base64.StdEncoding.EncodeToString([]byte("x"))},
		}
		if _, _, _, err := pairing.IngestSelfDeclaredBackup(payload, pairing.DefaultIngestLimits()); err == nil {
			t.Fatalf("expected rejection of unsafe path %q", bad)
		}
	}
}
