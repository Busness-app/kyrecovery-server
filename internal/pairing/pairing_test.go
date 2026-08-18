package pairing_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"kyrecovery-server/internal/adapter"
	"kyrecovery-server/internal/capsule"
	"kyrecovery-server/internal/db"
	"kyrecovery-server/internal/pairing"
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

	files, deps, recipe, err := pairing.IngestSelfDeclaredBackup(payload)
	if err != nil {
		t.Fatalf("IngestSelfDeclaredBackup failed: %v", err)
	}
	if len(files) != 2 || len(deps) != 1 || recipe.ServiceName != "kynotes" {
		t.Fatalf("ingested payload mismatch: files=%d, deps=%d, recipe=%+v", len(files), len(deps), recipe)
	}
}
