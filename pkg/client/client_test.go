package client_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kyrecovery-server/internal/audit"
	"kyrecovery-server/internal/auth"
	"kyrecovery-server/internal/db"
	"kyrecovery-server/internal/pairing"
	"kyrecovery-server/internal/server"
	"kyrecovery-server/pkg/client"
)

func TestClientSDKFlow(t *testing.T) {
	ctx := context.Background()

	// 1. Start test server
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	ledger := audit.NewLedger(database)
	srv, err := server.New(server.Config{
		Port:         0,
		DataDir:      t.TempDir(),
		DatabasePath: ":memory:",
		Auth:         auth.OIDCConfig{Enabled: false},
	}, database, ledger)
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}

	ts := httptest.NewServer(srv)
	defer ts.Close()

	// 2. Generate a pairing code on server
	pairedRecord, err := pairing.GeneratePairingCode(ctx, database, 15*time.Minute, "kybookmarks", "Pending App")
	if err != nil {
		t.Fatalf("GeneratePairingCode failed: %v", err)
	}

	// 3. Client claims pairing code using SDK
	c, claimResp, err := client.ClaimPairing(ctx, ts.URL, pairedRecord.PairingCode, "KyBookmarks Cluster Primary")
	if err != nil {
		t.Fatalf("ClaimPairing failed: %v", err)
	}
	if claimResp.APIToken == "" || claimResp.Status != "paired" {
		t.Fatalf("unexpected claim response: %+v", claimResp)
	}

	// 4. Create sample files in temp dir to push
	tempDir := t.TempDir()
	dataDir := filepath.Join(tempDir, "data")
	configDir := filepath.Join(tempDir, "config")
	_ = os.MkdirAll(dataDir, 0700)
	_ = os.MkdirAll(configDir, 0700)

	_ = os.WriteFile(filepath.Join(dataDir, "bookmarks.json"), []byte(`[{"title": "KySecurity", "url": "https://kysecurity.org"}]`), 0600)
	_ = os.WriteFile(filepath.Join(configDir, "settings.json"), []byte(`{"sync": true}`), 0600)

	// 5. Client pushes directory backup
	pushResp, err := c.PushDirectory(ctx, "kybookmarks", "KyBookmarks Cluster Primary", "v1.2.0", tempDir, 2, 3)
	if err != nil {
		t.Fatalf("PushDirectory failed: %v", err)
	}

	if pushResp.Status != "success" || pushResp.CapsuleID == "" {
		t.Fatalf("unexpected push response: %+v", pushResp)
	}
}
