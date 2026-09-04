package client_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/auth"
	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/pairing"
	"github.com/Busness-app/kyrecovery-server/internal/server"
	"github.com/Busness-app/kyrecovery-server/pkg/client"
)

func TestClientClaimsPairingCode(t *testing.T) {
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
	_, claimResp, err := client.ClaimPairing(ctx, ts.URL, pairedRecord.PairingCode, "KyBookmarks Cluster Primary")
	if err != nil {
		t.Fatalf("ClaimPairing failed: %v", err)
	}
	if claimResp.APIToken == "" || claimResp.Status != "paired" {
		t.Fatalf("unexpected claim response: %+v", claimResp)
	}

}
