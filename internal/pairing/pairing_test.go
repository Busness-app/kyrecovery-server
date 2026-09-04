package pairing_test

import (
	"context"
	"testing"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/pairing"
)

func TestPairingCodeGenerateAndClaim(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	pending, err := pairing.GeneratePairingCode(ctx, database, 10*time.Minute, "auto-declare", "New App")
	if err != nil {
		t.Fatalf("GeneratePairingCode failed: %v", err)
	}
	if len(pending.PairingCode) != 6 || pending.Status != "pending" {
		t.Fatalf("unexpected pending record: %+v", pending)
	}

	claimed, err := database.ClaimPairingCode(ctx, pending.PairingCode, "kynotes", "KyNotes Production Cluster", "key-test")
	if err != nil {
		t.Fatalf("ClaimPairingCode failed: %v", err)
	}
	if claimed.Status != "paired" || claimed.ServiceName != "kynotes" {
		t.Fatalf("claimed app mismatch: %+v", claimed)
	}

	tokenApp, err := database.GetPairedAppByToken(ctx, claimed.APIToken)
	if err != nil || tokenApp == nil {
		t.Fatalf("GetPairedAppByToken failed: %v", err)
	}
	if tokenApp.ID != claimed.ID {
		t.Fatalf("token app ID mismatch")
	}
}
