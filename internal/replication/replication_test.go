package replication_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kyrecovery-server/internal/audit"
	"kyrecovery-server/internal/db"
	"kyrecovery-server/internal/replication"
)

func TestLocalReplication(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	ledger := audit.NewLedger(database)
	mgr := replication.NewManager(database, ledger)

	// Create a dummy capsule file
	tempDir := t.TempDir()
	capFilePath := filepath.Join(tempDir, "cap-test-123.kycap")
	if err := os.WriteFile(capFilePath, []byte("mock-encrypted-capsule-content"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	capRec := db.CapsuleRecord{
		ID:          "cap-test-123",
		ServiceName: "kysignon",
		FilePath:    capFilePath,
		SizeBytes:   30,
		PayloadHash: "abc123hash",
		Threshold:   2,
		TotalShares: 3,
		Status:      "active",
		CreatedAt:   time.Now().UTC(),
	}
	if err := database.InsertCapsule(ctx, capRec); err != nil {
		t.Fatalf("InsertCapsule failed: %v", err)
	}

	// 1. Create a local replication target
	offsiteDir := filepath.Join(tempDir, "offsite-vault")
	target := db.ReplicationTargetRecord{
		ID:        "target-local-01",
		Name:      "Local Offsite Vault",
		Type:      "local",
		Endpoint:  offsiteDir,
		AutoSync:  true,
		Status:    "active",
		CreatedAt: time.Now().UTC(),
	}
	if err := database.InsertReplicationTarget(ctx, target); err != nil {
		t.Fatalf("InsertReplicationTarget failed: %v", err)
	}

	// 2. Test connectivity
	if err := mgr.TestTarget(ctx, target); err != nil {
		t.Fatalf("TestTarget failed: %v", err)
	}

	// 3. Replicate capsule
	logRec, err := mgr.SyncCapsule(ctx, "cap-test-123", "target-local-01")
	if err != nil {
		t.Fatalf("SyncCapsule failed: %v", err)
	}
	if logRec.Status != "success" || logRec.BytesTransferred != 30 {
		t.Fatalf("unexpected log record: %+v", logRec)
	}

	// 4. Verify file was copied to offsite destination
	replicatedPath := filepath.Join(offsiteDir, "cap-test-123.kycap")
	data, err := os.ReadFile(replicatedPath)
	if err != nil || string(data) != "mock-encrypted-capsule-content" {
		t.Fatalf("replicated file content mismatch or not found: %v", err)
	}
}
