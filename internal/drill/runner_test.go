package drill_test

import (
	"context"
	"testing"

	"kyrecovery-server/internal/adapter"
	"kyrecovery-server/internal/audit"
	"kyrecovery-server/internal/capsule"
	"kyrecovery-server/internal/crypto"
	"kyrecovery-server/internal/db"
	"kyrecovery-server/internal/drill"
)

func TestDrillExecutionWorkflow(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	ledger := audit.NewLedger(database)
	ssoAdapter := adapter.NewKySignOnAdapter()
	runner := drill.NewRunner(database, ledger, ssoAdapter)

	// Generate test capsule
	files, deps, err := ssoAdapter.Capture(ctx, "/mock/source")
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	packResult, err := capsule.Pack(capsule.PackOptions{
		CapsuleID:    "cap-sso-drill-test",
		ServiceName:  "kysignon",
		Files:        files,
		Dependencies: deps,
		Threshold:    2,
		TotalShares:  4,
	})
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	// Register capsule in DB
	err = database.InsertCapsule(ctx, db.CapsuleRecord{
		ID:          packResult.Manifest.CapsuleID,
		ServiceName: packResult.Manifest.ServiceName,
		FilePath:    "/tmp/cap-test.kycap",
		SizeBytes:   int64(len(packResult.CapsuleBytes)),
		PayloadHash: packResult.Manifest.PayloadHash,
		Threshold:   packResult.Manifest.Threshold,
		TotalShares: packResult.Manifest.TotalShares,
		Status:      "active",
		CreatedAt:   packResult.Manifest.CreatedAt,
	})
	if err != nil {
		t.Fatalf("InsertCapsule failed: %v", err)
	}

	// 1. Run drill with threshold shares (shares 1 and 3)
	summary, err := runner.Execute(ctx, drill.DrillParams{
		CapsuleBytes: packResult.CapsuleBytes,
		Shares:       []crypto.Share{packResult.Shares[1], packResult.Shares[3]},
		Actor:        "admin@kyrecovery.local",
	})
	if err != nil {
		t.Fatalf("runner.Execute failed: %v", err)
	}

	if !summary.Passed {
		t.Fatalf("expected drill to pass, got error: %s", summary.ErrorMessage)
	}
	if summary.DurationMs < 0 {
		t.Fatalf("invalid duration ms: %d", summary.DurationMs)
	}

	// 2. Verify DB drill record
	lastDrill, err := database.GetLastDrill(ctx)
	if err != nil || lastDrill == nil {
		t.Fatalf("failed retrieving recorded drill: %v", err)
	}
	if lastDrill.Status != "passed" || lastDrill.CapsuleID != packResult.Manifest.CapsuleID {
		t.Fatalf("drill DB record mismatch: %+v", lastDrill)
	}

	// 3. Verify audit record
	lastAudit, err := database.GetLastAuditEvent(ctx)
	if err != nil || lastAudit == nil {
		t.Fatalf("failed retrieving audit event: %v", err)
	}
	if lastAudit.Action != "drill_completed" || lastAudit.TargetID != packResult.Manifest.CapsuleID {
		t.Fatalf("audit record mismatch: %+v", lastAudit)
	}
}
