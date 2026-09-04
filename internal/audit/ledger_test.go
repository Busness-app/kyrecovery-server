package audit_test

import (
	"context"
	"testing"

	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/db"
)

func TestAuditLedgerChainingAndVerification(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	ledger := audit.NewLedger(database)

	// Record 3 events
	ev1, err := ledger.Record(ctx, "capsule_captured", "admin@kyrecovery", "cap-001", map[string]interface{}{"service": "kysignon"})
	if err != nil {
		t.Fatalf("Record ev1 failed: %v", err)
	}
	if ev1.Seq != 1 {
		t.Fatalf("ev1 seq mismatch: %+v", ev1)
	}

	ev2, err := ledger.Record(ctx, "custodian_added", "admin@kyrecovery", "cust-001", map[string]interface{}{"name": "Bob"})
	if err != nil {
		t.Fatalf("Record ev2 failed: %v", err)
	}
	if ev2.Seq != 2 || ev2.PrevHash != ev1.EventHash {
		t.Fatalf("ev2 prev_hash not linked to ev1 hash: %+v", ev2)
	}

	ev3, err := ledger.Record(ctx, "drill_completed", "system", "drill-001", map[string]interface{}{"status": "passed", "duration_ms": 120})
	if err != nil {
		t.Fatalf("Record ev3 failed: %v", err)
	}
	if ev3.Seq != 3 || ev3.PrevHash != ev2.EventHash {
		t.Fatalf("ev3 prev_hash not linked to ev2 hash: %+v", ev3)
	}

	// Verify chain integrity
	anchor, err := ledger.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if anchor.Count != 3 || anchor.Hash != ev3.EventHash {
		t.Fatalf("anchor count or hash mismatch: %+v", anchor)
	}
}
