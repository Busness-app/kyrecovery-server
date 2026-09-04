package db_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/db"
)

func TestDatabaseOperations(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	// 1. Insert & Retrieve Capsule
	capRec := db.CapsuleRecord{
		ID:          "cap-001",
		ServiceName: "kysignon",
		FilePath:    "/tmp/cap-001.kycap",
		SizeBytes:   4096,
		PayloadHash: "abc123hash",
		Threshold:   2,
		TotalShares: 3,
		Status:      "active",
		CreatedAt:   time.Now().UTC(),
	}
	if err := database.InsertCapsule(ctx, capRec); err != nil {
		t.Fatalf("InsertCapsule failed: %v", err)
	}

	retrieved, err := database.GetCapsule(ctx, "cap-001")
	if err != nil || retrieved == nil {
		t.Fatalf("GetCapsule failed: %v", err)
	}
	if retrieved.ServiceName != "kysignon" {
		t.Fatalf("service name mismatch: %s", retrieved.ServiceName)
	}

	// 2. Insert & List Custodians
	custodian := db.CustodianRecord{
		ID:          "cust-001",
		Name:        "Alice Security",
		Email:       "alice@example.com",
		Fingerprint: "SHA256:fingerprint001",
		CreatedAt:   time.Now().UTC(),
	}
	if err := database.InsertCustodian(ctx, custodian); err != nil {
		t.Fatalf("InsertCustodian failed: %v", err)
	}
	custodians, err := database.ListCustodians(ctx)
	if err != nil || len(custodians) != 1 {
		t.Fatalf("ListCustodians failed: %v, count=%d", err, len(custodians))
	}

	// 3. Insert & List Drills
	drill := db.DrillRecord{
		ID:           "drill-001",
		CapsuleID:    "cap-001",
		ServiceName:  "kysignon",
		Status:       "passed",
		DurationMs:   145,
		MissingDeps:  []string{},
		ErrorMessage: "",
		DetailsJSON:  `{"checks": 5}`,
		StartedAt:    time.Now().UTC().Add(-time.Second),
		CompletedAt:  time.Now().UTC(),
	}
	if err := database.InsertDrill(ctx, drill); err != nil {
		t.Fatalf("InsertDrill failed: %v", err)
	}

	lastDrill, err := database.GetLastDrill(ctx)
	if err != nil || lastDrill == nil {
		t.Fatalf("GetLastDrill failed: %v", err)
	}
	if lastDrill.Status != "passed" || lastDrill.DurationMs != 145 {
		t.Fatalf("last drill data mismatch: %+v", lastDrill)
	}
}

// InsertCapsule must classify a primary-key collision as ErrCapsuleExists so callers
// can distinguish "already stored" from any other insert failure.
func TestInsertCapsuleReportsDuplicateID(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	rec := db.CapsuleRecord{
		ID: "cap-dup", ServiceName: "kysignon", FilePath: "/tmp/cap-dup.kycap",
		SizeBytes: 1, PayloadHash: "h", Threshold: 2, TotalShares: 3,
		Status: "active", CreatedAt: time.Now().UTC(),
	}
	if err := database.InsertCapsule(ctx, rec); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := database.InsertCapsule(ctx, rec); err != db.ErrCapsuleExists {
		t.Fatalf("second insert: got %v, want ErrCapsuleExists", err)
	}
}

// publishCapsule's rollback runs DeleteCapsule on context.WithoutCancel(ctx) so a client
// that disconnects mid-request cannot leave a row with no file. Confirms the mechanism this
// depends on: the sqlite driver fails a query against an already-canceled context, and
// context.WithoutCancel is what lets the rollback still run.
func TestDeleteCapsuleSurvivesACanceledContext(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	rec := db.CapsuleRecord{
		ID: "cap-cancel", ServiceName: "kysignon", FilePath: "/tmp/cap-cancel.kycap",
		SizeBytes: 1, PayloadHash: "h", Threshold: 2, TotalShares: 3,
		Status: "active", CreatedAt: time.Now().UTC(),
	}
	if err := database.InsertCapsule(context.Background(), rec); err != nil {
		t.Fatalf("insert: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := database.DeleteCapsule(ctx, rec.ID); err == nil {
		t.Fatal("expected the canceled context itself to fail the query")
	}
	if err := database.DeleteCapsule(context.WithoutCancel(ctx), rec.ID); err != nil {
		t.Fatalf("DeleteCapsule on context.WithoutCancel: %v", err)
	}
	if got, err := database.GetCapsule(context.Background(), rec.ID); err != nil || got != nil {
		t.Fatalf("row still present after rollback: %+v, err=%v", got, err)
	}
}

// Concurrent claims of one pairing code must mint exactly one token.
func TestClaimPairingCodeIsSingleUseUnderRace(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	now := time.Now().UTC()
	if err := database.InsertPairedApp(ctx, db.PairedAppRecord{
		ID:          "pair-race",
		ServiceName: "auto-declare",
		AppName:     "Pending Service",
		APIToken:    "kyrec_live_race",
		PairingCode: "424242",
		Status:      "pending",
		ExpiresAt:   now.Add(15 * time.Minute),
		CreatedAt:   now,
	}); err != nil {
		t.Fatalf("InsertPairedApp failed: %v", err)
	}

	const racers = 16
	var wg sync.WaitGroup
	results := make(chan error, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			_, err := database.ClaimPairingCode(ctx, "424242", "kynotes", fmt.Sprintf("claimer-%d", n), "key-test")
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	claimed := 0
	for err := range results {
		if err == nil {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("expected exactly 1 successful claim, got %d", claimed)
	}
}
