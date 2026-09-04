package diff

import (
	"context"
	"testing"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/db"
)

func TestCompareManifests(t *testing.T) {
	created := time.Now().UTC()
	base := &db.CapsuleRecord{
		ID: "cap-v1", ServiceName: "kysignon", PayloadHash: "hash-v1",
		Threshold: 2, TotalShares: 3, CreatedAt: created,
	}
	target := &db.CapsuleRecord{
		ID: "cap-v2", ServiceName: "kysignon", PayloadHash: "hash-v2",
		Threshold: 3, TotalShares: 5, CreatedAt: created.Add(time.Hour),
	}

	report := CompareManifests(viewOf(base), viewOf(target))
	if report.BaseCapsuleID != "cap-v1" || report.TargetCapsuleID != "cap-v2" {
		t.Fatalf("unexpected capsule IDs in report: %+v", report)
	}
	if report.IdenticalPayload {
		t.Fatal("expected IdenticalPayload to be false")
	}
	if report.ThresholdDelta != 1 || report.TotalSharesDelta != 2 {
		t.Fatalf("unexpected quorum deltas: %+v", report)
	}
	if !report.TargetCreatedAt.After(report.BaseCreatedAt) {
		t.Fatalf("expected target to be newer: %+v", report)
	}
}

// A redeposit of unchanged bytes is the one thing a blind store can still recognise.
func TestCompareManifestsIdenticalPayload(t *testing.T) {
	rec := &db.CapsuleRecord{ID: "cap-v1", ServiceName: "kynotes", PayloadHash: "same"}
	other := &db.CapsuleRecord{ID: "cap-v2", ServiceName: "kynotes", PayloadHash: "same"}
	if !CompareManifests(viewOf(rec), viewOf(other)).IdenticalPayload {
		t.Fatal("expected IdenticalPayload to be true")
	}
}

func TestTimelineInspection(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	_ = database.InsertCapsule(ctx, db.CapsuleRecord{
		ID:          "cap-001",
		ServiceName: "kynotes",
		FilePath:    "/tmp/cap-001.kycap",
		SizeBytes:   1024,
		PayloadHash: "hash1",
		Threshold:   2,
		TotalShares: 3,
		Status:      "active",
		CreatedAt:   time.Now().UTC(),
	})

	inspector := NewInspector(database)
	timeline, err := inspector.GetServiceTimeline(ctx, "kynotes")
	if err != nil {
		t.Fatalf("GetServiceTimeline failed: %v", err)
	}
	if len(timeline) != 1 || timeline[0].CapsuleID != "cap-001" {
		t.Fatalf("unexpected timeline result: %+v", timeline)
	}
}
