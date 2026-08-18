package diff_test

import (
	"context"
	"testing"
	"time"

	"kyrecovery-server/internal/capsule"
	"kyrecovery-server/internal/db"
	"kyrecovery-server/internal/diff"
)

func TestCompareManifests(t *testing.T) {
	manifestA := &capsule.Manifest{
		CapsuleID:   "cap-v1",
		ServiceName: "kysignon",
		PayloadHash: "hash-v1",
		Files: []capsule.FileEntry{
			{Path: "data/users.db", SizeBytes: 1000, SHA256: "hash-db-1"},
			{Path: "config/app.env", SizeBytes: 200, SHA256: "hash-env-1"},
			{Path: "keys/old.key", SizeBytes: 500, SHA256: "hash-key-old"},
		},
		Dependencies: []capsule.Dependency{
			{Name: "PORT_8080", Type: "port"},
			{Name: "KY_ISSUER", Type: "env"},
		},
	}

	manifestB := &capsule.Manifest{
		CapsuleID:   "cap-v2",
		ServiceName: "kysignon",
		PayloadHash: "hash-v2",
		Files: []capsule.FileEntry{
			{Path: "data/users.db", SizeBytes: 1500, SHA256: "hash-db-2"}, // modified
			{Path: "config/app.env", SizeBytes: 200, SHA256: "hash-env-1"}, // unchanged
			{Path: "keys/new.key", SizeBytes: 600, SHA256: "hash-key-new"}, // added (old.key removed)
		},
		Dependencies: []capsule.Dependency{
			{Name: "PORT_8080", Type: "port"}, // unchanged
			{Name: "KY_ISSUER", Type: "env"},  // unchanged
			{Name: "KY_ADMIN_EMAIL", Type: "env"}, // added
		},
	}

	report := diff.CompareManifests(manifestA, manifestB)
	if report.BaseCapsuleID != "cap-v1" || report.TargetCapsuleID != "cap-v2" {
		t.Fatalf("unexpected capsule IDs in report: %+v", report)
	}

	if report.IdenticalPayload {
		t.Fatal("expected IdenticalPayload to be false")
	}

	// Verify file statuses
	fileStatus := make(map[string]string)
	for _, f := range report.FileDiffs {
		fileStatus[f.Path] = f.Status
	}

	if fileStatus["data/users.db"] != "modified" {
		t.Fatalf("expected users.db to be modified, got %s", fileStatus["data/users.db"])
	}
	if fileStatus["config/app.env"] != "unchanged" {
		t.Fatalf("expected app.env to be unchanged, got %s", fileStatus["config/app.env"])
	}
	if fileStatus["keys/new.key"] != "added" {
		t.Fatalf("expected keys/new.key to be added, got %s", fileStatus["keys/new.key"])
	}
	if fileStatus["keys/old.key"] != "removed" {
		t.Fatalf("expected keys/old.key to be removed, got %s", fileStatus["keys/old.key"])
	}

	// Verify dependency statuses
	depStatus := make(map[string]string)
	for _, d := range report.DependencyDiffs {
		depStatus[d.Name] = d.Status
	}

	if depStatus["KY_ADMIN_EMAIL"] != "added" {
		t.Fatalf("expected KY_ADMIN_EMAIL to be added, got %s", depStatus["KY_ADMIN_EMAIL"])
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

	inspector := diff.NewInspector(database)
	timeline, err := inspector.GetServiceTimeline(ctx, "kynotes")
	if err != nil {
		t.Fatalf("GetServiceTimeline failed: %v", err)
	}
	if len(timeline) != 1 || timeline[0].CapsuleID != "cap-001" {
		t.Fatalf("unexpected timeline result: %+v", timeline)
	}
}
