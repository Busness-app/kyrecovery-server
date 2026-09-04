package diff

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// manifestView is what the inspector compares: the deposited record, not the container.
type manifestView struct {
	CapsuleID   string
	ServiceName string
	PayloadHash string
	CreatedAt   time.Time
	Threshold   int
	TotalShares int
}

func viewOf(rec *db.CapsuleRecord) *manifestView {
	return &manifestView{CapsuleID: rec.ID, ServiceName: rec.ServiceName, PayloadHash: rec.PayloadHash,
		CreatedAt: rec.CreatedAt, Threshold: rec.Threshold, TotalShares: rec.TotalShares}
}

// CapsuleDiffReport summarizes the differences between two capsule versions.
type CapsuleDiffReport struct {
	BaseCapsuleID    string    `json:"base_capsule_id"`
	TargetCapsuleID  string    `json:"target_capsule_id"`
	ServiceName      string    `json:"service_name"`
	IdenticalPayload bool      `json:"identical_payload"`
	BaseCreatedAt    time.Time `json:"base_created_at"`
	TargetCreatedAt  time.Time `json:"target_created_at"`
	ThresholdDelta   int       `json:"threshold_delta"`
	TotalSharesDelta int       `json:"total_shares_delta"`
}

// CompareManifests computes a diff between two deposited capsule records. The store
// cannot open a capsule, so the comparison stops at what the deposit declared.
func CompareManifests(base, target *manifestView) *CapsuleDiffReport {
	return &CapsuleDiffReport{
		BaseCapsuleID:    base.CapsuleID,
		TargetCapsuleID:  target.CapsuleID,
		ServiceName:      target.ServiceName,
		IdenticalPayload: base.PayloadHash == target.PayloadHash,
		BaseCreatedAt:    base.CreatedAt,
		TargetCreatedAt:  target.CreatedAt,
		ThresholdDelta:   target.Threshold - base.Threshold,
		TotalSharesDelta: target.TotalShares - base.TotalShares,
	}
}

// Inspector assists with diffing capsules recorded in the database.
type Inspector struct {
	db *db.DB
}

// NewInspector creates a new diff and rollback inspector.
func NewInspector(database *db.DB) *Inspector {
	return &Inspector{db: database}
}

// DiffByCapsuleIDs compares the two deposited records.
func (i *Inspector) DiffByCapsuleIDs(ctx context.Context, baseID, targetID string) (*CapsuleDiffReport, error) {
	baseRec, err := i.db.GetCapsule(ctx, baseID)
	if err != nil || baseRec == nil {
		return nil, fmt.Errorf("base capsule not found: %s", baseID)
	}

	targetRec, err := i.db.GetCapsule(ctx, targetID)
	if err != nil || targetRec == nil {
		return nil, fmt.Errorf("target capsule not found: %s", targetID)
	}

	return CompareManifests(viewOf(baseRec), viewOf(targetRec)), nil
}

// HistoricalTimelineEntry represents a point-in-time snapshot of a service's state.
type HistoricalTimelineEntry struct {
	CapsuleID   string `json:"capsule_id"`
	ServiceName string `json:"service_name"`
	SizeBytes   int64  `json:"size_bytes"`
	PayloadHash string `json:"payload_hash"`
	Threshold   int    `json:"threshold"`
	TotalShares int    `json:"total_shares"`
	CreatedAt   string `json:"created_at"`
}

// GetServiceTimeline lists snapshots for a given service in chronological order.
func (i *Inspector) GetServiceTimeline(ctx context.Context, serviceName string) ([]HistoricalTimelineEntry, error) {
	capsules, err := i.db.ListCapsules(ctx)
	if err != nil {
		return nil, err
	}

	var timeline []HistoricalTimelineEntry
	for _, c := range capsules {
		if serviceName != "" && !strings.EqualFold(c.ServiceName, serviceName) {
			continue
		}
		timeline = append(timeline, HistoricalTimelineEntry{
			CapsuleID:   c.ID,
			ServiceName: c.ServiceName,
			SizeBytes:   c.SizeBytes,
			PayloadHash: c.PayloadHash,
			Threshold:   c.Threshold,
			TotalShares: c.TotalShares,
			CreatedAt:   c.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}
	return timeline, nil
}
