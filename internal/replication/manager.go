package replication

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Busness-app/ky-primitives/offsite"
	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// Manager coordinates replication of encrypted capsules to offsite storage targets.
type Manager struct {
	db     *db.DB
	ledger *audit.Ledger
}

// NewManager creates a new replication manager.
func NewManager(database *db.DB, ledger *audit.Ledger) *Manager {
	return &Manager{
		db:     database,
		ledger: ledger,
	}
}

// SyncCapsule replicates a single capsule to a specific target.
func (m *Manager) SyncCapsule(ctx context.Context, capsuleID, targetID string) (*db.ReplicationLogRecord, error) {
	startedAt := time.Now().UTC()

	target, err := m.db.GetReplicationTarget(ctx, targetID)
	if err != nil || target == nil {
		return nil, fmt.Errorf("replication target not found: %s", targetID)
	}

	capRec, err := m.db.GetCapsule(ctx, capsuleID)
	if err != nil || capRec == nil {
		return nil, fmt.Errorf("capsule not found: %s", capsuleID)
	}

	capFile, err := os.Open(capRec.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed opening capsule file %s: %w", capRec.FilePath, err)
	}
	defer capFile.Close()

	stat, err := capFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat capsule: %w", err)
	}
	sizeBytes := stat.Size()
	transferErr := m.transfer(ctx, *target, capRec, capFile, sizeBytes)

	completedAt := time.Now().UTC()
	durationMs := completedAt.Sub(startedAt).Milliseconds()

	status := "success"
	errMsg := ""
	if transferErr != nil {
		status = "failed"
		errMsg = transferErr.Error()
	}

	logRec := db.ReplicationLogRecord{
		TargetID:         target.ID,
		CapsuleID:        capRec.ID,
		BytesTransferred: sizeBytes,
		DurationMs:       durationMs,
		Status:           status,
		ErrorMessage:     errMsg,
		CreatedAt:        completedAt,
	}

	_ = m.db.InsertReplicationLog(ctx, logRec)
	_ = m.db.UpdateReplicationTargetLastSync(ctx, target.ID, status)

	if m.ledger != nil {
		_, _ = m.ledger.Record(ctx, "capsule_replicated", "replication-daemon", capRec.ID, map[string]interface{}{
			"target_id":   target.ID,
			"target_name": target.Name,
			"status":      status,
			"bytes":       sizeBytes,
			"duration_ms": durationMs,
		})
	}

	if transferErr != nil {
		return &logRec, transferErr
	}
	return &logRec, nil
}

// SyncAllAutoTargets replicates a capsule across all targets configured for auto-sync.
func (m *Manager) SyncAllAutoTargets(ctx context.Context, capsuleID string) []db.ReplicationLogRecord {
	targets, err := m.db.ListReplicationTargets(ctx)
	if err != nil {
		return nil
	}

	var logs []db.ReplicationLogRecord
	for _, t := range targets {
		if t.AutoSync && t.Status != "disabled" {
			logRec, _ := m.SyncCapsule(ctx, capsuleID, t.ID)
			if logRec != nil {
				logs = append(logs, *logRec)
			}
		}
	}
	return logs
}

// TestTarget validates connectivity and credentials for a target.
func (m *Manager) TestTarget(ctx context.Context, target db.ReplicationTargetRecord) error {
	l, err := targetLocation(target, "connectivity-test")
	if err != nil {
		return err
	}
	if l.absoluteSFTP {
		return NewSFTPClient(target.Endpoint, target.AccessKey, target.SecretKey, target.Prefix, target.HostKey).TestConnection(ctx)
	}
	if l.virtualS3 {
		return NewS3Client(target.Endpoint, target.Bucket, target.Region, target.AccessKey, target.SecretKey).TestConnection(ctx)
	}
	t, err := offsite.Parse(l.config)
	if err != nil {
		return err
	}
	return t.Test(ctx)
}
