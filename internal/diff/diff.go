package diff

import (
	"context"
	"fmt"
	"strings"

	"kyrecovery-server/internal/capsule"
	"kyrecovery-server/internal/db"
)

// FileDiffItem represents changes to a single file between two capsules.
type FileDiffItem struct {
	Path        string `json:"path"`
	Status      string `json:"status"` // "added", "removed", "modified", "unchanged"
	OldSizeBytes int64  `json:"old_size_bytes"`
	NewSizeBytes int64  `json:"new_size_bytes"`
	SizeDelta   int64  `json:"size_delta"`
	OldHash     string `json:"old_hash,omitempty"`
	NewHash     string `json:"new_hash,omitempty"`
}

// DependencyDiffItem tracks environment or port changes.
type DependencyDiffItem struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Status string `json:"status"` // "added", "removed", "unchanged"
}

// CapsuleDiffReport summarizes the differences between two capsule versions.
type CapsuleDiffReport struct {
	BaseCapsuleID     string               `json:"base_capsule_id"`
	TargetCapsuleID   string               `json:"target_capsule_id"`
	ServiceName       string               `json:"service_name"`
	TotalFilesDelta   int                  `json:"total_files_delta"`
	TotalSizeDelta    int64                `json:"total_size_delta"`
	IdenticalPayload  bool                 `json:"identical_payload"`
	FileDiffs         []FileDiffItem       `json:"file_diffs"`
	DependencyDiffs   []DependencyDiffItem `json:"dependency_diffs"`
}

// CompareManifests computes a content-blind diff between two capsule manifests.
func CompareManifests(base, target *capsule.Manifest) *CapsuleDiffReport {
	report := &CapsuleDiffReport{
		BaseCapsuleID:    base.CapsuleID,
		TargetCapsuleID:  target.CapsuleID,
		ServiceName:      target.ServiceName,
		IdenticalPayload: base.PayloadHash == target.PayloadHash,
	}

	baseFiles := make(map[string]capsule.FileEntry)
	for _, f := range base.Files {
		baseFiles[f.Path] = f
	}

	targetFiles := make(map[string]capsule.FileEntry)
	for _, f := range target.Files {
		targetFiles[f.Path] = f
	}

	var baseTotalSize, targetTotalSize int64

	// Inspect target files
	for path, tFile := range targetFiles {
		targetTotalSize += tFile.SizeBytes
		if bFile, exists := baseFiles[path]; exists {
			baseTotalSize += bFile.SizeBytes
			status := "unchanged"
			if bFile.SHA256 != tFile.SHA256 || bFile.SizeBytes != tFile.SizeBytes {
				status = "modified"
			}
			report.FileDiffs = append(report.FileDiffs, FileDiffItem{
				Path:         path,
				Status:       status,
				OldSizeBytes: bFile.SizeBytes,
				NewSizeBytes: tFile.SizeBytes,
				SizeDelta:    tFile.SizeBytes - bFile.SizeBytes,
				OldHash:      bFile.SHA256,
				NewHash:      tFile.SHA256,
			})
		} else {
			report.FileDiffs = append(report.FileDiffs, FileDiffItem{
				Path:         path,
				Status:       "added",
				OldSizeBytes: 0,
				NewSizeBytes: tFile.SizeBytes,
				SizeDelta:    tFile.SizeBytes,
				NewHash:      tFile.SHA256,
			})
		}
	}

	// Find removed files
	for path, bFile := range baseFiles {
		if _, exists := targetFiles[path]; !exists {
			baseTotalSize += bFile.SizeBytes
			report.FileDiffs = append(report.FileDiffs, FileDiffItem{
				Path:         path,
				Status:       "removed",
				OldSizeBytes: bFile.SizeBytes,
				NewSizeBytes: 0,
				SizeDelta:    -bFile.SizeBytes,
				OldHash:      bFile.SHA256,
			})
		}
	}

	report.TotalFilesDelta = len(target.Files) - len(base.Files)
	report.TotalSizeDelta = targetTotalSize - baseTotalSize

	// Dependency Diffs
	baseDeps := make(map[string]capsule.Dependency)
	for _, d := range base.Dependencies {
		baseDeps[d.Name] = d
	}
	targetDeps := make(map[string]capsule.Dependency)
	for _, d := range target.Dependencies {
		targetDeps[d.Name] = d
	}

	for name, td := range targetDeps {
		if _, exists := baseDeps[name]; exists {
			report.DependencyDiffs = append(report.DependencyDiffs, DependencyDiffItem{
				Name:   name,
				Type:   td.Type,
				Status: "unchanged",
			})
		} else {
			report.DependencyDiffs = append(report.DependencyDiffs, DependencyDiffItem{
				Name:   name,
				Type:   td.Type,
				Status: "added",
			})
		}
	}

	for name, bd := range baseDeps {
		if _, exists := targetDeps[name]; !exists {
			report.DependencyDiffs = append(report.DependencyDiffs, DependencyDiffItem{
				Name:   name,
				Type:   bd.Type,
				Status: "removed",
			})
		}
	}

	return report
}

// Inspector assists with diffing capsules from database paths.
type Inspector struct {
	db *db.DB
}

// NewInspector creates a new diff and rollback inspector.
func NewInspector(database *db.DB) *Inspector {
	return &Inspector{db: database}
}

// DiffByCapsuleIDs retrieves manifests from two capsule files and computes their diff.
func (i *Inspector) DiffByCapsuleIDs(ctx context.Context, baseID, targetID string) (*CapsuleDiffReport, error) {
	baseRec, err := i.db.GetCapsule(ctx, baseID)
	if err != nil || baseRec == nil {
		return nil, fmt.Errorf("base capsule not found: %s", baseID)
	}

	targetRec, err := i.db.GetCapsule(ctx, targetID)
	if err != nil || targetRec == nil {
		return nil, fmt.Errorf("target capsule not found: %s", targetID)
	}

	baseManifest, err := capsule.ReadManifestFromFile(baseRec.FilePath)
	if err != nil {
		// Fallback minimal manifest
		baseManifest = &capsule.Manifest{
			CapsuleID:   baseRec.ID,
			ServiceName: baseRec.ServiceName,
			PayloadHash: baseRec.PayloadHash,
		}
	}

	targetManifest, err := capsule.ReadManifestFromFile(targetRec.FilePath)
	if err != nil {
		targetManifest = &capsule.Manifest{
			CapsuleID:   targetRec.ID,
			ServiceName: targetRec.ServiceName,
			PayloadHash: targetRec.PayloadHash,
		}
	}

	return CompareManifests(baseManifest, targetManifest), nil
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
	FilesCount  int    `json:"files_count"`
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
		filesCount := 0
		if m, err := capsule.ReadManifestFromFile(c.FilePath); err == nil {
			filesCount = len(m.Files)
		}
		timeline = append(timeline, HistoricalTimelineEntry{
			CapsuleID:   c.ID,
			ServiceName: c.ServiceName,
			SizeBytes:   c.SizeBytes,
			PayloadHash: c.PayloadHash,
			Threshold:   c.Threshold,
			TotalShares: c.TotalShares,
			CreatedAt:   c.CreatedAt.Format("2006-01-02T15:04:05Z"),
			FilesCount:  filesCount,
		})
	}
	return timeline, nil
}
