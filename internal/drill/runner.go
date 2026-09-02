package drill

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/adapter"
	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/capsule"
	"github.com/Busness-app/kyrecovery-server/internal/crypto"
	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// Runner manages the execution of isolated restore verification drills.
type Runner struct {
	db       *db.DB
	ledger   *audit.Ledger
	adapters map[string]adapter.ServiceAdapter
}

// NewRunner creates a drill runner with registered service adapters.
func NewRunner(database *db.DB, ledger *audit.Ledger, adapters ...adapter.ServiceAdapter) *Runner {
	adapterMap := make(map[string]adapter.ServiceAdapter)
	for _, a := range adapters {
		adapterMap[a.Name()] = a
	}
	return &Runner{
		db:       database,
		ledger:   ledger,
		adapters: adapterMap,
	}
}

// DrillParams contains input parameters for running a drill.
type DrillParams struct {
	CapsuleID    string
	CapsulePath  string // Path on disk for constant O(1) memory streaming unpack
	CapsuleBytes []byte // In-memory fallback
	MasterKey    []byte
	Shares       []crypto.Share
	Actor        string
}

// DrillExecutionSummary contains detailed drill metrics and result.
type DrillExecutionSummary struct {
	DrillID             string                 `json:"drill_id"`
	CapsuleID           string                 `json:"capsule_id"`
	ServiceName         string                 `json:"service_name"`
	Passed              bool                   `json:"passed"`
	DurationMs          int64                  `json:"duration_ms"`
	Checks              []adapter.CheckItem    `json:"checks"`
	MissingDependencies []string               `json:"missing_dependencies"`
	ErrorMessage        string                 `json:"error_message,omitempty"`
	Details             map[string]interface{} `json:"details,omitempty"`
	StartedAt           time.Time              `json:"started_at"`
	CompletedAt         time.Time              `json:"completed_at"`
}

// Execute runs an isolated, ephemeral restore verification drill.
func (r *Runner) Execute(ctx context.Context, params DrillParams) (*DrillExecutionSummary, error) {
	startedAt := time.Now().UTC()
	drillID := fmt.Sprintf("drill-%d", startedAt.UnixNano())

	var manifest *capsule.Manifest
	var err error

	if params.CapsulePath != "" {
		manifest, err = capsule.ReadManifestFromFile(params.CapsulePath)
		if err != nil {
			return nil, fmt.Errorf("failed parsing manifest from %s: %w", params.CapsulePath, err)
		}
	} else if len(params.CapsuleBytes) > 0 {
		manifest, err = capsule.ReadManifest(params.CapsuleBytes)
		if err != nil {
			return nil, fmt.Errorf("failed parsing manifest: %w", err)
		}
	} else {
		return nil, errors.New("neither CapsulePath nor CapsuleBytes provided")
	}

	if params.Actor == "" {
		params.Actor = "system"
	}

	// 1. Resolve master key
	var key []byte
	if len(params.MasterKey) == crypto.KeyLength {
		key = params.MasterKey
	} else if len(params.Shares) >= manifest.Threshold {
		key, err = crypto.Combine(params.Shares, manifest.Threshold)
		if err != nil {
			return nil, fmt.Errorf("failed to reconstruct master key from shares: %w", err)
		}
	} else {
		return nil, fmt.Errorf("insufficient shares provided: need %d shares, received %d", manifest.Threshold, len(params.Shares))
	}

	// 2. Select service adapter
	adp, exists := r.adapters[manifest.ServiceName]
	if !exists {
		return nil, fmt.Errorf("no adapter registered for service %q", manifest.ServiceName)
	}

	// 3. Create isolated ephemeral directory with restricted 0700 permissions
	scratchDir, err := os.MkdirTemp("", fmt.Sprintf("kyrecovery-drill-%s-*", manifest.CapsuleID))
	if err != nil {
		return nil, fmt.Errorf("failed creating ephemeral drill sandbox: %w", err)
	}
	defer func() {
		if err := secureScrubDir(scratchDir); err != nil {
			audit.Log().Error("drill_sandbox_scrub", params.Actor, params.CapsuleID, "failed scrubbing drill sandbox", err)
		}
	}()

	// 4. Decrypt and extract capsule into ephemeral sandbox (Streaming O(1) RAM)
	if params.CapsulePath != "" {
		_, err = capsule.UnpackToDirectoryStream(params.CapsulePath, key, scratchDir)
		if err != nil {
			return nil, fmt.Errorf("streaming drill decrypt & unpack failed: %w", err)
		}
	} else {
		unpackedManifest, extractedFiles, err := capsule.Unpack(params.CapsuleBytes, key)
		if err != nil {
			return nil, fmt.Errorf("drill decrypt & unpack failed: %w", err)
		}
		if err := capsule.ExtractToDirectory(extractedFiles, scratchDir); err != nil {
			return nil, fmt.Errorf("failed extracting payload into drill sandbox: %w", err)
		}
		manifest = unpackedManifest
	}

	// 5. Execute verification checks
	res, err := adp.VerifyRestore(ctx, scratchDir, manifest)
	if err != nil {
		return nil, fmt.Errorf("adapter restore verification failed with error: %w", err)
	}

	completedAt := time.Now().UTC()
	durationMs := completedAt.Sub(startedAt).Milliseconds()

	statusStr := "failed"
	if res.Passed {
		statusStr = "passed"
	}

	detailsBytes, _ := json.Marshal(res.Details)

	// 6. Record drill in database
	drillRec := db.DrillRecord{
		ID:           drillID,
		CapsuleID:    manifest.CapsuleID,
		ServiceName:  manifest.ServiceName,
		Status:       statusStr,
		DurationMs:   durationMs,
		MissingDeps:  res.MissingDependencies,
		ErrorMessage: res.ErrorMessage,
		DetailsJSON:  string(detailsBytes),
		StartedAt:    startedAt,
		CompletedAt:  completedAt,
	}

	if r.db != nil {
		_ = r.db.InsertDrill(ctx, drillRec)
	}

	// 7. Record in audit ledger
	if r.ledger != nil {
		_, _ = r.ledger.Record(ctx, "drill_completed", params.Actor, manifest.CapsuleID, map[string]interface{}{
			"drill_id":     drillID,
			"service_name": manifest.ServiceName,
			"status":       statusStr,
			"duration_ms":  durationMs,
			"checks_count": len(res.Checks),
		})
	}

	return &DrillExecutionSummary{
		DrillID:             drillID,
		CapsuleID:           manifest.CapsuleID,
		ServiceName:         manifest.ServiceName,
		Passed:              res.Passed,
		DurationMs:          durationMs,
		Checks:              res.Checks,
		MissingDependencies: res.MissingDependencies,
		ErrorMessage:        res.ErrorMessage,
		Details:             res.Details,
		StartedAt:           startedAt,
		CompletedAt:         completedAt,
	}, nil
}

// scrubChunk is the fixed buffer reused to overwrite restored files, so cleaning a
// large capsule costs the same memory as cleaning a small one.
const scrubChunk = 64 << 10

// secureScrubDir overwrites restored file contents before deletion so a decrypted
// copy of a service's secrets does not linger in the sandbox.
//
// Overwriting in place is best-effort: on SSDs, copy-on-write filesystems (btrfs,
// ZFS), overlayfs and virtualised storage the original blocks may survive. Treat
// it as reducing exposure, not as guaranteed erasure — the deletion below is what
// the drill actually relies on.
func secureScrubDir(dir string) error {
	var firstErr error
	zeros := make([]byte, scrubChunk)

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() == 0 {
			return nil
		}
		if err := overwriteFile(path, info.Size(), zeros); err != nil && firstErr == nil {
			firstErr = err
		}
		return nil
	})

	if err := os.RemoveAll(dir); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// overwriteFile writes zeros over size bytes of path in fixed-size chunks.
func overwriteFile(path string, size int64, zeros []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	for remaining := size; remaining > 0; {
		n := int64(len(zeros))
		if remaining < n {
			n = remaining
		}
		if _, err := f.Write(zeros[:n]); err != nil {
			return err
		}
		remaining -= n
	}
	return f.Sync()
}
