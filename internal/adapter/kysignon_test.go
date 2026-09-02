package adapter_test

import (
	"context"
	"os"
	"testing"

	"github.com/Busness-app/kyrecovery-server/internal/adapter"
	"github.com/Busness-app/kyrecovery-server/internal/capsule"
	"github.com/Busness-app/kyrecovery-server/internal/crypto"
)

func TestKySignOnAdapterCaptureAndVerify(t *testing.T) {
	ctx := context.Background()
	adp := adapter.NewKySignOnAdapter()

	// 1. Capture state (using sample generation)
	files, deps, err := adp.Capture(ctx, "/nonexistent/test/dir")
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}
	if len(files) < 3 {
		t.Fatalf("expected at least 3 captured files, got %d", len(files))
	}
	if len(deps) < 3 {
		t.Fatalf("expected at least 3 dependencies, got %d", len(deps))
	}

	// 2. Pack into encrypted capsule
	packResult, err := capsule.Pack(capsule.PackOptions{
		CapsuleID:    "cap-kysignon-drill-001",
		ServiceName:  adp.Name(),
		Files:        files,
		Dependencies: deps,
		Threshold:    2,
		TotalShares:  3,
	})
	if err != nil {
		t.Fatalf("capsule.Pack failed: %v", err)
	}

	// 3. Reconstruct key and unpack into isolated ephemeral scratch directory
	key, err := crypto.Combine(packResult.Shares[:2], packResult.Manifest.Threshold)
	if err != nil {
		t.Fatalf("Combine shares failed: %v", err)
	}

	unpackedManifest, extractedFiles, err := capsule.Unpack(packResult.CapsuleBytes, key)
	if err != nil {
		t.Fatalf("capsule.Unpack failed: %v", err)
	}

	scratchDir, err := os.MkdirTemp("", "kyrecovery-drill-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(scratchDir)

	if err := capsule.ExtractToDirectory(extractedFiles, scratchDir); err != nil {
		t.Fatalf("ExtractToDirectory failed: %v", err)
	}

	// 4. Run VerifyRestore
	drillResult, err := adp.VerifyRestore(ctx, scratchDir, unpackedManifest)
	if err != nil {
		t.Fatalf("VerifyRestore failed: %v", err)
	}

	if !drillResult.Passed {
		t.Fatalf("drill verification failed: %s (checks: %+v)", drillResult.ErrorMessage, drillResult.Checks)
	}

	if count, ok := drillResult.Details["verified_files_count"].(int); !ok || count < 1 {
		t.Fatalf("expected verified files count >= 1, got %v", drillResult.Details["verified_files_count"])
	}
}
