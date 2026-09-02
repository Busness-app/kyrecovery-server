package adapter_test

import (
	"context"
	"os"
	"testing"

	"github.com/Busness-app/kyrecovery-server/internal/adapter"
	"github.com/Busness-app/kyrecovery-server/internal/capsule"
	"github.com/Busness-app/kyrecovery-server/internal/crypto"
)

func TestKyBookmarksAdapterCaptureAndVerify(t *testing.T) {
	ctx := context.Background()
	adp := adapter.NewKyBookmarksAdapter()

	files, deps, err := adp.Capture(ctx, "/tmp/nonexistent-kybookmarks-dir")
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected non-empty files map from capture")
	}

	packResult, err := capsule.Pack(capsule.PackOptions{
		CapsuleID:    "cap-test-bkm",
		ServiceName:  adp.Name(),
		Files:        files,
		Dependencies: deps,
		Threshold:    2,
		TotalShares:  3,
	})
	if err != nil {
		t.Fatalf("capsule.Pack failed: %v", err)
	}

	key, err := crypto.Combine(packResult.Shares[:2], packResult.Manifest.Threshold)
	if err != nil {
		t.Fatalf("Combine shares failed: %v", err)
	}

	manifest, extractedFiles, err := capsule.Unpack(packResult.CapsuleBytes, key)
	if err != nil {
		t.Fatalf("capsule.Unpack failed: %v", err)
	}

	scratchDir := t.TempDir()
	if err := capsule.ExtractToDirectory(extractedFiles, scratchDir); err != nil {
		t.Fatalf("ExtractToDirectory failed: %v", err)
	}

	res, err := adp.VerifyRestore(ctx, scratchDir, manifest)
	if err != nil {
		t.Fatalf("VerifyRestore failed: %v", err)
	}
	if !res.Passed {
		t.Fatalf("VerifyRestore drill failed: %s (checks: %+v)", res.ErrorMessage, res.Checks)
	}
}

func TestKyNotesAdapterCaptureAndVerify(t *testing.T) {
	ctx := context.Background()
	adp := adapter.NewKyNotesAdapter()

	files, deps, err := adp.Capture(ctx, "/tmp/nonexistent-kynotes-dir")
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	packResult, err := capsule.Pack(capsule.PackOptions{
		CapsuleID:    "cap-test-notes",
		ServiceName:  adp.Name(),
		Files:        files,
		Dependencies: deps,
		Threshold:    2,
		TotalShares:  3,
	})
	if err != nil {
		t.Fatalf("capsule.Pack failed: %v", err)
	}

	key, err := crypto.Combine(packResult.Shares[:2], packResult.Manifest.Threshold)
	if err != nil {
		t.Fatalf("Combine shares failed: %v", err)
	}

	manifest, extractedFiles, err := capsule.Unpack(packResult.CapsuleBytes, key)
	if err != nil {
		t.Fatalf("capsule.Unpack failed: %v", err)
	}

	scratchDir := t.TempDir()
	if err := capsule.ExtractToDirectory(extractedFiles, scratchDir); err != nil {
		t.Fatalf("ExtractToDirectory failed: %v", err)
	}

	res, err := adp.VerifyRestore(ctx, scratchDir, manifest)
	if err != nil {
		t.Fatalf("VerifyRestore failed: %v", err)
	}
	if !res.Passed {
		t.Fatalf("VerifyRestore drill failed: %s (checks: %+v)", res.ErrorMessage, res.Checks)
	}
}

func TestKyPostAdapterCaptureAndVerify(t *testing.T) {
	ctx := context.Background()
	adp := adapter.NewKyPostAdapter()

	files, deps, err := adp.Capture(ctx, "/tmp/nonexistent-kypost-dir")
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	packResult, err := capsule.Pack(capsule.PackOptions{
		CapsuleID:    "cap-test-post",
		ServiceName:  adp.Name(),
		Files:        files,
		Dependencies: deps,
		Threshold:    2,
		TotalShares:  3,
	})
	if err != nil {
		t.Fatalf("capsule.Pack failed: %v", err)
	}

	key, err := crypto.Combine(packResult.Shares[:2], packResult.Manifest.Threshold)
	if err != nil {
		t.Fatalf("Combine shares failed: %v", err)
	}

	manifest, extractedFiles, err := capsule.Unpack(packResult.CapsuleBytes, key)
	if err != nil {
		t.Fatalf("capsule.Unpack failed: %v", err)
	}

	scratchDir, _ := os.MkdirTemp("", "kypost-drill-*")
	defer os.RemoveAll(scratchDir)
	if err := capsule.ExtractToDirectory(extractedFiles, scratchDir); err != nil {
		t.Fatalf("ExtractToDirectory failed: %v", err)
	}

	res, err := adp.VerifyRestore(ctx, scratchDir, manifest)
	if err != nil {
		t.Fatalf("VerifyRestore failed: %v", err)
	}
	if !res.Passed {
		t.Fatalf("VerifyRestore drill failed: %s (checks: %+v)", res.ErrorMessage, res.Checks)
	}
}
