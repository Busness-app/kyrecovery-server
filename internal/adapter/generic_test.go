package adapter_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"kyrecovery-server/internal/adapter"
	"kyrecovery-server/internal/capsule"
	"kyrecovery-server/internal/crypto"
)

func TestGenericAdapterCaptureAndVerify(t *testing.T) {
	ctx := context.Background()

	// 1. Create a custom sample app directory with custom SQLite DB, JSON config, and recipe
	srcDir, err := os.MkdirTemp("", "generic-source-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(srcDir)

	if err := os.MkdirAll(filepath.Join(srcDir, "data"), 0700); err != nil {
		t.Fatalf("MkdirAll data failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(srcDir, "config"), 0700); err != nil {
		t.Fatalf("MkdirAll config failed: %v", err)
	}

	// Write JSON config
	if err := os.WriteFile(filepath.Join(srcDir, "config/settings.json"), []byte(`{"service": "custom-service", "active": true}`), 0600); err != nil {
		t.Fatalf("WriteFile settings.json failed: %v", err)
	}

	// Write custom recipe
	recipe := `
	{
		"service_name": "custom-app",
		"include_paths": ["data", "config"],
		"dependencies": [
			{"name": "CUSTOM_PORT", "type": "port", "required": true, "description": "Custom port"}
		],
		"verify_checks": {
			"check_sqlite_databases": true,
			"validate_json_files": true,
			"required_files": ["config/settings.json"]
		}
	}
	`
	if err := os.WriteFile(filepath.Join(srcDir, "kyrecovery-recipe.json"), []byte(recipe), 0600); err != nil {
		t.Fatalf("WriteFile recipe failed: %v", err)
	}

	genericAdp := adapter.NewGenericAdapter()

	// 2. Capture custom source
	files, deps, err := genericAdp.Capture(ctx, srcDir)
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}
	if len(files) < 2 {
		t.Fatalf("expected at least 2 files captured, got %d", len(files))
	}
	if len(deps) != 1 || deps[0].Name != "CUSTOM_PORT" {
		t.Fatalf("unexpected dependencies: %+v", deps)
	}

	// 3. Pack into encrypted capsule
	packResult, err := capsule.Pack(capsule.PackOptions{
		CapsuleID:    "cap-generic-custom-001",
		ServiceName:  "generic",
		Files:        files,
		Dependencies: deps,
		Threshold:    2,
		TotalShares:  3,
	})
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	// 4. Unpack in isolated sandbox
	key, err := crypto.Combine(packResult.Shares[:2], 2)
	if err != nil {
		t.Fatalf("Combine shares failed: %v", err)
	}

	manifest, extracted, err := capsule.Unpack(packResult.CapsuleBytes, key)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	scratchDir, err := os.MkdirTemp("", "generic-drill-*")
	if err != nil {
		t.Fatalf("MkdirTemp scratch failed: %v", err)
	}
	defer os.RemoveAll(scratchDir)

	if err := capsule.ExtractToDirectory(extracted, scratchDir); err != nil {
		t.Fatalf("ExtractToDirectory failed: %v", err)
	}

	// 5. Run VerifyRestore
	drillRes, err := genericAdp.VerifyRestore(ctx, scratchDir, manifest)
	if err != nil {
		t.Fatalf("VerifyRestore failed: %v", err)
	}

	if !drillRes.Passed {
		t.Fatalf("drill expected to pass, got error: %s (checks: %+v)", drillRes.ErrorMessage, drillRes.Checks)
	}
}
