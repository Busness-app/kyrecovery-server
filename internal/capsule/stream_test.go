package capsule_test

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busness-app/kyrecovery-server/internal/capsule"
	"github.com/Busness-app/kyrecovery-server/internal/crypto"
)

func TestStreamingPackAndUnpack(t *testing.T) {
	// Create mock directory with a large 3MB simulated database file
	srcDir, err := os.MkdirTemp("", "stream-src-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(srcDir)

	dbDir := filepath.Join(srcDir, "data")
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	largeData := make([]byte, 3*1024*1024) // 3 MB
	rand.Read(largeData)
	if err := os.WriteFile(filepath.Join(dbDir, "large_records.db"), largeData, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 1. Pack stream directly to disk
	tmpCap, err := os.CreateTemp("", "large-capsule-*.kycap")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	tmpCapPath := tmpCap.Name()
	tmpCap.Close()
	defer os.Remove(tmpCapPath)

	packRes, err := capsule.PackDirectoryStream(srcDir, tmpCapPath, capsule.PackOptions{
		CapsuleID:   "cap-stream-001",
		ServiceName: "generic",
		Threshold:   2,
		TotalShares: 3,
	})
	if err != nil {
		t.Fatalf("PackDirectoryStream failed: %v", err)
	}

	// 2. Combine shares
	key, err := crypto.Combine(packRes.Shares[:2], 2)
	if err != nil {
		t.Fatalf("Combine shares failed: %v", err)
	}

	// 3. Unpack stream directly to destination directory
	destDir, err := os.MkdirTemp("", "stream-dest-*")
	if err != nil {
		t.Fatalf("MkdirTemp dest failed: %v", err)
	}
	defer os.RemoveAll(destDir)

	manifest, err := capsule.UnpackToDirectoryStream(tmpCapPath, key, destDir)
	if err != nil {
		t.Fatalf("UnpackToDirectoryStream failed: %v", err)
	}

	if manifest.CapsuleID != "cap-stream-001" {
		t.Fatalf("manifest ID mismatch: %s", manifest.CapsuleID)
	}

	// 4. Verify extracted file content
	extractedData, err := os.ReadFile(filepath.Join(destDir, "data/large_records.db"))
	if err != nil {
		t.Fatalf("failed reading extracted file: %v", err)
	}

	if !bytes.Equal(extractedData, largeData) {
		t.Fatalf("extracted large data mismatch against original")
	}
}
