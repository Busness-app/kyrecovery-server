package capsule_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busness-app/kyrecovery-server/internal/capsule"
	"github.com/Busness-app/kyrecovery-server/internal/crypto"
)

func TestPackAndUnpackCapsule(t *testing.T) {
	files := map[string][]byte{
		"data/users.db":       []byte("SQLite format 3\x00-mock-database-content-12345"),
		"keys/private.key":    []byte("-----BEGIN RSA PRIVATE KEY-----\nMOCK_KEY\n-----END RSA PRIVATE KEY-----"),
		"config/settings.env": []byte("KY_PORT=8080\nKY_ENV=production\n"),
	}

	deps := []capsule.Dependency{
		{Name: "KY_SIGNING_KEY", Type: "env", Required: true, Description: "JWT RSA private signing key"},
		{Name: "PORT_8080", Type: "port", Required: true, Description: "Main SSO listener port"},
	}

	opts := capsule.PackOptions{
		CapsuleID:    "cap-test-001",
		ServiceName:  "kysignon",
		Files:        files,
		Dependencies: deps,
		Threshold:    3,
		TotalShares:  5,
	}

	result, err := capsule.Pack(opts)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	if len(result.CapsuleBytes) == 0 {
		t.Fatalf("CapsuleBytes is empty")
	}
	if len(result.Shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(result.Shares))
	}

	// Test ReadManifest without key
	manifest, err := capsule.ReadManifest(result.CapsuleBytes)
	if err != nil {
		t.Fatalf("ReadManifest failed: %v", err)
	}
	if manifest.CapsuleID != "cap-test-001" || manifest.ServiceName != "kysignon" {
		t.Fatalf("manifest metadata mismatch: %+v", manifest)
	}
	if len(manifest.Dependencies) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(manifest.Dependencies))
	}

	// Reconstruct master key from threshold shares (e.g. shares 0, 2, 4)
	subset := []crypto.Share{result.Shares[0], result.Shares[2], result.Shares[4]}
	recoveredKey, err := crypto.Combine(subset, manifest.Threshold)
	if err != nil {
		t.Fatalf("Combine shares failed: %v", err)
	}

	// Unpack capsule with recovered key
	unpackedManifest, extractedFiles, err := capsule.Unpack(result.CapsuleBytes, recoveredKey)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	if unpackedManifest.CapsuleID != manifest.CapsuleID {
		t.Fatalf("unpacked manifest ID mismatch")
	}

	if len(extractedFiles) != len(files) {
		t.Fatalf("expected %d extracted files, got %d", len(files), len(extractedFiles))
	}

	for k, v := range files {
		extracted, ok := extractedFiles[k]
		if !ok {
			t.Fatalf("missing file %s in extracted files", k)
		}
		if !bytes.Equal(extracted, v) {
			t.Fatalf("content mismatch for %s", k)
		}
	}

	// Test ExtractToDirectory
	tmpDir, err := os.MkdirTemp("", "kyrecovery-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := capsule.ExtractToDirectory(extractedFiles, tmpDir); err != nil {
		t.Fatalf("ExtractToDirectory failed: %v", err)
	}

	diskData, err := os.ReadFile(filepath.Join(tmpDir, "data/users.db"))
	if err != nil {
		t.Fatalf("failed reading extracted file from disk: %v", err)
	}
	if !bytes.Equal(diskData, files["data/users.db"]) {
		t.Fatalf("extracted disk file content mismatch")
	}
}

// Capsule contents are client-supplied, so extraction must refuse to escape the target dir.
func TestExtractToDirectoryRejectsPathTraversal(t *testing.T) {
	targetDir := filepath.Join(t.TempDir(), "restore")
	escapee := filepath.Join(filepath.Dir(targetDir), "escaped.txt")

	err := capsule.ExtractToDirectory(map[string][]byte{"../escaped.txt": []byte("pwned")}, targetDir)
	if err == nil {
		t.Fatal("expected extraction of ../escaped.txt to be refused")
	}
	if _, statErr := os.Stat(escapee); statErr == nil {
		t.Fatalf("traversal wrote outside the target directory: %s", escapee)
	}
}
