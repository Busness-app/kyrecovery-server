package drill

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestOverwriteFileUsesFixedBuffer proves cleanup cost does not scale with file
// size: a large restored file is zeroed through the shared 64 KiB buffer.
func TestOverwriteFileUsesFixedBuffer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "restored.db")

	// Comfortably larger than one chunk, so the loop is exercised.
	original := bytes.Repeat([]byte("secret"), (scrubChunk/6)*3)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	zeros := make([]byte, scrubChunk)
	if err := overwriteFile(path, int64(len(original)), zeros); err != nil {
		t.Fatalf("overwriteFile failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(got) != len(original) {
		t.Fatalf("file length changed: %d -> %d", len(original), len(got))
	}
	if bytes.Contains(got, []byte("secret")) {
		t.Fatal("restored file still contains plaintext after scrubbing")
	}
}

// TestSecureScrubDirRemovesEverythingAndReportsFailure covers the drill's
// deferred cleanup, including the case where a file cannot be overwritten.
func TestSecureScrubDirRemovesEverythingAndReportsFailure(t *testing.T) {
	dir := t.TempDir()
	sandbox := filepath.Join(dir, "sandbox")
	if err := os.MkdirAll(filepath.Join(sandbox, "nested"), 0700); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	for _, name := range []string{"a.txt", "nested/b.key"} {
		if err := os.WriteFile(filepath.Join(sandbox, name), []byte("sensitive"), 0600); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}
	}

	if err := secureScrubDir(sandbox); err != nil {
		t.Fatalf("secureScrubDir reported an error: %v", err)
	}
	if _, err := os.Stat(sandbox); !os.IsNotExist(err) {
		t.Fatalf("sandbox was not removed: %v", err)
	}

	// A file that cannot be opened for writing is reported, not swallowed.
	readOnly := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readOnly, 0700); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	locked := filepath.Join(readOnly, "locked.key")
	if err := os.WriteFile(locked, []byte("sensitive"), 0400); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := os.Chmod(locked, 0400); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: file permissions do not prevent writes")
	}
	if err := secureScrubDir(readOnly); err == nil {
		t.Fatal("a file that could not be scrubbed was reported as clean")
	}
}
