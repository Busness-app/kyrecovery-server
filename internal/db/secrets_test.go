package db_test

import (
	"context"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/db"

	_ "modernc.org/sqlite"
)

// TestReplicationSecretIsNotStoredInPlaintext proves that stealing the database
// file does not hand over the offsite storage credentials.
func TestReplicationSecretIsNotStoredInPlaintext(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "kyrecovery.db")

	database, err := db.Open(path)
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	const secret = "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY"
	target := db.ReplicationTargetRecord{
		ID: "target-1", Name: "R2", Type: "s3", Endpoint: "https://r2.example",
		Bucket: "capsules", Region: "auto", AccessKey: "AKIA-EXAMPLE",
		SecretKey: secret, Prefix: "capsules/", AutoSync: true, Status: "active",
		CreatedAt: time.Now().UTC(),
	}
	if err := database.InsertReplicationTarget(ctx, target); err != nil {
		t.Fatalf("InsertReplicationTarget failed: %v", err)
	}

	// What an attacker reads out of the stolen file.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open failed: %v", err)
	}
	defer raw.Close()

	var stored string
	if err := raw.QueryRowContext(ctx, `SELECT secret_key FROM replication_targets WHERE id = 'target-1'`).Scan(&stored); err != nil {
		t.Fatalf("raw query failed: %v", err)
	}
	if strings.Contains(stored, secret) {
		t.Fatal("the replication secret key is stored in plaintext")
	}
	if !strings.HasPrefix(stored, "enc:v1:") {
		t.Fatalf("expected a sealed value, got %q", stored)
	}

	// The running server still gets the real credential back.
	got, err := database.GetReplicationTarget(ctx, "target-1")
	if err != nil || got == nil {
		t.Fatalf("GetReplicationTarget failed: %v", err)
	}
	if got.SecretKey != secret {
		t.Fatalf("sealed credential did not round-trip: %q", got.SecretKey)
	}

	list, err := database.ListReplicationTargets(ctx)
	if err != nil || len(list) != 1 || list[0].SecretKey != secret {
		t.Fatalf("ListReplicationTargets did not unseal the credential: %+v %v", list, err)
	}
}

// TestKeyFileIsCreatedOutsideTheDatabase pins where the key lives and how it is
// permissioned, since that is the whole basis of the at-rest protection.
func TestKeyFileIsCreatedOutsideTheDatabase(t *testing.T) {
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "kyrecovery.db"))
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	info, err := statKeyFile(dir)
	if err != nil {
		t.Fatalf("expected a server key file next to the database: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("key file permissions are %o, want 0600", perm)
	}
	// keyfile writes hex, the suite's spelling: an operator can read, copy and diff the
	// key without a tool, and no one has to guess whether the bytes are raw or encoded.
	raw, err := os.ReadFile(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	if key, err := hex.DecodeString(strings.TrimSpace(string(raw))); err != nil || len(key) != 32 {
		t.Fatalf("key file is not 32 bytes of hex: %v (%d bytes decoded)", err, len(key))
	}
}

func statKeyFile(dir string) (os.FileInfo, error) {
	return os.Stat(filepath.Join(dir, "secret.key"))
}
