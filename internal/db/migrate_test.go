package db_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// A replication_targets table from before host_key existed must gain the
// column on open, and a target must round-trip through it.
func TestOpenAddsHostKeyToOldReplicationTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`CREATE TABLE replication_targets (
		id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, endpoint TEXT NOT NULL,
		bucket TEXT NOT NULL, region TEXT NOT NULL DEFAULT 'us-east-1', access_key TEXT NOT NULL,
		secret_key TEXT NOT NULL, prefix TEXT NOT NULL DEFAULT 'capsules/',
		auto_sync INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'active',
		last_sync_at DATETIME, created_at DATETIME NOT NULL)`)
	raw.Close()
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ { // second open proves the migration is idempotent
		database, err := db.Open(path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		database.Close()
	}

	database, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	rec := db.ReplicationTargetRecord{ID: "t1", Name: "n", Type: "sftp", Endpoint: "h", HostKey: "SHA256:abc", CreatedAt: time.Now()}
	if err := database.InsertReplicationTarget(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := database.GetReplicationTarget(ctx, "t1")
	if err != nil || got == nil || got.HostKey != "SHA256:abc" {
		t.Fatalf("host key did not round-trip: %+v err=%v", got, err)
	}
}
