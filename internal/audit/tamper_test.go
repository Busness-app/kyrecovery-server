package audit_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/db"

	_ "modernc.org/sqlite"
)

// openLedgerDB returns a file-backed database plus a raw handle standing in for
// an attacker with write access to the SQLite file.
func openLedgerDB(t *testing.T) (*db.DB, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kyrecovery.db")

	database, err := db.Open(path)
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw sql.Open failed: %v", err)
	}
	t.Cleanup(func() { raw.Close() })
	return database, raw
}

// TestRewrittenEventIsDetected is the attack the ledger key exists to stop: an
// attacker holding only the database edits an event. Recomputing the chain over
// it needs the key, which is not in the file.
func TestRewrittenEventIsDetected(t *testing.T) {
	ctx := context.Background()
	database, raw := openLedgerDB(t)
	ledger := audit.NewLedger(database)

	for _, action := range []string{"capsule_deposited", "kit_exported", "drill_completed"} {
		if _, err := ledger.Record(ctx, action, "mallory", "cap-1", map[string]interface{}{"n": action}); err != nil {
			t.Fatalf("Record(%s) failed: %v", action, err)
		}
	}
	if _, err := ledger.Verify(ctx); err != nil {
		t.Fatalf("baseline chain should verify: %v", err)
	}

	// Mallory hides the export.
	if _, err := raw.ExecContext(ctx, `UPDATE audit_events SET action = 'nothing_happened' WHERE seq = 2`); err != nil {
		t.Fatalf("tamper update failed: %v", err)
	}
	if _, err := ledger.Verify(ctx); err == nil {
		t.Fatal("a rewritten event was reported as valid")
	}
}
