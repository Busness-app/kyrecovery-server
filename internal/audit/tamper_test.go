package audit_test

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/Busness-app/ky-primitives/auditchain"
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

// TestChainRecomputedUnderAnotherKeyIsDetected is the whole point of keying the
// chain: an attacker with write access to the database rewrites an event and
// relinks every record and the anchor. Without the ledger key, that chain is
// self-consistent and still fails verification.
func TestChainRecomputedUnderAnotherKeyIsDetected(t *testing.T) {
	ctx := context.Background()
	database, raw := openLedgerDB(t)
	ledger := audit.NewLedger(database)

	for _, action := range []string{"capsule_deposited", "kit_exported", "drill_completed"} {
		if _, err := ledger.Record(ctx, action, "mallory", "cap-1", nil); err != nil {
			t.Fatalf("Record(%s) failed: %v", action, err)
		}
	}

	rows, err := raw.QueryContext(ctx, `SELECT seq, action, actor, target_id, details_json, created_at FROM audit_events ORDER BY seq ASC`)
	if err != nil {
		t.Fatal(err)
	}
	var seqs []uint64
	var tuples [][]string
	for rows.Next() {
		var seq uint64
		var action, actor, target, details, created string
		if err := rows.Scan(&seq, &action, &actor, &target, &details, &created); err != nil {
			t.Fatal(err)
		}
		if seq == 2 {
			action = "nothing_happened" // Mallory hides the export.
		}
		seqs = append(seqs, seq)
		tuples = append(tuples, []string{action, actor, target, details, created})
	}
	rows.Close()

	// Mallory's own key: 32 bytes, so auditchain accepts it and rebuilds happily.
	forged, anchor, err := auditchain.Replay(bytes.Repeat([]byte{0xA5}, 32), tuples)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range forged {
		if _, err := raw.ExecContext(ctx, `UPDATE audit_events SET action = ?, prev_hash = ?, event_hash = ? WHERE seq = ?`,
			tuples[i][0], r.Prev, r.Hash, seqs[i]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := raw.ExecContext(ctx, `UPDATE audit_anchor SET count = ?, hash = ? WHERE singleton = 1`, anchor.Count, anchor.Hash); err != nil {
		t.Fatal(err)
	}

	if _, err := ledger.Verify(ctx); err == nil {
		t.Fatal("a chain recomputed under another key was reported as valid")
	}
}
