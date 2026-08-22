package audit_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kyrecovery-server/internal/audit"
	"kyrecovery-server/internal/db"
	"kyrecovery-server/internal/secrets"

	_ "modernc.org/sqlite"
)

// openLedgerDB returns a file-backed database plus a raw handle standing in for
// an attacker with write access to the SQLite file.
func openLedgerDB(t *testing.T) (*db.DB, *sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "kyrecovery.db")

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
	return database, raw, dir
}

// TestRewrittenEventWithRecomputedChainIsDetected is the attack the hash chain
// alone could not stop: edit an event, then recompute every following hash.
func TestRewrittenEventWithRecomputedChainIsDetected(t *testing.T) {
	ctx := context.Background()
	database, raw, _ := openLedgerDB(t)
	ledger := audit.NewLedger(database)

	for _, action := range []string{"capsule_captured", "kit_exported", "drill_completed"} {
		if _, err := ledger.Record(ctx, action, "mallory", "cap-1", map[string]interface{}{"n": action}); err != nil {
			t.Fatalf("Record(%s) failed: %v", action, err)
		}
	}
	if status, err := ledger.VerifyChain(ctx); err != nil || !status.Valid {
		t.Fatalf("baseline chain should verify: %+v %v", status, err)
	}

	// Mallory hides the export and rebuilds the chain with the unkeyed hash.
	if _, err := raw.ExecContext(ctx, `UPDATE audit_events SET action = 'nothing_happened' WHERE sequence_num = 2`); err != nil {
		t.Fatalf("tamper update failed: %v", err)
	}
	rebuildUnkeyedChain(t, ctx, raw)

	status, err := ledger.VerifyChain(ctx)
	if err == nil && status.Valid {
		t.Fatal("a rewritten event with a recomputed chain was reported as valid")
	}
}

// rebuildUnkeyedChain recomputes prev_hash/event_hash for every event using the
// unkeyed algorithm, exactly as an attacker holding only the database could.
func rebuildUnkeyedChain(t *testing.T, ctx context.Context, raw *sql.DB) {
	t.Helper()
	rows, err := raw.QueryContext(ctx, `SELECT sequence_num, action, actor, target_id, details_json, created_at FROM audit_events ORDER BY sequence_num ASC`)
	if err != nil {
		t.Fatalf("select failed: %v", err)
	}
	type ev struct {
		seq                                int64
		action, actor, targetID, detailsJS string
		createdAt                          time.Time
	}
	var events []ev
	for rows.Next() {
		var e ev
		if err := rows.Scan(&e.seq, &e.action, &e.actor, &e.targetID, &e.detailsJS, &e.createdAt); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		events = append(events, e)
	}
	rows.Close()

	prev := audit.GenesisHash
	for _, e := range events {
		h := audit.CalculateEventHash(e.seq, prev, e.action, e.actor, e.targetID, e.detailsJS, e.createdAt)
		if _, err := raw.ExecContext(ctx, `UPDATE audit_events SET prev_hash = ?, event_hash = ? WHERE sequence_num = ?`, prev, h, e.seq); err != nil {
			t.Fatalf("chain rewrite failed: %v", err)
		}
		prev = h
	}
}

// TestLegacyChainIsRekeyedOnUpgrade keeps an existing installation's audit chain
// verifiable across the upgrade, and proves the unkeyed hashes stop being
// accepted once that migration has happened.
func TestLegacyChainIsRekeyedOnUpgrade(t *testing.T) {
	ctx := context.Background()
	database, raw, dir := openLedgerDB(t)

	ledger := audit.NewLedger(database)
	for i := 0; i < 3; i++ {
		if _, err := ledger.Record(ctx, "capsule_captured", "ops", "cap-1", nil); err != nil {
			t.Fatalf("Record failed: %v", err)
		}
	}

	// Rewind to the pre-upgrade state: unkeyed hashes and no migration marker.
	rebuildUnkeyedChain(t, ctx, raw)
	if err := os.Remove(filepath.Join(dir, secrets.KeyedMarkerName)); err != nil {
		t.Fatalf("removing the keyed marker failed: %v", err)
	}

	// Opening the ledger migrates the chain in place.
	upgraded := audit.NewLedger(database)
	status, err := upgraded.VerifyChain(ctx)
	if err != nil || !status.Valid || status.Count != 3 {
		t.Fatalf("re-keyed chain should verify: %+v %v", status, err)
	}

	// And the unkeyed algorithm is no longer a way in.
	rebuildUnkeyedChain(t, ctx, raw)
	if status, err := upgraded.VerifyChain(ctx); err == nil && status.Valid {
		t.Fatal("unkeyed event hashes were accepted after the ledger was keyed")
	}
}

// TestBrokenLegacyChainIsNotBlessed proves the upgrade refuses to re-key a chain
// that was already inconsistent.
func TestBrokenLegacyChainIsNotBlessed(t *testing.T) {
	ctx := context.Background()
	database, raw, dir := openLedgerDB(t)

	ledger := audit.NewLedger(database)
	for i := 0; i < 3; i++ {
		if _, err := ledger.Record(ctx, "kit_exported", "ops", "cap-1", nil); err != nil {
			t.Fatalf("Record failed: %v", err)
		}
	}
	rebuildUnkeyedChain(t, ctx, raw)
	if _, err := raw.ExecContext(ctx, `UPDATE audit_events SET actor = 'someone_else' WHERE sequence_num = 2`); err != nil {
		t.Fatalf("tamper failed: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, secrets.KeyedMarkerName)); err != nil {
		t.Fatalf("removing the keyed marker failed: %v", err)
	}

	upgraded := audit.NewLedger(database)
	if status, err := upgraded.VerifyChain(ctx); err == nil && status.Valid {
		t.Fatal("a chain that was already broken was re-keyed and reported valid")
	}
}
