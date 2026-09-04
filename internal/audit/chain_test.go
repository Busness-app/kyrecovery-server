package audit_test

import (
	"testing"

	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/db"
)

func TestLedgerVerifiesAndDetectsTruncation(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	l := audit.NewLedger(database)
	for i := 0; i < 3; i++ {
		if _, err := l.Record(t.Context(), "capsule_deposited", "paired-app:x", "cap-1", map[string]interface{}{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	anchor, err := l.Verify(t.Context())
	if err != nil || anchor.Count != 3 {
		t.Fatalf("verify: %v %+v", err, anchor)
	}
	// Remove the tail: the remaining chain still links, only the anchor knows.
	if err := database.DeleteAuditEventForTest(t.Context(), 3); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Verify(t.Context()); err == nil {
		t.Fatal("truncated log verified")
	}
	// A fresh ledger over the same store resumes from the anchor and refuses to append onto
	// a log that no longer matches it.
	l2 := audit.NewLedger(database)
	if _, err := l2.Record(t.Context(), "x", "y", "z", nil); err == nil {
		t.Fatal("append succeeded on a chain that fails its anchor")
	}
}
