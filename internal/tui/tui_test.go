package tui_test

import (
	"testing"

	"kyrecovery-server/internal/audit"
	"kyrecovery-server/internal/db"
	"kyrecovery-server/internal/tui"
)

func TestConsoleInstantiation(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	ledger := audit.NewLedger(database)
	console := tui.NewConsole(t.TempDir(), database, ledger)
	if console == nil {
		t.Fatal("expected non-nil Console instance")
	}
}
