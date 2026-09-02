package tui_test

import (
	"testing"

	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/tui"
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
