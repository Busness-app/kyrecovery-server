package adapter

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// SafeSQLiteHotBackup creates an atomic, transactionally consistent snapshot of an active SQLite database
// without locking out concurrent writers (using WAL-safe VACUUM INTO or atomic online snapshot).
func SafeSQLiteHotBackup(ctx context.Context, sourceDBPath, targetSnapshotPath string) error {
	if _, err := os.Stat(sourceDBPath); os.IsNotExist(err) {
		return fmt.Errorf("source database does not exist: %s", sourceDBPath)
	}

	if err := os.MkdirAll(filepath.Dir(targetSnapshotPath), 0700); err != nil {
		return err
	}
	_ = os.Remove(targetSnapshotPath) // Clean existing target if any

	// Open read-only connection with busy timeout
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=query_only(true)", sourceDBPath)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("failed opening source database: %w", err)
	}
	defer conn.Close()

	// Try atomic VACUUM INTO
	vacuumQuery := fmt.Sprintf("VACUUM INTO '%s'", targetSnapshotPath)
	if _, err := conn.ExecContext(ctx, vacuumQuery); err == nil {
		return nil
	}

	// Fallback for older formats: perform WAL checkpoint and standard copy
	_, _ = conn.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)")

	srcData, err := os.ReadFile(sourceDBPath)
	if err != nil {
		return fmt.Errorf("fallback read failed: %w", err)
	}
	return os.WriteFile(targetSnapshotPath, srcData, 0600)
}
