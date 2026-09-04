package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// maxAPIBodyBytes bounds every API route. The deposit route, which carries a
// sealed capsule, gets its own ceiling when it lands.
const maxAPIBodyBytes = 1 << 20 // 1 MiB

// Login and backup push throttles.
const (
	loginWindow         = 15 * time.Minute
	loginAttemptsPerIP  = 20
	loginAttemptsPerAcc = 5

	pushWindow     = 15 * time.Minute
	pushesPerToken = 60

	// A deposit is held in memory more than once, so the ceiling that matters is
	// how many run at once, not how many run per quarter hour.
	maxConcurrentPushes = 4

	// maxPairingTTL caps how long a six-digit code stays guessable.
	maxPairingTTL = 60 * time.Minute
)

// serviceNamePattern is what may appear in a capsule ID, and therefore in a
// capsule filename. Self-declared pushes choose their own service name, so this
// is what stops a paired product writing outside the capsule directory.
var serviceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func validServiceName(name string) bool {
	return serviceNamePattern.MatchString(name) && !strings.Contains(name, "..")
}

// bodyLimit returns the maximum request body accepted on an API path.
func bodyLimit(path string) int64 {
	return maxAPIBodyBytes
}

// publishCapsule durably stores a capsule and its database record. The bytes are
// written to a temporary file, fsynced and renamed into place before the record
// is committed, so an existing recovery point is never overwritten and no record
// can describe a file that was never fully written.
func (s *Server) publishCapsule(ctx context.Context, rec db.CapsuleRecord, capsuleBytes []byte) error {
	tmpPath := rec.FilePath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed creating capsule file: %w", err)
	}
	if _, err := f.Write(capsuleBytes); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed writing capsule file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed flushing capsule file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed closing capsule file: %w", err)
	}

	if err := os.Rename(tmpPath, rec.FilePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed publishing capsule file: %w", err)
	}
	if err := s.db.InsertCapsule(ctx, rec); err != nil {
		os.Remove(rec.FilePath)
		return fmt.Errorf("failed recording capsule: %w", err)
	}
	return nil
}

// capsulePath returns the on-disk location for a capsule ID.
func (s *Server) capsulePath(capsuleID string) string {
	return filepath.Join(s.cfg.DataDir, "capsules", capsuleID+".kycap")
}
