package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// Request body ceilings. Every API route is bounded; backup pushes get a larger
// allowance because they carry file contents, tunable for services with big state.
const (
	maxAPIBodyBytes           = 1 << 20  // 1 MiB
	defaultMaxBackupPushBytes = 64 << 20 // 64 MiB of base64 payload
	EnvMaxBackupPushBytes     = "KYRECOVERY_MAX_BACKUP_BYTES"
	maxSharesPerCapsule       = 255 // GF(2^8) ceiling in crypto.Split
)

// Login and backup push throttles.
const (
	loginWindow         = 15 * time.Minute
	loginAttemptsPerIP  = 20
	loginAttemptsPerAcc = 5

	pushWindow     = 15 * time.Minute
	pushesPerToken = 60

	// A push is held in memory several times over — base64 body, decoded files,
	// tar buffer, ciphertext — so the ceiling that matters is how many run at
	// once, not how many run per quarter hour.
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
	if path == "/api/backup/push" || path == "/api/v1/backup/push" {
		return maxBackupPushBytes()
	}
	return maxAPIBodyBytes
}

func maxBackupPushBytes() int64 {
	if v := os.Getenv(EnvMaxBackupPushBytes); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return defaultMaxBackupPushBytes
}

// newCapsuleID returns a collision-free capsule ID. The timestamp keeps IDs
// readable and roughly ordered; the random suffix is what makes them unique, so
// two pushes in the same second can never name the same capsule.
func newCapsuleID(serviceName string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed generating capsule ID: %w", err)
	}
	return fmt.Sprintf("cap-%s-%d-%s", serviceName, time.Now().UTC().Unix(), hex.EncodeToString(b)), nil
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
