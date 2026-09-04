package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// maxAPIBodyBytes bounds every API route but the deposit, which carries a sealed
// capsule and gets the container format's own ceiling.
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

	// capsuleTransferBudget is how long one deposit or download may take end to end.
	// A whole container at capsule.MaxContainerBytes needs roughly 430 KiB/s to finish
	// inside it — slow enough to survive a bad link, short enough to bound a stuck peer.
	capsuleTransferBudget = 15 * time.Minute
)

// setDeadline gives one request its own clock. The listener sets no ReadTimeout or
// WriteTimeout, because a capsule transfer has no size a fixed timeout could fit; the
// routes that move one take a budget here instead of running unbounded. Not every
// ResponseWriter supports deadlines (httptest.ResponseRecorder does not), and one that
// does not is not a request failure.
func setDeadline(w http.ResponseWriter, d time.Duration) {
	rc := http.NewResponseController(w)
	at := time.Now().Add(d)
	_ = rc.SetReadDeadline(at)
	_ = rc.SetWriteDeadline(at)
}

// serviceNamePattern is what may appear in a capsule ID, and therefore in a
// capsule filename. Self-declared pushes choose their own service name, so this
// is what stops a paired product writing outside the capsule directory.
var serviceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func validServiceName(name string) bool {
	return serviceNamePattern.MatchString(name) && !strings.Contains(name, "..")
}

// capsuleIDPattern is the same alphabet as a service name, with room for the honest shape
// a sealer mints: "cap-" + a service name of up to 64 + "-" + 19 digits of UnixNano.
var capsuleIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

func validCapsuleID(id string) bool {
	return capsuleIDPattern.MatchString(id) && !strings.Contains(id, "..")
}

// bodyLimit returns the maximum request body accepted on an API path.
func bodyLimit(path string) int64 {
	if path == "/api/backup/deposit" {
		return capsule.MaxContainerBytes
	}
	return maxAPIBodyBytes
}

// publishCapsule durably stores a capsule and its database record.
//
// The database row is the mutual-exclusion primitive, not the file: the primary key makes
// InsertCapsule atomic, so exactly one of any number of racing deposits of the same capsule
// ID claims the path. Order matters. The bytes are written to a private temporary file and
// fsynced first, so no record can describe a file that was never fully written; the row is
// then claimed; only the request that won the row renames its temporary file into place.
// A loser removes its own temporary file and nothing else — an earlier version renamed
// first and deleted rec.FilePath when the insert failed, which let a retry racing the
// original delete a capsule the store had already published.
func (s *Server) publishCapsule(ctx context.Context, rec db.CapsuleRecord, capsuleBytes []byte) error {
	f, err := os.CreateTemp(filepath.Dir(rec.FilePath), filepath.Base(rec.FilePath)+".tmp")
	if err != nil {
		return fmt.Errorf("failed creating capsule file: %w", err)
	}
	tmpPath := f.Name()
	cleanup := func() { os.Remove(tmpPath) }
	if _, err := f.Write(capsuleBytes); err != nil {
		f.Close()
		cleanup()
		return fmt.Errorf("failed writing capsule file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		cleanup()
		return fmt.Errorf("failed flushing capsule file: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("failed closing capsule file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		cleanup()
		return fmt.Errorf("failed setting capsule file mode: %w", err)
	}

	if err := s.db.InsertCapsule(ctx, rec); err != nil {
		cleanup()
		if errors.Is(err, db.ErrCapsuleExists) {
			return err
		}
		return fmt.Errorf("failed recording capsule: %w", err)
	}
	if err := os.Rename(tmpPath, rec.FilePath); err != nil {
		// The row is this request's, so releasing it is safe. Run the rollback on an
		// uncancelable context: a client that hung up must not leave a row with no file.
		_ = s.db.DeleteCapsule(context.WithoutCancel(ctx), rec.ID)
		cleanup()
		return fmt.Errorf("failed publishing capsule file: %w", err)
	}
	return nil
}

// capsulePath returns the on-disk location for a capsule ID.
func (s *Server) capsulePath(capsuleID string) string {
	return filepath.Join(s.cfg.DataDir, "capsules", capsuleID+".kycap")
}
