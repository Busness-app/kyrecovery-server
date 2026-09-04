package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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

// defaultReadBudget is how long any one request has to deliver its body, and the value
// Server.readBudget starts at. The listener sets no ReadTimeout — a capsule does not fit
// one — so without this a client trickling a byte a second at a 1 MiB route would hold a
// goroutine for as long as it liked: MaxBytesReader bounds the bytes, nothing bounded the
// clock, and IdleTimeout does not apply mid-request. The two capsule routes raise it to
// capsuleTransferBudget for themselves.
const defaultReadBudget = 30 * time.Second

// requestHasBody reports whether a request has anything left to read. Only those are
// clocked: setting a read deadline on a body-less request cancels its context when the
// deadline expires, because net/http reads ahead on the connection while the handler runs
// and treats that expiry as a dead connection. A handler that legitimately takes minutes —
// re-hashing a container, waiting on an identity provider — would be cancelled mid-work.
// A body-less request cannot slowloris anyway: it is already past ReadHeaderTimeout.
//
// A chunked body reports -1, which is a body.
func requestHasBody(r *http.Request) bool { return r.ContentLength != 0 }

// setReadDeadline and setWriteDeadline give one request its own clock. Not every
// ResponseWriter supports deadlines (httptest.ResponseRecorder does not), and one that
// does not is not a request failure.
//
// There is deliberately no blanket write deadline: /api/auth/callback blocks on an
// identity provider round trip before it writes a byte.
func setReadDeadline(w http.ResponseWriter, d time.Duration) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(d))
}

func setWriteDeadline(w http.ResponseWriter, d time.Duration) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d))
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

// errDepositUnrecorded: the audit chain would not take the deposit, so the store did not.
var errDepositUnrecorded = errors.New("deposit could not be recorded in the audit chain")

// errCapsuleFileExists: the path is already taken on disk by a file no row describes.
var errCapsuleFileExists = errors.New("a capsule file with this ID already exists on disk")

// publishCapsule durably stores a capsule, its audit event and its database record.
//
// The database row is the mutual-exclusion primitive: the primary key makes InsertCapsule
// atomic, so exactly one of any number of racing deposits of the same capsule ID claims
// it. Order matters. The bytes are written to a private temporary file and fsynced first,
// so no record can describe a file that was never fully written; the row is then claimed;
// the deposit is recorded in the audit chain; only then is the file published. A 201
// therefore implies a chain entry, and a loser removes its own temporary file and nothing
// else — an earlier version renamed first and deleted rec.FilePath when the insert failed,
// which let a retry racing the original delete a capsule the store had already published.
//
// The file is published with a hard link, not a rename: rename replaces whatever is at the
// target, and on a case-insensitive volume two IDs that are two rows can be one path. link
// refuses an existing target, so the filesystem enforces the same exclusion as the row.
func (s *Server) publishCapsule(ctx context.Context, rec db.CapsuleRecord, capsuleBytes []byte, record func(context.Context) error) error {
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
	// The row is this request's, so releasing it on failure is safe. From here on the
	// context is uncancelable: a client that hung up must not leave a row with no file,
	// or a file with no event.
	ctx = context.WithoutCancel(ctx)
	if err := record(ctx); err != nil {
		_ = s.db.DeleteCapsule(ctx, rec.ID)
		cleanup()
		return fmt.Errorf("%w: %v", errDepositUnrecorded, err)
	}
	if err := os.Link(tmpPath, rec.FilePath); err != nil {
		_ = s.db.DeleteCapsule(ctx, rec.ID)
		cleanup()
		// The chain already says deposited; append-only means the correction is a second
		// event, not a missing one.
		_, _ = s.ledger.Record(ctx, "capsule_deposit_failed", "system", rec.ID, map[string]interface{}{"error": err.Error()})
		if errors.Is(err, fs.ErrExist) {
			return errCapsuleFileExists
		}
		return fmt.Errorf("failed publishing capsule file: %w", err)
	}
	cleanup()
	return nil
}

// capsulePath returns the on-disk location for a capsule ID.
func (s *Server) capsulePath(capsuleID string) string {
	return filepath.Join(s.cfg.DataDir, "capsules", capsuleID+".kycap")
}
