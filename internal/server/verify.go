package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// verifyCapsule re-hashes the stored container against the digest recorded at deposit and
// writes the outcome to the audit chain. It is the only attestation this store can make:
// the bytes are what arrived. It says nothing about what is inside them.
//
// A file that is not there is not a verification error: it is the strongest possible
// evidence of corruption, and is flagged the same way a digest mismatch is — the row is
// marked corrupt, the reason is logged to the audit chain, and (false, nil) is returned so
// a sweep does not skip the row forever and an on-demand check does not 500.
//
// Every other failure to read is the opposite: a full disk, a dropped mount or a lost
// permission says nothing about the bytes. Those return an error and leave the row alone,
// so one bad I/O moment does not get amplified into a store-wide "corrupt" verdict the
// operator then has to disbelieve.
func (s *Server) verifyCapsule(ctx context.Context, rec *db.CapsuleRecord, actor string) (bool, error) {
	defer s.idLocks.acquire(rec.ID)()
	f, err := os.Open(rec.FilePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return s.markCorrupt(ctx, rec, actor, "file missing")
		}
		return false, fmt.Errorf("opening capsule file: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, fmt.Errorf("reading capsule file: %w", err)
	}
	valid := hex.EncodeToString(h.Sum(nil)) == rec.Digest
	if !valid {
		return s.markCorrupt(ctx, rec, actor, "digest mismatch")
	}
	if err := s.db.SetCapsuleStatus(ctx, rec.ID, "active"); err != nil {
		return true, err
	}
	_, _ = s.ledger.Record(ctx, "capsule_verified", actor, rec.ID, map[string]interface{}{"digest": rec.Digest})
	return true, nil
}

// markCorrupt records why a capsule failed verification. It returns (false, nil) rather
// than an error: the file being gone is the finding, not a failure to find out.
func (s *Server) markCorrupt(ctx context.Context, rec *db.CapsuleRecord, actor, reason string) (bool, error) {
	if err := s.db.SetCapsuleStatus(ctx, rec.ID, "corrupt"); err != nil {
		return false, err
	}
	_, _ = s.ledger.Record(ctx, "capsule_corrupt", actor, rec.ID, map[string]interface{}{"digest": rec.Digest, "reason": reason})
	return false, nil
}

func (s *Server) handleCapsuleVerify(w http.ResponseWriter, r *http.Request, rec *db.CapsuleRecord) {
	valid, err := s.verifyCapsule(r.Context(), rec, s.actor(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed recording verification result")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"capsule_id": rec.ID, "digest": rec.Digest, "valid": valid, "checked_at": time.Now().UTC()})
}

// verifyAll is the daily sweep. It never stops on one bad capsule: an unreadable file or a
// failed status write is logged and the row is left as it was, and the sweep moves on.
func (s *Server) verifyAll(ctx context.Context) (checked, corrupt int) {
	caps, err := s.db.ListCapsules(ctx)
	if err != nil {
		return 0, 0
	}
	for i := range caps {
		valid, err := s.verifyCapsule(ctx, &caps[i], "integrity-sweep")
		if err != nil {
			log.Printf("verify: capsule %s: %v", caps[i].ID, err)
			continue
		}
		checked++
		if !valid {
			corrupt++
		}
	}
	return checked, corrupt
}

func (s *Server) runIntegritySweep(ctx context.Context) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	s.verifyAll(ctx) // a restart is exactly when the disk may have changed under us
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.verifyAll(ctx)
		}
	}
}
