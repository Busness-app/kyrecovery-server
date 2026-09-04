package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// verifyCapsule re-hashes the stored container against the digest recorded at deposit and
// writes the outcome to the audit chain. It is the only attestation this store can make:
// the bytes are what arrived. It says nothing about what is inside them.
func (s *Server) verifyCapsule(ctx context.Context, rec *db.CapsuleRecord) (bool, error) {
	f, err := os.Open(rec.FilePath)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	valid := hex.EncodeToString(h.Sum(nil)) == rec.Digest
	action, status := "capsule_verified", "active"
	if !valid {
		action, status = "capsule_corrupt", "corrupt"
	}
	if err := s.db.SetCapsuleStatus(ctx, rec.ID, status); err != nil {
		return valid, err
	}
	_, _ = s.ledger.Record(ctx, action, "integrity-sweep", rec.ID, map[string]interface{}{"digest": rec.Digest})
	return valid, nil
}

func (s *Server) handleCapsuleVerify(w http.ResponseWriter, r *http.Request, rec *db.CapsuleRecord) {
	valid, err := s.verifyCapsule(r.Context(), rec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Capsule file unreadable on disk")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"capsule_id": rec.ID, "digest": rec.Digest, "valid": valid, "checked_at": time.Now().UTC()})
}

// verifyAll is the daily sweep. It never stops on one bad capsule.
func (s *Server) verifyAll(ctx context.Context) (checked, corrupt int) {
	caps, err := s.db.ListCapsules(ctx)
	if err != nil {
		return 0, 0
	}
	for i := range caps {
		valid, err := s.verifyCapsule(ctx, &caps[i])
		if err != nil {
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.verifyAll(ctx)
		}
	}
}
