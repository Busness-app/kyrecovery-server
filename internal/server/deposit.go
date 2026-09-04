package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// handleDeposit stores a sealed container. It reads the manifest without a key, decides on
// exactly two of its fields — the recovery key ID against the pin and the service name
// against the paired app — and records the rest as the sealer attested it.
func (s *Server) handleDeposit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" || authHeader == token {
		writeError(w, http.StatusUnauthorized, "Missing or invalid Bearer authorization token")
		return
	}
	ctx := r.Context()
	app, err := s.db.GetPairedAppByToken(ctx, token)
	if err != nil || app == nil {
		writeError(w, http.StatusUnauthorized, "Invalid or revoked API token")
		return
	}
	now := time.Now()
	pushKey := "push:" + app.ID
	if s.pushLimit.exceeded(pushKey, pushesPerToken, now) {
		writeError(w, http.StatusTooManyRequests, "Deposit rate limit exceeded for this paired product")
		return
	}
	s.pushLimit.record(pushKey, now)
	select {
	case s.pushSlots <- struct{}{}:
		defer func() { <-s.pushSlots }()
	case <-ctx.Done():
		writeError(w, http.StatusServiceUnavailable, "Server busy; retry shortly")
		return
	}

	raw, err := io.ReadAll(r.Body) // MaxBytesReader in ServeHTTP caps this at capsule.MaxContainerBytes
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("Container exceeds %d bytes", capsule.MaxContainerBytes))
			return
		}
		writeError(w, http.StatusBadRequest, "Failed reading request body")
		return
	}
	m, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Body is not a kycap/3 container")
		return
	}
	key, err := s.db.GetRecoveryKey(ctx)
	if err != nil || key == nil {
		writeError(w, http.StatusConflict, "No recovery key imported")
		return
	}
	if m.RecoveryKeyID != key.KeyID {
		writeError(w, http.StatusConflict, fmt.Sprintf("capsule is sealed to recovery key %s; this store pins %s", m.RecoveryKeyID, key.KeyID))
		return
	}
	if m.ServiceName != app.ServiceName {
		writeError(w, http.StatusForbidden, fmt.Sprintf("capsule names service %q; this token is paired for %q", m.ServiceName, app.ServiceName))
		return
	}
	// The capsule ID becomes a filename, so it is held to an allowlist rather than a
	// denylist of separators.
	if !validCapsuleID(m.CapsuleID) || !validServiceName(m.ServiceName) {
		writeError(w, http.StatusBadRequest, "Manifest capsule_id or service_name is not a usable name")
		return
	}

	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])

	// Fast path only. The row claimed by publishCapsule below is what actually decides.
	existing, err := s.db.GetCapsule(ctx, m.CapsuleID)
	if err != nil {
		log.Printf("deposit: reading capsule %s: %v", m.CapsuleID, err)
		writeError(w, http.StatusInternalServerError, "Failed reading capsule record")
		return
	}
	if existing != nil {
		s.respondToDuplicate(w, existing, digest)
		return
	}

	rec := db.CapsuleRecord{
		ID: m.CapsuleID, ServiceName: m.ServiceName, AppName: app.AppName, AppVersion: m.AppVersion,
		FilePath: s.capsulePath(m.CapsuleID), SizeBytes: int64(len(raw)), Digest: digest,
		PayloadHash: m.PayloadHash, Threshold: m.Threshold, TotalShares: m.TotalShares,
		RecoveryKeyID: m.RecoveryKeyID, EncapsulatedKey: m.EncapsulatedKey,
		CreatedAt: m.CreatedAt, DepositedAt: now.UTC(), PairedAppID: app.ID, Status: "active",
	}
	if err := s.publishCapsule(ctx, rec, raw); err != nil {
		if errors.Is(err, db.ErrCapsuleExists) {
			// A concurrent deposit of the same ID won the row. Re-read it and answer as if
			// the pre-check had seen it.
			stored, getErr := s.db.GetCapsule(ctx, rec.ID)
			if getErr != nil || stored == nil {
				log.Printf("deposit: re-reading capsule %s after a lost race: %v", rec.ID, getErr)
				writeError(w, http.StatusInternalServerError, "Failed reading capsule record")
				return
			}
			s.respondToDuplicate(w, stored, digest)
			return
		}
		log.Printf("deposit: publishing capsule %s: %v", rec.ID, err)
		writeError(w, http.StatusInternalServerError, "Failed storing capsule")
		return
	}
	_ = s.db.UpdateAppLastBackup(ctx, app.ID)
	go s.replication.SyncAllAutoTargets(context.Background(), rec.ID)
	_, _ = s.ledger.Record(ctx, "capsule_deposited", "paired-app:"+app.ID, rec.ID, map[string]interface{}{
		"service_name": rec.ServiceName, "digest": digest, "size_bytes": rec.SizeBytes, "recovery_key_id": rec.RecoveryKeyID,
	})
	writeJSON(w, http.StatusCreated, depositResponse(&rec))
}

// respondToDuplicate answers a deposit whose ID is already stored: identical bytes are the
// idempotent retry the products actually make, anything else is a collision.
func (s *Server) respondToDuplicate(w http.ResponseWriter, stored *db.CapsuleRecord, digest string) {
	if stored.Digest == digest {
		writeJSON(w, http.StatusOK, depositResponse(stored))
		return
	}
	writeError(w, http.StatusConflict, "A different capsule with this ID is already stored")
}

func depositResponse(rec *db.CapsuleRecord) map[string]any {
	return map[string]any{"capsule_id": rec.ID, "digest": rec.Digest, "size_bytes": rec.SizeBytes, "deposited_at": rec.DepositedAt}
}
