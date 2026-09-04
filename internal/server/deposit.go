package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	if m.CapsuleID == "" || !validServiceName(m.ServiceName) || strings.ContainsAny(m.CapsuleID, "/\\\x00") {
		writeError(w, http.StatusBadRequest, "Manifest capsule_id or service_name is not a usable name")
		return
	}

	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])

	if existing, _ := s.db.GetCapsule(ctx, m.CapsuleID); existing != nil {
		if existing.Digest == digest {
			writeJSON(w, http.StatusOK, depositResponse(existing))
			return
		}
		writeError(w, http.StatusConflict, "A different capsule with this ID is already stored")
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
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.db.UpdateAppLastBackup(ctx, app.ID)
	go s.replication.SyncAllAutoTargets(context.Background(), rec.ID)
	_, _ = s.ledger.Record(ctx, "capsule_deposited", "paired-app:"+app.ID, rec.ID, map[string]interface{}{
		"service_name": rec.ServiceName, "digest": digest, "size_bytes": rec.SizeBytes, "recovery_key_id": rec.RecoveryKeyID,
	})
	writeJSON(w, http.StatusCreated, depositResponse(&rec))
}

func depositResponse(rec *db.CapsuleRecord) map[string]any {
	return map[string]any{"capsule_id": rec.ID, "digest": rec.Digest, "size_bytes": rec.SizeBytes, "deposited_at": rec.DepositedAt}
}
