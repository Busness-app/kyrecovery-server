package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// recoveryKeyImport is the whole body the ceremony page may send. It has no field for
// shares on purpose; DisallowUnknownFields makes a body carrying one a 400.
type recoveryKeyImport struct {
	PublicKey   string `json:"public_key"`
	Threshold   int    `json:"threshold"`
	TotalShares int    `json:"total_shares"`
}

func validTopology(k, n int) bool { return k >= 2 && n >= k && n <= 255 }

func (s *Server) handleRecoveryKey(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rec, err := s.db.GetRecoveryKey(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed reading recovery key")
			return
		}
		if rec == nil {
			writeError(w, http.StatusNotFound, "No recovery key imported; run the ceremony")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"key_id": rec.KeyID, "public_key": base64.StdEncoding.EncodeToString(rec.PublicKey),
			"threshold": rec.Threshold, "total_shares": rec.TotalShares,
			"imported_by": rec.ImportedBy, "imported_at": rec.ImportedAt,
		})
	case http.MethodPost:
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var req recoveryKeyImport
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Body must be exactly {public_key, threshold, total_shares}")
			return
		}
		raw, err := base64.StdEncoding.DecodeString(req.PublicKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "public_key is not standard base64")
			return
		}
		pk, err := recoverykey.ParsePublicKey(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("public_key: %v", err))
			return
		}
		if !validTopology(req.Threshold, req.TotalShares) {
			writeError(w, http.StatusBadRequest, "threshold and total_shares must satisfy 2 <= threshold <= total_shares <= 255")
			return
		}
		rec := db.RecoveryKeyRecord{
			KeyID: pk.ID(), PublicKey: pk.Bytes(), Threshold: req.Threshold, TotalShares: req.TotalShares,
			ImportedBy: s.actor(r), ImportedAt: time.Now().UTC(),
		}
		if err := s.db.InsertRecoveryKey(r.Context(), rec); err != nil {
			if errors.Is(err, db.ErrRecoveryKeyExists) {
				existing, _ := s.db.GetRecoveryKey(r.Context())
				id := ""
				if existing != nil {
					id = existing.KeyID
				}
				writeError(w, http.StatusConflict, fmt.Sprintf("recovery key %s is already imported; rotation is a separate procedure", id))
				return
			}
			writeError(w, http.StatusInternalServerError, "Failed storing recovery key")
			return
		}
		_, _ = s.ledger.Record(r.Context(), "recovery_key_imported", s.actor(r), rec.KeyID, map[string]interface{}{
			"threshold": rec.Threshold, "total_shares": rec.TotalShares,
		})
		writeJSON(w, http.StatusCreated, map[string]any{"key_id": rec.KeyID, "threshold": rec.Threshold, "total_shares": rec.TotalShares})
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}
