package server

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kyrecovery-server/internal/adapter"
	"kyrecovery-server/internal/audit"
	"kyrecovery-server/internal/auth"
	"kyrecovery-server/internal/capsule"
	"kyrecovery-server/internal/ceremony"
	"kyrecovery-server/internal/crypto"
	"kyrecovery-server/internal/db"
	"kyrecovery-server/internal/diff"
	"kyrecovery-server/internal/drill"
	"kyrecovery-server/internal/export"
	"kyrecovery-server/internal/pairing"
	"kyrecovery-server/internal/replication"
)

//go:embed static/*
var staticFS embed.FS

// Config contains server options.
type Config struct {
	Port         int
	DataDir      string
	DatabasePath string
	Auth         auth.OIDCConfig
}

// Server provides the HTTP router, REST API, and static assets for KyRecovery.
type Server struct {
	cfg         Config
	db          *db.DB
	ledger      *audit.Ledger
	runner      *drill.Runner
	authMgr     *auth.Manager
	ceremonies  *ceremony.Manager
	replication *replication.Manager
	inspector   *diff.Inspector
	adapters    map[string]adapter.ServiceAdapter
	mux         *http.ServeMux
}

// New creates a new KyRecovery server instance.
func New(cfg Config, database *db.DB, ledger *audit.Ledger) (*Server, error) {
	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}
	if err := os.MkdirAll(filepath.Join(cfg.DataDir, "capsules"), 0700); err != nil {
		return nil, fmt.Errorf("failed to create capsules directory: %w", err)
	}

	ssoAdapter := adapter.NewKySignOnAdapter()
	pwdAdapter := adapter.NewKyPasswordAdapter()
	bkmAdapter := adapter.NewKyBookmarksAdapter()
	notesAdapter := adapter.NewKyNotesAdapter()
	postAdapter := adapter.NewKyPostAdapter()
	genericAdapter := adapter.NewGenericAdapter()
	runner := drill.NewRunner(database, ledger, ssoAdapter, pwdAdapter, bkmAdapter, notesAdapter, postAdapter, genericAdapter)
	authMgr := auth.NewManager(cfg.Auth, database)
	ceremonyMgr := ceremony.NewManager()
	replMgr := replication.NewManager(database, ledger)
	inspector := diff.NewInspector(database)

	adapters := map[string]adapter.ServiceAdapter{
		ssoAdapter.Name():     ssoAdapter,
		pwdAdapter.Name():     pwdAdapter,
		bkmAdapter.Name():     bkmAdapter,
		notesAdapter.Name():   notesAdapter,
		postAdapter.Name():    postAdapter,
		genericAdapter.Name(): genericAdapter,
	}

	s := &Server{
		cfg:         cfg,
		db:          database,
		ledger:      ledger,
		runner:      runner,
		authMgr:     authMgr,
		ceremonies:  ceremonyMgr,
		replication: replMgr,
		inspector:   inspector,
		adapters:    adapters,
		mux:         http.NewServeMux(),
	}

	s.routes()
	return s, nil
}

func (s *Server) routes() {
	// Static files
	staticSub, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(staticSub))
	s.mux.Handle("/static/", http.StripPrefix("/static/", fileServer))

	// Web UI index
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "Index not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// Auth & SSO Routes
	s.mux.HandleFunc("/api/auth/config", s.handleAuthConfig)
	s.mux.HandleFunc("/api/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("/api/auth/login/local", s.handleAuthLoginLocal)
	s.mux.HandleFunc("/api/auth/password", s.handleAuthPasswordChange)
	s.mux.HandleFunc("/api/auth/sso/config", s.handleSSOConfig)
	s.mux.HandleFunc("/api/auth/sso/test", s.handleSSOTest)
	s.mux.HandleFunc("/api/auth/callback", s.handleAuthCallback)
	s.mux.HandleFunc("/api/auth/me", s.handleAuthMe)
	s.mux.HandleFunc("/api/auth/logout", s.handleAuthLogout)

	// API Routes
	s.mux.HandleFunc("/api/readiness", s.handleReadiness)
	s.mux.HandleFunc("/api/capsules", s.handleCapsules)
	s.mux.HandleFunc("/api/capsules/capture", s.handleCapsuleCapture)
	s.mux.HandleFunc("/api/capsules/", s.handleCapsuleDetail)
	s.mux.HandleFunc("/api/custodians", s.handleCustodians)
	s.mux.HandleFunc("/api/drills", s.handleDrills)
	s.mux.HandleFunc("/api/drills/run", s.handleRunDrill)
	s.mux.HandleFunc("/api/audit", s.handleAudit)
	s.mux.HandleFunc("/api/audit/verify", s.handleAuditVerify)

	// Pairing & Self-Declared Backup Ingest Routes
	s.mux.HandleFunc("/api/pairing/generate", s.handlePairingGenerate)
	s.mux.HandleFunc("/api/pairing/list", s.handlePairingList)
	s.mux.HandleFunc("/api/pairing/revoke", s.handlePairingRevoke)
	s.mux.HandleFunc("/api/pairing/claim", s.handlePairingClaim)
	s.mux.HandleFunc("/api/backup/push", s.handleBackupPush)
	s.mux.HandleFunc("/api/v1/backup/push", s.handleBackupPush)

	// Quorum Ceremony Routes
	s.mux.HandleFunc("/api/ceremonies", s.handleCeremonies)
	s.mux.HandleFunc("/api/ceremonies/create", s.handleCeremonyCreate)
	s.mux.HandleFunc("/api/ceremonies/submit", s.handleCeremonySubmit)
	s.mux.HandleFunc("/api/ceremonies/execute", s.handleCeremonyExecute)
	s.mux.HandleFunc("/api/ceremonies/cancel", s.handleCeremonyCancel)

	// Offsite Replication Routes
	s.mux.HandleFunc("/api/replication/targets", s.handleReplicationTargets)
	s.mux.HandleFunc("/api/replication/targets/test", s.handleReplicationTargetTest)
	s.mux.HandleFunc("/api/replication/targets/", s.handleReplicationTargetDelete)
	s.mux.HandleFunc("/api/replication/sync", s.handleReplicationSync)
	s.mux.HandleFunc("/api/replication/logs", s.handleReplicationLogs)

	// Snapshot Diff & Rollback Inspector Routes
	s.mux.HandleFunc("/api/capsules/diff", s.handleCapsuleDiff)
	s.mux.HandleFunc("/api/capsules/timeline", s.handleCapsuleTimeline)
}

func isPublicPath(p string) bool {
	switch p {
	case "/api/auth/config",
		"/api/auth/me",
		"/api/auth/login",
		"/api/auth/login/local",
		"/api/auth/callback",
		"/api/auth/logout",
		"/api/auth/sso/config",
		"/api/auth/sso/test",
		"/api/readiness",
		"/api/pairing/claim",
		"/api/backup/push",
		"/api/v1/backup/push":
		return true
	default:
		return false
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")

		// Authentication enforcement for protected API routes
		if !isPublicPath(r.URL.Path) {
			session, err := s.authMgr.GetSession(r.Context(), r)
			if err != nil || session == nil {
				writeError(w, http.StatusUnauthorized, "Unauthorized: Authentication required")
				return
			}
		}
	}

	s.mux.ServeHTTP(w, r)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// 1. Readiness Handler
func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	capsules, _ := s.db.ListCapsules(ctx)
	custodians, _ := s.db.ListCustodians(ctx)
	lastDrill, _ := s.db.GetLastDrill(ctx)

	ready := len(capsules) > 0 && lastDrill != nil && lastDrill.Status == "passed"
	var lastRTO int64 = -1
	if lastDrill != nil {
		lastRTO = lastDrill.DurationMs
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ready":            ready,
		"capsules_count":   len(capsules),
		"custodians_count": len(custodians),
		"last_rto_ms":      lastRTO,
		"last_drill":       lastDrill,
	})
}

// 2. Capsules List
func (s *Server) handleCapsules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	list, err := s.db.ListCapsules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// 3. Capsule Capture
type captureRequest struct {
	ServiceName string `json:"service_name"`
	Threshold   int    `json:"threshold"`
	TotalShares int    `json:"total_shares"`
}

func (s *Server) handleCapsuleCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req captureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON request")
		return
	}

	if req.ServiceName == "" {
		req.ServiceName = "kysignon"
	}
	if req.Threshold < 2 {
		req.Threshold = 2
	}
	if req.TotalShares < req.Threshold {
		req.TotalShares = req.Threshold + 1
	}

	adp, exists := s.adapters[req.ServiceName]
	if !exists {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Unsupported service %q", req.ServiceName))
		return
	}

	ctx := r.Context()
	files, deps, err := adp.Capture(ctx, filepath.Join(s.cfg.DataDir, "source", req.ServiceName))
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Capture failed: %v", err))
		return
	}

	capsuleID := fmt.Sprintf("cap-%s-%d", req.ServiceName, time.Now().Unix())
	packResult, err := capsule.Pack(capsule.PackOptions{
		CapsuleID:    capsuleID,
		ServiceName:  req.ServiceName,
		Files:        files,
		Dependencies: deps,
		Threshold:    req.Threshold,
		TotalShares:  req.TotalShares,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Capsule packing failed: %v", err))
		return
	}

	// Write encrypted capsule file to disk
	capsuleFilePath := filepath.Join(s.cfg.DataDir, "capsules", fmt.Sprintf("%s.kycap", capsuleID))
	if err := os.WriteFile(capsuleFilePath, packResult.CapsuleBytes, 0600); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to write capsule file: %v", err))
		return
	}

	// Insert into DB
	capRec := db.CapsuleRecord{
		ID:          capsuleID,
		ServiceName: req.ServiceName,
		FilePath:    capsuleFilePath,
		SizeBytes:   int64(len(packResult.CapsuleBytes)),
		PayloadHash: packResult.Manifest.PayloadHash,
		Threshold:   req.Threshold,
		TotalShares: req.TotalShares,
		Status:      "active",
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.db.InsertCapsule(ctx, capRec); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed recording capsule: %v", err))
		return
	}

	// Record in audit ledger
	_, _ = s.ledger.Record(ctx, "capsule_captured", "operator", capsuleID, map[string]interface{}{
		"service":      req.ServiceName,
		"threshold":    req.Threshold,
		"total_shares": req.TotalShares,
		"size_bytes":   capRec.SizeBytes,
	})

	// Background offsite replication to configured auto targets
	go s.replication.SyncAllAutoTargets(context.Background(), capsuleID)

	// Format share responses (values returned once to admin, not stored in DB)
	type shareResp struct {
		Index    byte   `json:"index"`
		ValueHex string `json:"value_hex"`
	}
	var shareList []shareResp
	for _, sh := range packResult.Shares {
		shareList = append(shareList, shareResp{
			Index:    sh.Index,
			ValueHex: hex.EncodeToString(sh.Value),
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"capsule":  capRec,
		"manifest": packResult.Manifest,
		"shares":   shareList,
	})
}

// 4. Capsule Detail / Download / Export
func (s *Server) handleCapsuleDetail(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		writeError(w, http.StatusBadRequest, "Invalid capsule URL")
		return
	}
	capsuleID := parts[2]
	action := ""
	if len(parts) >= 4 {
		action = parts[3]
	}

	ctx := r.Context()
	capRec, err := s.db.GetCapsule(ctx, capsuleID)
	if err != nil || capRec == nil {
		writeError(w, http.StatusNotFound, "Capsule not found")
		return
	}

	switch action {
	case "download":
		capsuleBytes, err := os.ReadFile(capRec.FilePath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Capsule file unreadable on disk")
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.kycap", capsuleID))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(capsuleBytes)

	case "export-kit":
		format := r.URL.Query().Get("format")
		capsuleBytes, err := os.ReadFile(capRec.FilePath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Capsule file unreadable")
			return
		}
		manifest, err := capsule.ReadManifest(capsuleBytes)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed reading capsule manifest")
			return
		}

		custodians, _ := s.db.ListCustodians(ctx)
		lastDrill, _ := s.db.GetLastDrill(ctx)

		kitData := export.KitData{
			CapsuleID:    manifest.CapsuleID,
			ServiceName:  manifest.ServiceName,
			GeneratedAt:  time.Now().UTC(),
			Threshold:    manifest.Threshold,
			TotalShares:  manifest.TotalShares,
			PayloadHash:  manifest.PayloadHash,
			Dependencies: manifest.Dependencies,
			Files:        manifest.Files,
			Custodians:   custodians,
			LastDrill:    lastDrill,
		}

		_, _ = s.ledger.Record(ctx, "kit_exported", "operator", capsuleID, map[string]interface{}{"format": format})

		if format == "md" {
			md := export.GenerateMarkdownRunbook(kitData)
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			w.Write([]byte(md))
			return
		}

		html, err := export.GenerateHTMLRunbook(kitData)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed generating HTML runbook")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))

	default:
		writeJSON(w, http.StatusOK, capRec)
	}
}

// 5. Custodians Handler
type custodianCreateRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (s *Server) handleCustodians(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		list, err := s.db.ListCustodians(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, list)

	case http.MethodPost:
		var req custodianCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Email == "" {
			writeError(w, http.StatusBadRequest, "Name and Email are required")
			return
		}

		rawFP := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", req.Name, req.Email, time.Now().UnixNano())))
		fingerprint := fmt.Sprintf("SHA256:%s", hex.EncodeToString(rawFP[:8]))
		custID := fmt.Sprintf("cust-%d", time.Now().UnixNano())

		custRec := db.CustodianRecord{
			ID:          custID,
			Name:        req.Name,
			Email:       req.Email,
			Fingerprint: fingerprint,
			CreatedAt:   time.Now().UTC(),
		}

		if err := s.db.InsertCustodian(ctx, custRec); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		_, _ = s.ledger.Record(ctx, "custodian_added", "admin", custID, map[string]interface{}{
			"name":        req.Name,
			"email":       req.Email,
			"fingerprint": fingerprint,
		})

		writeJSON(w, http.StatusOK, custRec)

	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// 6. Drills Handler
func (s *Server) handleDrills(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	drills, err := s.db.ListDrills(r.Context(), 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, drills)
}

// 7. Run Drill Handler
type runDrillRequest struct {
	CapsuleID string   `json:"capsule_id"`
	Shares    []string `json:"shares"`
}

func (s *Server) handleRunDrill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req runDrillRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CapsuleID == "" {
		writeError(w, http.StatusBadRequest, "Capsule ID is required")
		return
	}

	ctx := r.Context()
	capRec, err := s.db.GetCapsule(ctx, req.CapsuleID)
	if err != nil || capRec == nil {
		writeError(w, http.StatusNotFound, "Capsule not found")
		return
	}

	capsuleBytes, err := os.ReadFile(capRec.FilePath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Capsule file could not be read from disk")
		return
	}

	var parsedShares []crypto.Share
	for _, raw := range req.Shares {
		sh, err := crypto.ParseShare(raw)
		if err == nil {
			parsedShares = append(parsedShares, sh)
		}
	}

	summary, err := s.runner.Execute(ctx, drill.DrillParams{
		CapsuleID:    req.CapsuleID,
		CapsuleBytes: capsuleBytes,
		Shares:       parsedShares,
		Actor:        "web-operator",
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Drill execution failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, summary)
}

// 8. Audit List
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	events, err := s.db.ListAuditEvents(r.Context(), 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// 9. Audit Chain Verification
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	valid, count, lastHash, err := s.ledger.VerifyChain(r.Context())
	resp := map[string]interface{}{
		"valid":     valid,
		"count":     count,
		"last_hash": lastHash,
	}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// 10. Pairing Generate
type pairingGenRequest struct {
	TTLMinutes  int    `json:"ttl_minutes"`
	ServiceName string `json:"service_name"`
	AppName     string `json:"app_name"`
}

func (s *Server) handlePairingGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req pairingGenRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	ttl := 15 * time.Minute
	if req.TTLMinutes > 0 {
		ttl = time.Duration(req.TTLMinutes) * time.Minute
	}

	record, err := pairing.GeneratePairingCode(r.Context(), s.db, ttl, req.ServiceName, req.AppName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed generating pairing code: %v", err))
		return
	}

	_, _ = s.ledger.Record(r.Context(), "pairing_code_generated", "admin", record.PairingCode, map[string]interface{}{
		"expires_at": record.ExpiresAt,
	})

	writeJSON(w, http.StatusOK, record)
}

// 11. Pairing List
func (s *Server) handlePairingList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	list, err := s.db.ListPairedApps(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// 12. Pairing Revoke
type pairingRevokeRequest struct {
	ID string `json:"id"`
}

func (s *Server) handlePairingRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req pairingRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		writeError(w, http.StatusBadRequest, "ID is required")
		return
	}
	if err := s.db.RevokePairedApp(r.Context(), req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = s.ledger.Record(r.Context(), "pairing_token_revoked", "admin", req.ID, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// 13. Pairing Claim
type pairingClaimRequest struct {
	PairingCode string `json:"pairing_code"`
	ServiceName string `json:"service_name"`
	AppName     string `json:"app_name"`
}

func (s *Server) handlePairingClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req pairingClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PairingCode == "" {
		writeError(w, http.StatusBadRequest, "PairingCode is required")
		return
	}
	if req.ServiceName == "" {
		req.ServiceName = "generic"
	}
	if req.AppName == "" {
		req.AppName = fmt.Sprintf("App-%s", req.PairingCode)
	}

	app, err := s.db.ClaimPairingCode(r.Context(), req.PairingCode, req.ServiceName, req.AppName)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	_, _ = s.ledger.Record(r.Context(), "product_paired", req.AppName, app.ID, map[string]interface{}{
		"service_name": app.ServiceName,
		"app_name":     app.AppName,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "paired",
		"api_token":    app.APIToken,
		"service_name": app.ServiceName,
		"app_name":     app.AppName,
		"server_url":   r.Host,
	})
}

// 14. Self-Declared Backup Push
func (s *Server) handleBackupPush(w http.ResponseWriter, r *http.Request) {
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

	var payload pairing.SelfDeclaredBackupPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON backup payload: %v", err))
		return
	}

	if payload.ServiceName == "" {
		payload.ServiceName = app.ServiceName
	}
	if payload.Threshold < 2 {
		payload.Threshold = 2
	}
	if payload.TotalShares < payload.Threshold {
		payload.TotalShares = payload.Threshold + 1
	}

	rawFiles, deps, recipe, err := pairing.IngestSelfDeclaredBackup(payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed processing backup payload: %v", err))
		return
	}

	// Embed declarative recipe into capsule files
	recipeBytes, _ := json.MarshalIndent(recipe, "", "  ")
	rawFiles["kyrecovery-recipe.json"] = recipeBytes

	capsuleID := fmt.Sprintf("cap-%s-%d", payload.ServiceName, time.Now().Unix())
	packResult, err := capsule.Pack(capsule.PackOptions{
		CapsuleID:    capsuleID,
		ServiceName:  payload.ServiceName,
		Files:        rawFiles,
		Dependencies: deps,
		Threshold:    payload.Threshold,
		TotalShares:  payload.TotalShares,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Capsule encryption failed: %v", err))
		return
	}

	// Write encrypted capsule file to disk
	capsuleFilePath := filepath.Join(s.cfg.DataDir, "capsules", fmt.Sprintf("%s.kycap", capsuleID))
	if err := os.WriteFile(capsuleFilePath, packResult.CapsuleBytes, 0600); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed writing capsule: %v", err))
		return
	}

	// Save to DB
	capRec := db.CapsuleRecord{
		ID:          capsuleID,
		ServiceName: payload.ServiceName,
		FilePath:    capsuleFilePath,
		SizeBytes:   int64(len(packResult.CapsuleBytes)),
		PayloadHash: packResult.Manifest.PayloadHash,
		Threshold:   payload.Threshold,
		TotalShares: payload.TotalShares,
		Status:      "active",
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.db.InsertCapsule(ctx, capRec); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed recording capsule: %v", err))
		return
	}

	_ = s.db.UpdateAppLastBackup(ctx, app.ID)

	// Background offsite replication to configured auto targets
	go s.replication.SyncAllAutoTargets(context.Background(), capsuleID)

	// Append to audit ledger
	_, _ = s.ledger.Record(ctx, "self_declared_backup_ingested", app.AppName, capsuleID, map[string]interface{}{
		"service":      payload.ServiceName,
		"app_version":  payload.AppVersion,
		"size_bytes":   capRec.SizeBytes,
		"files_count":  len(rawFiles),
		"threshold":    payload.Threshold,
		"total_shares": payload.TotalShares,
	})

	// Run automatic isolated verification drill with self-declared recipe
	drillAdapter := adapter.NewGenericAdapter(recipe)
	drillRunner := drill.NewRunner(s.db, s.ledger, drillAdapter)
	drillSummary, _ := drillRunner.Execute(ctx, drill.DrillParams{
		CapsuleID:    capsuleID,
		CapsuleBytes: packResult.CapsuleBytes,
		MasterKey:    packResult.MasterKey,
		Actor:        app.AppName,
	})

	type shareResp struct {
		Index    byte   `json:"index"`
		ValueHex string `json:"value_hex"`
	}
	var shareList []shareResp
	for _, sh := range packResult.Shares {
		shareList = append(shareList, shareResp{
			Index:    sh.Index,
			ValueHex: hex.EncodeToString(sh.Value),
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "success",
		"capsule_id":    capsuleID,
		"payload_hash":  packResult.Manifest.PayloadHash,
		"shares":        shareList,
		"initial_drill": drillSummary,
	})
}

// 15. Auth Config (Public status)
func (s *Server) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.authMgr.GetConfig()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sso_enabled":  s.authMgr.IsEnabled(),
		"issuer_url":   cfg.IssuerURL,
		"client_id":    cfg.ClientID,
		"redirect_url": cfg.RedirectURL,
		"admin_email":  cfg.AdminEmail,
	})
}

// 16. Auth Login (Initiates KySignOn OIDC PKCE Flow)
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if !s.authMgr.IsEnabled() {
		writeError(w, http.StatusBadRequest, "KySignOn SSO is not configured or enabled on this server. Please sign in as Local Admin.")
		return
	}

	verifier, challenge, err := auth.GeneratePKCE()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed generating PKCE challenge")
		return
	}
	state, _ := auth.GenerateRandomString(16)
	nonce, _ := auth.GenerateRandomString(16)

	http.SetCookie(w, &http.Cookie{
		Name:     "kyrec_pkce",
		Value:    verifier,
		Path:     "/api/auth/callback",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "kyrec_state",
		Value:    state,
		Path:     "/api/auth/callback",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	authURL := s.authMgr.BuildAuthURL(state, nonce, challenge)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// 16b. Local Admin Login
type localLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleAuthLoginLocal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req localLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON login payload")
		return
	}

	userInfo, err := s.authMgr.AuthenticateLocal(r.Context(), req.Username, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	sessionCookie, err := s.authMgr.CreateSession(r.Context(), userInfo)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed creating session")
		return
	}

	http.SetCookie(w, sessionCookie)

	_, _ = s.ledger.Record(r.Context(), "user_logged_in_local", userInfo.Email, userInfo.Subject, map[string]interface{}{
		"username": req.Username,
		"role":     userInfo.Role,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "authenticated",
		"session_token": sessionCookie.Value,
		"user":          userInfo,
	})
}

// 16c. Change Admin / User Password
type passwordChangeRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (s *Server) handleAuthPasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	session, err := s.authMgr.GetSession(r.Context(), r)
	if err != nil || session == nil {
		writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req passwordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "New password must be at least 8 characters long")
		return
	}

	// Verify old password
	user, err := s.db.GetUserByID(r.Context(), session.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusBadRequest, "User account not found")
		return
	}

	if !auth.VerifyPassword(req.OldPassword, user.PasswordHash, user.Salt) {
		writeError(w, http.StatusUnauthorized, "Current password is incorrect")
		return
	}

	newHash, newSalt, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed hashing new password")
		return
	}

	if err := s.db.UpdateUserPassword(r.Context(), user.ID, newHash, newSalt); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed updating password")
		return
	}

	_, _ = s.ledger.Record(r.Context(), "password_changed", user.Email, user.ID, nil)

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_updated"})
}

// 16d. SSO Pairing & Config Management (Admin)
func (s *Server) handleSSOConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		cfg := s.authMgr.GetConfig()
		clientSecretMasked := ""
		if cfg.ClientSecret != "" {
			clientSecretMasked = "••••••••"
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled":       cfg.Enabled,
			"issuer_url":    cfg.IssuerURL,
			"client_id":     cfg.ClientID,
			"client_secret": clientSecretMasked,
			"redirect_url":  cfg.RedirectURL,
			"admin_email":   cfg.AdminEmail,
		})

	case http.MethodPost:
		session, err := s.authMgr.GetSession(ctx, r)
		if err != nil || session == nil || session.Role != "admin" {
			writeError(w, http.StatusForbidden, "Admin role required to configure SSO settings")
			return
		}

		var req auth.OIDCConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON SSO config payload")
			return
		}

		if req.RedirectURL == "" && req.IssuerURL != "" {
			req.RedirectURL = fmt.Sprintf("http://%s/api/auth/callback", r.Host)
		}

		if err := s.authMgr.SaveConfig(ctx, req); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed saving SSO config: %v", err))
			return
		}

		_, _ = s.ledger.Record(ctx, "sso_config_updated", session.Email, "sso_settings", map[string]interface{}{
			"enabled":    req.Enabled,
			"issuer_url": req.IssuerURL,
			"client_id":  req.ClientID,
		})

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "saved",
			"config":  s.authMgr.GetConfig(),
			"enabled": s.authMgr.IsEnabled(),
		})

	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// 16e. Test KySignOn SSO Endpoint
type ssoTestRequest struct {
	IssuerURL string `json:"issuer_url"`
}

func (s *Server) handleSSOTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req ssoTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IssuerURL == "" {
		writeError(w, http.StatusBadRequest, "Issuer URL is required")
		return
	}

	if err := s.authMgr.TestSSOConnection(r.Context(), req.IssuerURL); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Successfully connected to KySignOn authority at %s", req.IssuerURL),
	})
}

// 17. Auth Callback (Handles OIDC Authorization Code)
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	stateCookie, err := r.Cookie("kyrec_state")
	if err != nil || stateCookie.Value != state || state == "" {
		writeError(w, http.StatusBadRequest, "Invalid or expired OAuth state parameter")
		return
	}

	pkceCookie, err := r.Cookie("kyrec_pkce")
	if err != nil || pkceCookie.Value == "" {
		writeError(w, http.StatusBadRequest, "Missing PKCE verifier cookie")
		return
	}

	userInfo, err := s.authMgr.ExchangeCode(r.Context(), code, pkceCookie.Value)
	if err != nil {
		writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	sessionCookie, err := s.authMgr.CreateSession(r.Context(), userInfo)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed creating session")
		return
	}

	http.SetCookie(w, sessionCookie)

	// Clean up temporary auth cookies
	http.SetCookie(w, &http.Cookie{Name: "kyrec_pkce", Value: "", Path: "/api/auth/callback", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "kyrec_state", Value: "", Path: "/api/auth/callback", MaxAge: -1})

	_, _ = s.ledger.Record(r.Context(), "user_logged_in_sso", userInfo.Email, userInfo.Subject, map[string]interface{}{
		"name": userInfo.Name,
		"role": userInfo.Role,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

// 18. Auth Me (Current User)
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	session, err := s.authMgr.GetSession(r.Context(), r)
	if err != nil || session == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"authenticated": false,
			"sso_enabled":   s.authMgr.IsEnabled(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"sso_enabled":   s.authMgr.IsEnabled(),
		"user":          session,
	})
}

// 19. Auth Logout
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	clearCookie := s.authMgr.InvalidateSession(r.Context(), r)
	http.SetCookie(w, clearCookie)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// 20. List Ceremonies
func (s *Server) handleCeremonies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	sessions := s.ceremonies.ListSessions()
	if sessions == nil {
		sessions = []*ceremony.Session{}
	}
	writeJSON(w, http.StatusOK, sessions)
}

// 21. Create Ceremony
type ceremonyCreateRequest struct {
	CapsuleID  string `json:"capsule_id"`
	Purpose    string `json:"purpose"`
	TTLMinutes int    `json:"ttl_minutes"`
}

func (s *Server) handleCeremonyCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req ceremonyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CapsuleID == "" {
		writeError(w, http.StatusBadRequest, "CapsuleID is required")
		return
	}

	capRec, err := s.db.GetCapsule(r.Context(), req.CapsuleID)
	if err != nil || capRec == nil {
		writeError(w, http.StatusNotFound, "Capsule not found")
		return
	}

	ttl := 30 * time.Minute
	if req.TTLMinutes > 0 {
		ttl = time.Duration(req.TTLMinutes) * time.Minute
	}
	if req.Purpose == "" {
		req.Purpose = "Quorum Verification Ceremony"
	}

	actor := "operator"
	if session, _ := s.authMgr.GetSession(r.Context(), r); session != nil {
		actor = session.Name
	}

	sess, err := s.ceremonies.CreateSession(capRec.ID, capRec.ServiceName, req.Purpose, actor, capRec.Threshold, capRec.TotalShares, ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_, _ = s.ledger.Record(r.Context(), "ceremony_initiated", actor, sess.ID, map[string]interface{}{
		"capsule_id":   capRec.ID,
		"purpose":      req.Purpose,
		"threshold":    capRec.Threshold,
		"total_shares": capRec.TotalShares,
		"expires_at":   sess.ExpiresAt,
	})

	writeJSON(w, http.StatusOK, sess)
}

// 22. Submit Custodian Share to Ceremony
type ceremonySubmitRequest struct {
	SessionID     string `json:"session_id"`
	CustodianName string `json:"custodian_name"`
	Share         string `json:"share"`
}

func (s *Server) handleCeremonySubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req ceremonySubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" || req.Share == "" {
		writeError(w, http.StatusBadRequest, "SessionID and Share are required")
		return
	}
	if req.CustodianName == "" {
		req.CustodianName = "Anonymous Custodian"
	}

	sess, err := s.ceremonies.SubmitShare(req.SessionID, req.CustodianName, req.Share)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	_, _ = s.ledger.Record(r.Context(), "custodian_share_submitted", req.CustodianName, req.SessionID, map[string]interface{}{
		"submitted_count": sess.SubmittedCount,
		"quorum_reached":  sess.Status == ceremony.StatusQuorumReached,
	})

	writeJSON(w, http.StatusOK, sess)
}

// 23. Execute Quorum Ceremony Drill / Restore
type ceremonyExecRequest struct {
	SessionID string `json:"session_id"`
}

func (s *Server) handleCeremonyExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req ceremonyExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "SessionID is required")
		return
	}

	sess, err := s.ceremonies.GetSession(req.SessionID)
	if err != nil || sess == nil {
		writeError(w, http.StatusNotFound, "Ceremony not found")
		return
	}

	if sess.Status != ceremony.StatusQuorumReached {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Ceremony status is %s (quorum not reached)", sess.Status))
		return
	}

	// Reconstruct master key from ephemeral in-memory shares
	key, err := s.ceremonies.GetReconstructedKey(req.SessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed reconstructing key: %v", err))
		return
	}

	capRec, err := s.db.GetCapsule(r.Context(), sess.CapsuleID)
	if err != nil || capRec == nil {
		writeError(w, http.StatusNotFound, "Target capsule not found on disk")
		return
	}

	// Execute isolated verification drill
	drillSummary, err := s.runner.Execute(r.Context(), drill.DrillParams{
		CapsuleID:   capRec.ID,
		CapsulePath: capRec.FilePath,
		MasterKey:   key,
		Actor:       fmt.Sprintf("Quorum-Ceremony (%s)", sess.ID),
	})

	// Cryptographically wipe in-memory shares and close session
	_ = s.ceremonies.CompleteSession(req.SessionID)

	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Drill execution failed: %v", err))
		return
	}

	_, _ = s.ledger.Record(r.Context(), "ceremony_executed", sess.Initiator, sess.ID, map[string]interface{}{
		"capsule_id":   sess.CapsuleID,
		"drill_passed": drillSummary.Passed,
		"duration_ms":  drillSummary.DurationMs,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "executed",
		"drill_summary": drillSummary,
	})
}

// 24. Cancel Ceremony
func (s *Server) handleCeremonyCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req ceremonyExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "SessionID is required")
		return
	}
	if err := s.ceremonies.CancelSession(req.SessionID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _ = s.ledger.Record(r.Context(), "ceremony_cancelled", "operator", req.SessionID, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

// 25. Replication Targets List / Create
func (s *Server) handleReplicationTargets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		targets, err := s.db.ListReplicationTargets(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Mask secret keys in list response
		for i := range targets {
			if targets[i].SecretKey != "" {
				targets[i].SecretKey = "••••••••"
			}
		}
		writeJSON(w, http.StatusOK, targets)

	case http.MethodPost:
		var target db.ReplicationTargetRecord
		if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if target.ID == "" {
			target.ID = fmt.Sprintf("target-%s-%d", target.Type, time.Now().Unix())
		}
		if target.Name == "" {
			target.Name = "Offsite Target"
		}
		if target.Type == "" {
			target.Type = "s3"
		}
		if target.Region == "" {
			target.Region = "us-east-1"
		}
		if target.Prefix == "" {
			target.Prefix = "capsules/"
		}
		if target.Status == "" {
			target.Status = "active"
		}
		target.CreatedAt = time.Now().UTC()

		if err := s.db.InsertReplicationTarget(ctx, target); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		_, _ = s.ledger.Record(ctx, "replication_target_saved", "operator", target.ID, map[string]interface{}{
			"name":      target.Name,
			"type":      target.Type,
			"endpoint":  target.Endpoint,
			"auto_sync": target.AutoSync,
		})

		target.SecretKey = "••••••••"
		writeJSON(w, http.StatusOK, target)

	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// 26. Replication Target Connection Test
func (s *Server) handleReplicationTargetTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var target db.ReplicationTargetRecord
	if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.replication.TestTarget(r.Context(), target); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Connection and write test successful",
	})
}

// 27. Replication Target Delete
func (s *Server) handleReplicationTargetDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	targetID := strings.TrimPrefix(r.URL.Path, "/api/replication/targets/")
	if targetID == "" {
		writeError(w, http.StatusBadRequest, "Target ID is required")
		return
	}
	if err := s.db.DeleteReplicationTarget(r.Context(), targetID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = s.ledger.Record(r.Context(), "replication_target_deleted", "operator", targetID, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// 28. Replication Manual Sync
type replSyncRequest struct {
	CapsuleID string `json:"capsule_id"`
	TargetID  string `json:"target_id"`
}

func (s *Server) handleReplicationSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req replSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CapsuleID == "" {
		writeError(w, http.StatusBadRequest, "CapsuleID is required")
		return
	}

	ctx := r.Context()
	if req.TargetID != "" {
		logRec, err := s.replication.SyncCapsule(ctx, req.CapsuleID, req.TargetID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("Replication failed: %v", err))
			return
		}
		writeJSON(w, http.StatusOK, logRec)
		return
	}

	// Sync to all auto targets
	logs := s.replication.SyncAllAutoTargets(ctx, req.CapsuleID)
	writeJSON(w, http.StatusOK, logs)
}

// 29. Replication Logs
func (s *Server) handleReplicationLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	logs, err := s.db.ListReplicationLogs(r.Context(), 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

// 30. Capsule Version Diff
func (s *Server) handleCapsuleDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	baseID := r.URL.Query().Get("base")
	targetID := r.URL.Query().Get("target")

	if baseID == "" || targetID == "" {
		writeError(w, http.StatusBadRequest, "Both 'base' and 'target' capsule IDs are required")
		return
	}

	report, err := s.inspector.DiffByCapsuleIDs(r.Context(), baseID, targetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, report)
}

// 31. Service Snapshot Timeline
func (s *Server) handleCapsuleTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	service := r.URL.Query().Get("service")
	timeline, err := s.inspector.GetServiceTimeline(r.Context(), service)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, timeline)
}

// Start runs the HTTP listener until context cancellation.
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", s.cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      s,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	errChan := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errChan:
		return err
	}
}
